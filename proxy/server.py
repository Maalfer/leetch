"""Proxy HTTP/HTTPS con interceptación MITM.

Para HTTPS: genera una CA local, firma certificados por host al vuelo y hace
TLS termination en ambos lados, de forma que el tráfico cifrado aparece en
HTTP History igual que el HTTP plano.
"""
from __future__ import annotations

import socket
import ssl
import threading
from typing import Callable, Optional
from urllib.parse import urlsplit

from proxy.ca import ensure_ca, make_host_cert
from proxy.flow import Flow, PendingRequest, set_header
from net import http_message as hm

try:
    import h2.connection  # noqa: F401
    _H2_AVAILABLE = True
except ImportError:
    _H2_AVAILABLE = False

# Construir Accept-Encoding con los codecs que tenemos disponibles en Python,
# para que el servidor nunca responda con algo que no podamos descomprimir.
_SUPPORTED_ENCODINGS: list[str] = ["gzip", "deflate"]
try:
    import brotli as _brotli  # noqa: F401
    _SUPPORTED_ENCODINGS.append("br")
except ImportError:
    pass
try:
    import zstandard as _zstd  # noqa: F401
    _SUPPORTED_ENCODINGS.append("zstd")
except ImportError:
    pass
_ACCEPT_ENCODING = ", ".join(_SUPPORTED_ENCODINGS).encode()


def _prepare_for_browser(response: bytes) -> bytes:
    """Normaliza la respuesta antes de enviarla al browser en modo keep-alive.

    Fuerza Connection: keep-alive y añade Content-Length cuando el servidor
    no lo incluye (p.ej. respondió con Connection: close). Sin esto el browser
    espera el cierre de conexión que nunca llega y los recursos quedan colgados.
    """
    response = set_header(response, b"Connection", b"keep-alive")
    head, sep, body = response.partition(b"\r\n\r\n")
    if not sep:
        return response
    headers_lower = head.lower()
    if b"content-length:" in headers_lower or b"transfer-encoding:" in headers_lower:
        return response
    # 1xx / 204 / 304 no tienen cuerpo
    first_line = head.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)
    sc = parts[1].strip() if len(parts) >= 2 else b""
    if sc[:1] == b"1" or sc in (b"204", b"304"):
        return response
    return head + (b"\r\nContent-Length: " + str(len(body)).encode()) + sep + body


class ProxyServer:
    """Servidor proxy multihilo con MITM HTTPS."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 on_flow: Optional[Callable[[Flow], None]] = None,
                 on_intercept: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.on_flow = on_flow
        self.on_intercept = on_intercept
        self.intercept_enabled: bool = False
        self.transform_request: Optional[Callable[[bytes], bytes]] = None
        self.transform_response: Optional[Callable[[bytes], bytes]] = None
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._counter = 0
        self._counter_lock = threading.Lock()

        self._ca_key = None
        self._ca_cert = None
        self._ca_lock = threading.Lock()
        self._cert_lock = threading.Lock()

    def _load_ca(self):
        with self._ca_lock:
            if self._ca_key is None:
                self._ca_key, self._ca_cert = ensure_ca()

    def _next_id(self) -> int:
        with self._counter_lock:
            self._counter += 1
            return self._counter

    def _get_host_cert(self, hostname: str) -> tuple[str, str]:
        self._load_ca()
        with self._cert_lock:
            return make_host_cert(hostname, self._ca_key, self._ca_cert)

    def start(self) -> None:
        if self._running:
            return
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(50)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        # Pre-genera la CA en background para que esté lista cuando el usuario
        # abra el navegador integrado, sin bloquear el hilo de la GUI.
        threading.Thread(target=self._load_ca, daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

    def _accept_loop(self) -> None:
        while self._running and self._server_sock:
            try:
                client, _addr = self._server_sock.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(client,),
                                  daemon=True)
            t.start()

    def _handle_client(self, client: socket.socket) -> None:
        try:
            raw = hm.read_http_message(client)
            if not raw or b"\r\n" not in raw:
                return
            method, target, _version = hm.parse_request_line(raw)

            if method.upper() == "CONNECT":
                self._handle_connect(client, target)
            else:
                self._handle_http(client, raw, method, target)
        except Exception:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _handle_http(self, client: socket.socket, raw: bytes,
                     method: str, target: str) -> None:
        if target.startswith("http://") or target.startswith("https://"):
            split = urlsplit(target)
            host = split.hostname or ""
            scheme = split.scheme
            port = split.port or (443 if scheme == "https" else 80)
            path = split.path or "/"
            if split.query:
                path += "?" + split.query
        else:
            headers = hm.parse_headers(raw)
            host_header = headers.get("host", "")
            scheme = "http"
            if ":" in host_header:
                host, port_s = host_header.rsplit(":", 1)
                port = int(port_s) if port_s.isdigit() else 80
            else:
                host, port = host_header, 80
            path = target

        if not host:
            return

        outgoing = self._to_origin_form(raw, path)

        # Match & Replace en petición
        if self.transform_request:
            try:
                outgoing = self.transform_request(outgoing)
            except Exception:
                pass

        # Intercept: bloquea el hilo hasta que el usuario decide Forward/Drop
        if self.intercept_enabled and self.on_intercept:
            pending = PendingRequest(outgoing, host, port, scheme)
            self.on_intercept(pending)
            if not pending.wait(timeout=300):
                return
            if pending.dropped:
                return
            if pending.modified_raw is not None:
                outgoing = pending.modified_raw

        flow = Flow(
            id=self._next_id(),
            method=method,
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            raw_request=outgoing,
        )

        try:
            upstream = socket.create_connection((host, port), timeout=15)
            upstream.sendall(outgoing)
            response = hm.read_http_message(upstream)
            upstream.close()
        except Exception as exc:  # noqa: BLE001
            response = (
                f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(str(exc))}\r\n\r\n{exc}"
            ).encode("latin-1", "replace")

        # Match & Replace en respuesta
        if self.transform_response:
            try:
                response = self.transform_response(response)
            except Exception:
                pass

        flow.raw_response = response
        flow.status = hm.status_code(response)

        try:
            client.sendall(response)
        except OSError:
            pass

        if self.on_flow:
            self.on_flow(flow)

    def _handle_connect(self, client: socket.socket, target: str) -> None:
        """MITM HTTPS: termina TLS en ambos lados e intercepta el tráfico."""
        if ":" in target:
            host, port_s = target.rsplit(":", 1)
            port = int(port_s) if port_s.isdigit() else 443
        else:
            host, port = target, 443

        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        try:
            cert_path, key_path = self._get_host_cert(host)
        except Exception:
            return

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_ctx.load_cert_chain(cert_path, key_path)
        client_ctx.set_alpn_protocols(["h2", "http/1.1"] if _H2_AVAILABLE else ["http/1.1"])

        try:
            tls_client = client_ctx.wrap_socket(client, server_side=True)
        except (ssl.SSLError, OSError):
            return

        tls_client.settimeout(30)

        up_ctx = ssl.create_default_context()
        up_ctx.check_hostname = False
        up_ctx.verify_mode = ssl.CERT_NONE
        up_ctx.set_alpn_protocols(["http/1.1"])

        def _open_upstream():
            raw_up = socket.create_connection((host, port), timeout=15)
            tls = up_ctx.wrap_socket(raw_up, server_hostname=host)
            tls.settimeout(30)
            return tls

        if tls_client.selected_alpn_protocol() == "h2":
            try:
                self._handle_h2_tunnel(tls_client, host, port, _open_upstream)
            finally:
                try:
                    tls_client.close()
                except OSError:
                    pass
            return

        try:
            tls_up = _open_upstream()
        except Exception:
            try:
                tls_client.close()
            except OSError:
                pass
            return

        try:
            while True:
                try:
                    raw = hm.read_http_message(tls_client)
                except (ssl.SSLError, OSError):
                    break
                if not raw or b"\r\n" not in raw:
                    break

                method, path, _version = hm.parse_request_line(raw)

                if "://" in path:
                    split = urlsplit(path)
                    path = split.path or "/"
                    if split.query:
                        path += "?" + split.query

                outgoing = self._to_origin_form(raw, path)

                # Match & Replace en petición HTTPS
                if self.transform_request:
                    try:
                        outgoing = self.transform_request(outgoing)
                    except Exception:
                        pass

                # Intercept HTTPS
                if self.intercept_enabled and self.on_intercept:
                    pending = PendingRequest(outgoing, host, port, "https")
                    self.on_intercept(pending)
                    if not pending.wait(timeout=300):
                        break
                    if pending.dropped:
                        break
                    if pending.modified_raw is not None:
                        outgoing = pending.modified_raw

                flow = Flow(
                    id=self._next_id(),
                    method=method,
                    host=host,
                    port=port,
                    scheme="https",
                    path=path,
                    raw_request=outgoing,
                    use_tls=True,
                )

                try:
                    tls_up.sendall(outgoing)
                    response = hm.read_http_message(tls_up)
                except (ssl.SSLError, OSError):
                    try:
                        tls_up.close()
                    except OSError:
                        pass
                    try:
                        tls_up = _open_upstream()
                        tls_up.sendall(outgoing)
                        response = hm.read_http_message(tls_up)
                    except Exception as exc:  # noqa: BLE001
                        msg = str(exc)
                        response = (
                            f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n"
                            f"Content-Length: {len(msg)}\r\n\r\n{msg}"
                        ).encode("latin-1", "replace")

                # Match & Replace en respuesta HTTPS
                if self.transform_response:
                    try:
                        response = self.transform_response(response)
                    except Exception:
                        pass

                flow.raw_response = response
                flow.status = hm.status_code(response)

                forwarded = _prepare_for_browser(response)

                try:
                    tls_client.sendall(forwarded)
                except (ssl.SSLError, OSError):
                    break

                if self.on_flow:
                    self.on_flow(flow)

                resp_headers = hm.parse_headers(response)
                if resp_headers.get("connection", "").lower() == "close":
                    try:
                        tls_up.close()
                    except OSError:
                        pass
                    try:
                        tls_up = _open_upstream()
                    except Exception:
                        break

        finally:
            for s in (tls_client, tls_up):
                try:
                    s.close()
                except OSError:
                    pass

    def _handle_h2_tunnel(self, tls_client: ssl.SSLSocket,
                          host: str, port: int, open_upstream) -> None:
        """Gestiona una conexión HTTP/2 del cliente, reenviando como HTTP/1.1 al servidor."""
        try:
            import h2.connection
            import h2.config
            import h2.events
            import h2.exceptions
        except ImportError:
            return

        h2_lock = threading.Lock()
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        h2c = h2.connection.H2Connection(config=cfg)
        h2c.initiate_connection()

        def _flush():
            d = h2c.data_to_send(65535)
            if d:
                tls_client.sendall(d)

        with h2_lock:
            _flush()

        pending: dict[int, dict] = {}
        dispatched: set[int] = set()

        def _dispatch(stream_id: int) -> None:
            if stream_id in dispatched:
                return
            dispatched.add(stream_id)
            info = pending.pop(stream_id, None)
            if not info:
                return
            threading.Thread(
                target=self._serve_h2_stream,
                args=(h2c, h2_lock, tls_client, stream_id,
                      info["hdrs"], info["body"], host, port, open_upstream),
                daemon=True,
            ).start()

        try:
            while True:
                try:
                    data = tls_client.recv(65535)
                except (ssl.SSLError, OSError):
                    break
                if not data:
                    break

                with h2_lock:
                    try:
                        events = h2c.receive_data(data)
                    except h2.exceptions.ProtocolError:
                        break
                    _flush()

                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        pending[ev.stream_id] = {"hdrs": list(ev.headers), "body": b""}
                        if ev.stream_ended is not None:
                            _dispatch(ev.stream_id)

                    elif isinstance(ev, h2.events.DataReceived):
                        with h2_lock:
                            h2c.acknowledge_received_data(
                                ev.flow_controlled_length, ev.stream_id
                            )
                            _flush()
                        if ev.stream_id in pending:
                            pending[ev.stream_id]["body"] += ev.data
                        if ev.stream_ended is not None:
                            _dispatch(ev.stream_id)

                    elif isinstance(ev, h2.events.StreamEnded):
                        _dispatch(ev.stream_id)

                    elif isinstance(ev, h2.events.WindowUpdated):
                        with h2_lock:
                            _flush()

                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        return
        except Exception:
            pass

    def _serve_h2_stream(self, h2c, h2_lock: threading.Lock,
                          tls_client: ssl.SSLSocket, stream_id: int,
                          hdrs: list, body: bytes,
                          host: str, port: int, open_upstream) -> None:
        """Hilo worker: convierte un stream H2 a HTTP/1.1, lo envía y devuelve H2 response."""
        method, path, authority = "GET", "/", host
        for name, value in hdrs:
            n = name if isinstance(name, str) else name.decode("utf-8", "replace")
            v = value if isinstance(value, str) else value.decode("utf-8", "replace")
            if n == ":method":
                method = v
            elif n == ":path":
                path = v
            elif n == ":authority":
                authority = v

        _skip_req = {
            ":method", ":path", ":scheme", ":authority", ":status",
            "host", "connection", "keep-alive", "transfer-encoding",
            "upgrade", "te", "proxy-connection",
        }
        h1_parts = [f"{method} {path} HTTP/1.1\r\n".encode(),
                    f"Host: {authority or host}\r\n".encode()]
        for name, value in hdrs:
            n = (name if isinstance(name, str) else name.decode("utf-8", "replace")).lower()
            v = value if isinstance(value, str) else value.decode("utf-8", "replace")
            if n in _skip_req:
                continue
            h1_parts.append(f"{n}: {v}\r\n".encode())
        if body:
            h1_parts.append(f"content-length: {len(body)}\r\n".encode())
        h1_parts.append(b"\r\n")
        if body:
            h1_parts.append(body)

        outgoing = b"".join(h1_parts)

        if self.transform_request:
            try:
                outgoing = self.transform_request(outgoing)
            except Exception:
                pass

        if self.intercept_enabled and self.on_intercept:
            pending_req = PendingRequest(outgoing, host, port, "https")
            self.on_intercept(pending_req)
            if not pending_req.wait(timeout=300) or pending_req.dropped:
                try:
                    with h2_lock:
                        h2c.reset_stream(stream_id)
                        d = h2c.data_to_send(65535)
                        if d:
                            tls_client.sendall(d)
                except Exception:
                    pass
                return
            if pending_req.modified_raw is not None:
                outgoing = pending_req.modified_raw

        flow = Flow(
            id=self._next_id(), method=method, host=host, port=port,
            scheme="https", path=path, raw_request=outgoing, use_tls=True,
        )

        try:
            tls_up = open_upstream()
            tls_up.sendall(outgoing)
            response = hm.read_http_message(tls_up)
            tls_up.close()
        except Exception as exc:
            msg = str(exc)
            response = (
                f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(msg)}\r\n\r\n{msg}"
            ).encode("latin-1", "replace")

        if self.transform_response:
            try:
                response = self.transform_response(response)
            except Exception:
                pass

        flow.raw_response = response
        flow.status = hm.status_code(response)
        if self.on_flow:
            self.on_flow(flow)

        hdr_bytes, _, resp_body = response.partition(b"\r\n\r\n")
        status_parts = hdr_bytes.split(b"\r\n", 1)[0].split(b" ", 2)
        status_code = status_parts[1].decode("ascii", "replace") if len(status_parts) >= 2 else "502"

        _skip_resp = {b"connection", b"keep-alive", b"transfer-encoding",
                      b"upgrade", b"te", b"proxy-connection"}
        h2_resp_hdrs = [(b":status", status_code.encode())]
        for line in hdr_bytes.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                k_lower = k.strip().lower()
                if k_lower not in _skip_resp:
                    h2_resp_hdrs.append((k_lower, v.strip()))

        if b"transfer-encoding: chunked" in hdr_bytes.lower():
            result = b""
            buf = resp_body
            while buf:
                crlf = buf.find(b"\r\n")
                if crlf == -1:
                    break
                try:
                    size = int(buf[:crlf].split(b";")[0].strip(), 16)
                except ValueError:
                    break
                buf = buf[crlf + 2:]
                if size == 0:
                    break
                result += buf[:size]
                buf = buf[size + 2:]
            resp_body = result

        try:
            with h2_lock:
                h2c.send_headers(stream_id, h2_resp_hdrs)
                d = h2c.data_to_send(65535)
                if d:
                    tls_client.sendall(d)

            chunk_size = 16384
            for i in range(0, len(resp_body), chunk_size):
                with h2_lock:
                    h2c.send_data(stream_id, resp_body[i: i + chunk_size])
                    d = h2c.data_to_send(65535)
                    if d:
                        tls_client.sendall(d)

            with h2_lock:
                h2c.send_data(stream_id, b"", end_stream=True)
                d = h2c.data_to_send(65535)
                if d:
                    tls_client.sendall(d)
        except Exception:
            pass

    @staticmethod
    def _to_origin_form(raw: bytes, path: str) -> bytes:
        """Cambia la línea de petición a forma de origen y quita cabeceras de proxy."""
        method, _target, version = hm.parse_request_line(raw)
        new_first = f"{method} {path} {version}".encode("latin-1", "replace")
        _head, sep, rest = raw.partition(b"\r\n")
        rebuilt = new_first + sep + rest
        lines = rebuilt.split(b"\r\n")
        out = []
        for line in lines:
            ll = line.lower()
            if ll.startswith(b"proxy-connection:"):
                continue
            if ll.startswith(b"accept-encoding:"):
                # Solo anunciar encodings que podemos decodificar para el History
                out.append(b"Accept-Encoding: " + _ACCEPT_ENCODING)
                continue
            out.append(line)
        return b"\r\n".join(out)
