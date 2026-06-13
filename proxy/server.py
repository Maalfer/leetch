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
from proxy.flow import Flow, set_header
from net import http_message as hm


class ProxyServer:
    """Servidor proxy multihilo con MITM HTTPS."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 on_flow: Optional[Callable[[Flow], None]] = None):
        self.host = host
        self.port = port
        self.on_flow = on_flow
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
        client_ctx.set_alpn_protocols(["http/1.1"])

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

                flow.raw_response = response
                flow.status = hm.status_code(response)

                forwarded = set_header(response, b"Connection", b"keep-alive")

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

    @staticmethod
    def _to_origin_form(raw: bytes, path: str) -> bytes:
        """Cambia la línea de petición a forma de origen y quita cabeceras de proxy."""
        method, _target, version = hm.parse_request_line(raw)
        new_first = f"{method} {path} {version}".encode("latin-1", "replace")
        _head, sep, rest = raw.partition(b"\r\n")
        rebuilt = new_first + sep + rest
        lines = rebuilt.split(b"\r\n")
        lines = [l for l in lines if not l.lower().startswith(b"proxy-connection:")]
        return b"\r\n".join(lines)
