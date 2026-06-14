"""Servidor HTTP REST de Leetch — acceso programático via API Key."""
from __future__ import annotations

import base64
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Callable
from urllib.parse import parse_qs, urlparse

from net.http_client import send_raw_request
from net import http_message as hm
from ui.style import decode, decode_http


def _flow_to_dict(flow, full: bool = False) -> dict:
    d = {
        "id":        flow.id,
        "method":    flow.method,
        "host":      flow.host,
        "port":      flow.port,
        "scheme":    flow.scheme,
        "url":       flow.url,
        "status":    flow.status,
        "length":    flow.length,
        "timestamp": flow.timestamp,
        "label":     flow.label,
        "comment":   flow.comment,
    }
    if full:
        d["request"]      = decode(flow.raw_request)
        d["response"]     = decode_http(flow.raw_response)
        d["request_b64"]  = base64.b64encode(flow.raw_request).decode()
        d["response_b64"] = base64.b64encode(flow.raw_response).decode()
    return d


class _Handler(BaseHTTPRequestHandler):
    # Inyectado por LeetchAPIServer antes de arrancar
    api_key:      str = ""
    flows_getter: Callable | None = None
    log_cb:       Callable | None = None   # callback(line: str)

    # ── logging ───────────────────────────────────────────────

    def log_message(self, fmt, *args):
        line = f"{self.address_string()} — {fmt % args}"
        if self.log_cb:
            self.log_cb(line)

    # ── auth ──────────────────────────────────────────────────

    def _authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth[7:] == self.api_key:
            return True
        qs = parse_qs(urlparse(self.path).query)
        return qs.get("api_key", [""])[0] == self.api_key

    # ── respuestas ────────────────────────────────────────────

    def _send_json(self, data, status: int = 200):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, msg: str, status: int):
        self._send_json({"error": msg}, status)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    # ── CORS preflight ────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    # ── GET ───────────────────────────────────────────────────

    def do_GET(self):
        if not self._authorized():
            self._send_error_json("Unauthorized — API key inválida o ausente", 401)
            return

        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        # GET /api/status
        if path == "/api/status":
            flows = self.flows_getter() if self.flows_getter else []
            self._send_json({
                "status": "ok",
                "version": "leetch",
                "flows": len(flows),
                "uptime": time.time(),
            })
            return

        # GET /api/flows
        if path == "/api/flows":
            flows  = self.flows_getter() if self.flows_getter else []
            limit  = int(qs.get("limit",  [str(len(flows))])[0])
            offset = int(qs.get("offset", ["0"])[0])
            method = qs.get("method", [None])[0]
            host   = qs.get("host",   [None])[0]
            status = qs.get("status", [None])[0]

            filtered = flows
            if method:
                filtered = [f for f in filtered if f.method.upper() == method.upper()]
            if host:
                filtered = [f for f in filtered if host.lower() in f.host.lower()]
            if status:
                filtered = [f for f in filtered if f.status.startswith(status)]

            page = filtered[offset: offset + limit]
            self._send_json({
                "total":  len(filtered),
                "offset": offset,
                "limit":  limit,
                "flows":  [_flow_to_dict(f) for f in page],
            })
            return

        # GET /api/flows/{id}
        if path.startswith("/api/flows/"):
            try:
                fid = int(path.split("/")[-1])
            except ValueError:
                self._send_error_json("ID de flow inválido", 400)
                return
            flows = self.flows_getter() if self.flows_getter else []
            flow  = next((f for f in flows if f.id == fid), None)
            if flow is None:
                self._send_error_json(f"Flow {fid} no encontrado", 404)
                return
            self._send_json(_flow_to_dict(flow, full=True))
            return

        self._send_error_json(f"Endpoint no encontrado: {path}", 404)

    # ── POST ──────────────────────────────────────────────────

    def do_POST(self):
        if not self._authorized():
            self._send_error_json("Unauthorized", 401)
            return

        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")

        # POST /api/repeat
        if path == "/api/repeat":
            try:
                body = self._read_body()
                data = json.loads(body)
            except Exception as exc:
                self._send_error_json(f"JSON inválido: {exc}", 400)
                return

            raw_text = data.get("request", "")
            tls      = bool(data.get("tls", False))

            if not raw_text:
                self._send_error_json("Campo 'request' requerido", 400)
                return

            raw_req = raw_text.replace("\r\n", "\n").replace("\n", "\r\n")
            raw_req = raw_req.encode("utf-8", "replace")

            # Parsear host del header Host:
            headers  = hm.parse_headers(raw_req)
            host_val = data.get("host") or headers.get("host", "")
            if not host_val:
                self._send_error_json("No se pudo determinar el host", 400)
                return

            if ":" in host_val:
                host, _, p = host_val.rpartition(":")
                try:
                    port = int(p)
                except ValueError:
                    host, port = host_val, 443 if tls else 80
            else:
                host = host_val
                port = data.get("port", 443 if tls else 80)

            tls = tls or port in (443, 8443)

            t0 = time.perf_counter()
            try:
                raw_resp = send_raw_request(raw_req, host, port, tls)
                ms = (time.perf_counter() - t0) * 1000
                first = raw_resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                parts = first.split(" ", 2)
                status = parts[1] if len(parts) >= 2 else "???"
                self._send_json({
                    "status":       status,
                    "length":       len(raw_resp),
                    "ms":           round(ms, 2),
                    "response":     decode_http(raw_resp),
                    "response_b64": base64.b64encode(raw_resp).decode(),
                })
            except Exception as exc:
                ms = (time.perf_counter() - t0) * 1000
                self._send_json({
                    "error":  str(exc),
                    "status": "ERR",
                    "ms":     round(ms, 2),
                }, 502)
            return

        self._send_error_json(f"Endpoint no encontrado: {path}", 404)

    # ── DELETE ────────────────────────────────────────────────

    def do_DELETE(self):
        if not self._authorized():
            self._send_error_json("Unauthorized", 401)
            return

        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")

        if path == "/api/flows":
            # Señal: limpiar history — lo hace el caller vía callback
            if self.log_cb:
                self.log_cb("DELETE /api/flows — la limpieza se hace desde la UI")
            self._send_json({"message": "Para limpiar el historial usa la UI (no se puede modificar el estado desde el API en esta versión)"}, 200)
            return

        self._send_error_json(f"Endpoint no encontrado: {path}", 404)


# ══════════════════════════════════════════════════════════════
class LeetchAPIServer:
    """Servidor REST de Leetch. Singleton gestionado desde APIKeyTab."""

    def __init__(self):
        self._server:       HTTPServer | None = None
        self._thread:       Thread | None = None
        self.api_key:       str = secrets.token_hex(24)   # 48 chars
        self.port:          int = 7070
        self.flows_getter:  Callable | None = None
        self.log_cb:        Callable | None = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self, port: int | None = None) -> str | None:
        """Arranca el servidor. Devuelve un mensaje de error o None si ok."""
        if self._server:
            return "El servidor ya está activo."
        if port:
            self.port = port
        try:
            handler = type("_H", (_Handler,), {
                "api_key":      self.api_key,
                "flows_getter": self.flows_getter,
                "log_cb":       self.log_cb,
            })
            self._server = HTTPServer(("127.0.0.1", self.port), handler)
        except OSError as exc:
            self._server = None
            return str(exc)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return None

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None
            self._thread = None

    def regenerate_key(self) -> str:
        self.api_key = secrets.token_hex(24)
        # actualizar el handler en caliente si el server está corriendo
        if self._server:
            self._server.RequestHandlerClass.api_key = self.api_key
        return self.api_key
