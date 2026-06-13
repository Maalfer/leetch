
"""Envío de peticiones HTTP crudas, usado por el Repeater."""
from __future__ import annotations

import socket
import ssl

import http_message as hm


def send_raw_request(raw: bytes, host: str, port: int, use_tls: bool,
                     timeout: float = 20.0) -> bytes:
    """Envía una petición HTTP cruda a host:port y devuelve la respuesta cruda.

    Lanza una excepción si la conexión falla (el llamador la captura).
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            # Permitimos certificados no verificables: es una herramienta de pruebas.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw)
        return hm.read_http_message(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass
