"""Utilidades para leer y parsear mensajes HTTP crudos desde un socket."""
from __future__ import annotations

import socket


def _recv_until_headers(sock: socket.socket) -> bytes:
    """Lee de un socket hasta encontrar el final de las cabeceras (\r\n\r\n)."""
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 1_048_576:   # 1 MB — cabeceras nunca deben ser tan grandes
            break
    return data


def _read_exact(sock: socket.socket, buffer: bytes, n: int) -> bytes:
    """Devuelve al menos `n` bytes acumulando lo que ya hay en `buffer`."""
    data = buffer
    while len(data) < n:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


def _read_chunked(sock: socket.socket, buffer: bytes) -> bytes:
    """Lee un cuerpo con Transfer-Encoding: chunked. Devuelve los bytes crudos
    (incluyendo los marcadores de chunk, tal cual viajan por el cable)."""
    data = buffer
    while True:
        while b"\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                return data
            data += chunk
        size_line, rest = data.split(b"\r\n", 1)
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            return data
        if size == 0:
            data = _read_exact(sock, data, len(data) - len(rest) + 2)
            return data
        needed = len(data) - len(rest) + size + 2
        data = _read_exact(sock, data, needed)


def read_http_message(sock: socket.socket) -> bytes:
    """Lee un mensaje HTTP completo (cabeceras + cuerpo) de un socket.

    Maneja Content-Length, Transfer-Encoding: chunked y, en su defecto,
    lee hasta que el socket se cierra.
    """
    raw = _recv_until_headers(sock)
    if not raw or b"\r\n\r\n" not in raw:
        return raw

    header_part, body_part = raw.split(b"\r\n\r\n", 1)
    headers_lower = header_part.lower()

    if b"transfer-encoding: chunked" in headers_lower:
        body = _read_chunked(sock, body_part)
        return header_part + b"\r\n\r\n" + body

    content_length = None
    for line in header_part.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                content_length = None
            break

    if content_length is not None:
        body = _read_exact(sock, body_part, content_length)
        return header_part + b"\r\n\r\n" + body

    first_line = header_part.split(b"\r\n", 1)[0]
    if first_line.startswith(b"HTTP/"):
        parts = first_line.split(b" ", 2)
        sc = parts[1].strip() if len(parts) >= 2 else b""
        if sc[:1] == b"1" or sc in (b"204", b"304"):
            return header_part + b"\r\n\r\n" + body_part

        body = body_part
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            body += chunk
        return header_part + b"\r\n\r\n" + body

    return header_part + b"\r\n\r\n" + body_part


def parse_request_line(raw: bytes) -> tuple[str, str, str]:
    """Devuelve (método, target, versión) de la primera línea de una petición."""
    first_line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = first_line.split(" ", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return first_line, "", ""


def parse_headers(raw: bytes) -> dict[str, str]:
    """Devuelve un diccionario con las cabeceras (claves en minúscula)."""
    header_part = raw.split(b"\r\n\r\n", 1)[0]
    lines = header_part.split(b"\r\n")[1:]
    headers: dict[str, str] = {}
    for line in lines:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return headers


def status_code(raw: bytes) -> str:
    """Extrae el código de estado de una respuesta HTTP cruda."""
    first_line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = first_line.split(" ", 2)
    if len(parts) >= 2:
        return parts[1]
    return ""
