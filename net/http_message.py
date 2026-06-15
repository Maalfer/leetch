from __future__ import annotations

import socket


def _recv_until_headers(sock: socket.socket) -> bytes:
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
    out = b""
    pending = buffer

    while True:
        # Esperar la línea de tamaño del próximo chunk
        while b"\r\n" not in pending:
            try:
                more = sock.recv(4096)
            except OSError:
                return out + pending
            if not more:
                return out + pending
            pending += more

        size_line, pending = pending.split(b"\r\n", 1)
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            return out + size_line + b"\r\n" + pending

        out += size_line + b"\r\n"

        if size == 0:
            while len(pending) < 2:
                try:
                    more = sock.recv(4096)
                except OSError:
                    break
                if not more:
                    break
                pending += more
            out += pending[:2]
            return out

        needed = size + 2
        while len(pending) < needed:
            try:
                more = sock.recv(4096)
            except OSError:
                out += pending
                return out
            if not more:
                out += pending
                return out
            pending += more

        out += pending[:needed]
        pending = pending[needed:]


def read_http_message(sock: socket.socket) -> bytes:
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
    first_line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = first_line.split(" ", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return first_line, "", ""


def parse_headers(raw: bytes) -> dict[str, str]:
    header_part = raw.split(b"\r\n\r\n", 1)[0]
    lines = header_part.split(b"\r\n")[1:]
    headers: dict[str, str] = {}
    for line in lines:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return headers


def status_code(raw: bytes) -> str:
    first_line = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = first_line.split(" ", 2)
    if len(parts) >= 2:
        return parts[1]
    return ""
