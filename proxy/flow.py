"""Modelo de datos Flow y utilidad de cabeceras HTTP."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class Flow:
    """Representa una petición interceptada junto a su respuesta."""

    id: int
    method: str
    host: str
    port: int
    scheme: str
    path: str
    raw_request: bytes
    raw_response: bytes = b""
    status: str = ""
    use_tls: bool = False
    timestamp: float = field(default_factory=time.time)
    label: str = ""     # "" | "rojo" | "naranja" | "amarillo" | "verde" | "azul" | "morado"
    comment: str = ""

    @property
    def url(self) -> str:
        netloc = self.host
        if (self.scheme == "http" and self.port != 80) or (
            self.scheme == "https" and self.port != 443
        ):
            netloc = f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"

    @property
    def length(self) -> int:
        return len(self.raw_response)


class PendingRequest:
    """Petición HTTP retenida en el Intercept hasta que el usuario decide Forward/Drop."""

    def __init__(self, raw: bytes, host: str, port: int, scheme: str):
        self.raw = raw
        self.host = host
        self.port = port
        self.scheme = scheme
        self._event = threading.Event()
        self.modified_raw: bytes | None = None
        self.dropped: bool = False

    def forward(self, modified: bytes | None = None) -> None:
        self.modified_raw = modified
        self.dropped = False
        self._event.set()

    def drop(self) -> None:
        self.dropped = True
        self._event.set()

    def wait(self, timeout: float = 300.0) -> bool:
        return self._event.wait(timeout=timeout)


def set_header(raw: bytes, header: bytes, value: bytes) -> bytes:
    """Sustituye o añade una cabecera en un mensaje HTTP crudo."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    hdr_lower = header.lower()
    new_lines = [lines[0]]
    found = False
    for line in lines[1:]:
        if line.lower().startswith(hdr_lower + b":"):
            new_lines.append(header + b": " + value)
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(header + b": " + value)
    return b"\r\n".join(new_lines) + sep + body
