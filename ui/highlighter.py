"""Resaltado de sintaxis HTTP/JSON para QPlainTextEdit."""
from __future__ import annotations
import re
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont


def _fmt(color: str, bold: bool = False) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if bold:
        f.setFontWeight(QFont.Bold)
    return f


_F = {
    "method":   _fmt("#ff8c1a", bold=True),  # naranja  – verbo HTTP
    "path":     _fmt("#7fb3ff"),              # azul     – ruta/URL
    "version":  _fmt("#9aa1ad"),              # gris     – HTTP/1.1
    "status_2": _fmt("#5fd38a", bold=True),  # verde    – 2xx
    "status_3": _fmt("#4fc3d6", bold=True),  # cian     – 3xx
    "status_4": _fmt("#ffb454", bold=True),  # ámbar    – 4xx
    "status_5": _fmt("#ff6b6b", bold=True),  # rojo     – 5xx
    "hdr_name": _fmt("#4fc3d6"),             # cian     – nombre de header
    "hdr_sep":  _fmt("#9aa1ad"),             # gris     – ':'
    "hdr_val":  _fmt("#dfe3ea"),             # texto    – valor de header
    "num":      _fmt("#c3a6ff"),             # lila     – números en headers
    "j_key":    _fmt("#4fc3d6"),             # cian     – clave JSON
    "j_str":    _fmt("#5fd38a"),             # verde    – cadena JSON
    "j_num":    _fmt("#ffb454"),             # ámbar    – número JSON
    "j_kw":     _fmt("#ff8c1a", bold=True), # naranja  – true/false/null
}

_RE_REQUEST = re.compile(
    r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)'
    r'( +)(\S+)( +)(HTTP/[\d.]+)',
    re.IGNORECASE,
)
_RE_STATUS = re.compile(r'^(HTTP/[\d.]+)( +)(\d{3})([ \t].*)?$', re.IGNORECASE)
_RE_HEADER = re.compile(r'^([^:\r\n]+?)(:)([ \t]*)(.*)')
_RE_NUM_HDR = re.compile(r'\b\d[\d.,]*\b')

_RE_J_STR = re.compile(r'"(?:[^"\\]|\\.)*"')
_RE_J_NUM = re.compile(r'(?<!["\w])-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?!["\w])')
_RE_J_KW  = re.compile(r'\b(true|false|null)\b')

_S_FIRST = 0
_S_HDR   = 1
_S_BODY  = 2


class HTTPHighlighter(QSyntaxHighlighter):
    """Resalta peticiones y respuestas HTTP crudas (cabeceras + cuerpo JSON)."""

    def highlightBlock(self, text: str):
        prev = self.previousBlockState()

        if prev < _S_HDR:
            self._first_line(text)
            self.setCurrentBlockState(_S_BODY if not text.strip() else _S_HDR)

        elif prev == _S_HDR:
            if not text.strip():
                self.setCurrentBlockState(_S_BODY)
            else:
                self._header_line(text)
                self.setCurrentBlockState(_S_HDR)

        else:
            self._body_line(text)
            self.setCurrentBlockState(_S_BODY)

    def _first_line(self, text: str):
        m = _RE_REQUEST.match(text)
        if m:
            self.setFormat(m.start(1), len(m.group(1)), _F["method"])
            self.setFormat(m.start(3), len(m.group(3)), _F["path"])
            self.setFormat(m.start(5), len(m.group(5)), _F["version"])
            return
        m = _RE_STATUS.match(text)
        if m:
            self.setFormat(m.start(1), len(m.group(1)), _F["version"])
            code = m.group(3)
            key = f"status_{code[0]}" if code[0] in "2345" else "hdr_val"
            self.setFormat(m.start(3), len(code), _F[key])
            if m.group(4):
                self.setFormat(m.start(4), len(m.group(4)), _F["version"])

    def _header_line(self, text: str):
        m = _RE_HEADER.match(text)
        if not m:
            return
        self.setFormat(m.start(1), len(m.group(1)), _F["hdr_name"])
        self.setFormat(m.start(2), 1, _F["hdr_sep"])
        vs, val = m.start(4), m.group(4)
        self.setFormat(vs, len(val), _F["hdr_val"])
        for nm in _RE_NUM_HDR.finditer(val):
            self.setFormat(vs + nm.start(), nm.end() - nm.start(), _F["num"])

    def _body_line(self, text: str):
        if not text.strip():
            return
        if _RE_J_STR.search(text) or _RE_J_KW.search(text):
            _apply_json(self, text)


class JSONHighlighter(QSyntaxHighlighter):
    """Resalta contenido JSON puro (para vistas de JWT decoded)."""

    def highlightBlock(self, text: str):
        _apply_json(self, text)
        self.setCurrentBlockState(0)


def _apply_json(hl: QSyntaxHighlighter, text: str):
    # 1. todas las cadenas en verde
    for m in _RE_J_STR.finditer(text):
        hl.setFormat(m.start(), m.end() - m.start(), _F["j_str"])
    # 2. cadenas seguidas de ':' → clave (cian sobreescribe verde)
    for m in _RE_J_STR.finditer(text):
        rest = text[m.end():].lstrip()
        if rest.startswith(":"):
            hl.setFormat(m.start(), m.end() - m.start(), _F["j_key"])
    # 3. números (solo fuera de cadenas — aproximación suficiente)
    for m in _RE_J_NUM.finditer(text):
        hl.setFormat(m.start(), m.end() - m.start(), _F["j_num"])
    # 4. true / false / null
    for m in _RE_J_KW.finditer(text):
        hl.setFormat(m.start(), m.end() - m.start(), _F["j_kw"])
