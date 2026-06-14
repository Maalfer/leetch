"""Paleta de colores, fuente monoespaciada y stylesheet QSS de Leech."""
from __future__ import annotations

from PySide6.QtGui import QColor, QFont

MONO = QFont("Menlo")
MONO.setStyleHint(QFont.Monospace)
MONO.setPointSize(12)

ACCENT = "#ff8c1a"
ACCENT_HOVER = "#ffa040"
ACCENT_PRESSED = "#e07000"
BG_DEEP = "#1b1d22"
BG_BASE = "#23262d"
BG_PANEL = "#2b2f37"
BORDER = "#3a3f4a"
TEXT = "#dfe3ea"
TEXT_DIM = "#9aa1ad"
SELECTION = "#3a4a63"


def decode(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _unchunk(body: bytes) -> bytes:
    """Extrae los datos de un cuerpo Transfer-Encoding: chunked."""
    result = b""
    while body:
        crlf = body.find(b"\r\n")
        if crlf == -1:
            break
        try:
            size = int(body[:crlf].split(b";")[0].strip(), 16)
        except ValueError:
            break
        body = body[crlf + 2:]
        if size == 0:
            break
        result += body[:size]
        body = body[size + 2:]
    return result


def _decompress(body: bytes, encoding: str) -> bytes:
    import gzip, zlib
    enc = encoding.lower().strip()
    try:
        if enc == "gzip":
            return gzip.decompress(body)
        if enc == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -15)
        if enc in ("br", "brotli"):
            import brotli          # pip install brotli (opcional)
            return brotli.decompress(body)
        if enc == "zstd":
            import zstandard       # pip install zstandard (opcional)
            return zstandard.ZstdDecompressor().decompress(body)
    except Exception:
        pass
    return body


def decode_http(raw: bytes) -> str:
    """Decodifica un mensaje HTTP descomprimiendo y desencadenando el cuerpo."""
    if not raw:
        return ""
    if b"\r\n\r\n" not in raw:
        return decode(raw)

    header_bytes, body = raw.split(b"\r\n\r\n", 1)
    headers_lower = header_bytes.lower()

    if b"transfer-encoding: chunked" in headers_lower:
        body = _unchunk(body)

    content_encoding = ""
    for line in header_bytes.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-encoding:"):
            content_encoding = line.split(b":", 1)[1].decode("latin-1").strip()
            break

    if content_encoding:
        body = _decompress(body, content_encoding)

    return decode(header_bytes) + "\r\n\r\n" + decode(body)


def status_color(status: str) -> QColor | None:
    """Color del texto según la clase del código HTTP."""
    s = (status or "").strip()
    if not s[:1].isdigit():
        return None
    cls = s[0]
    if cls == "2":
        return QColor("#5fd38a")
    if cls == "3":
        return QColor("#4fc3d6")
    if cls == "4":
        return QColor("#ffb454")
    if cls == "5":
        return QColor("#ff6b6b")
    return QColor(TEXT_DIM)


STYLE = """
* {{
    font-size: 13px;
}}
QWidget {{
    background-color: {bg_base};
    color: {text};
}}
QMainWindow, QDialog {{
    background-color: {bg_base};
}}

QLabel#brand {{
    font-size: 22px;
    font-weight: 700;
    color: {text};
    letter-spacing: 0.5px;
}}
QLabel#tagline {{
    color: {text_dim};
    font-size: 12px;
    padding-left: 6px;
}}
QLabel#paneCaption {{
    color: {text_dim};
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 1px;
}}

QFrame#controlBar {{
    background-color: {bg_panel};
    border: 1px solid {border};
    border-radius: 8px;
}}
QLabel#statusLabel {{
    font-weight: 600;
    padding: 0 6px;
}}
QLabel#statusLabel[state="running"] {{
    color: {accent_green};
}}
QLabel#statusLabel[state="stopped"] {{
    color: {text_dim};
}}

QTabWidget::pane {{
    border: 1px solid {border};
    border-radius: 8px;
    background-color: {bg_base};
    top: -1px;
}}
QTabWidget#innerTabWidget::pane {{
    border: 1px solid {border};
    border-radius: 6px;
    background-color: {bg_deep};
    top: -1px;
}}
QTabWidget#innerTabWidget > QTabBar::tab {{
    background-color: {bg_deep};
    color: {text_dim};
    padding: 5px 14px;
    margin-right: 2px;
    border: 1px solid {border};
    border-bottom: none;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    font-size: 12px;
}}
QTabWidget#innerTabWidget > QTabBar::tab:selected {{
    background-color: {bg_base};
    color: {text};
    border-bottom: 2px solid {accent};
}}
QTabWidget#innerTabWidget > QTabBar::tab:hover:!selected {{
    background-color: {bg_panel};
    color: {text};
}}
QTabBar::tab {{
    background-color: {bg_panel};
    color: {text_dim};
    padding: 7px 16px;
    margin-right: 2px;
    border: 1px solid {border};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}}
QTabBar::tab:selected {{
    background-color: {bg_base};
    color: {text};
    border-bottom: 2px solid {accent};
}}
QTabBar::tab:hover:!selected {{
    background-color: {bg_panel_hover};
    color: {text};
}}
QPushButton#tabCloseBtn {{
    background: transparent;
    color: {text_dim};
    border: none;
    border-radius: 3px;
    font-size: 13px;
    font-weight: bold;
    padding: 0px;
    margin: 0px 2px;
}}
QPushButton#tabCloseBtn:hover {{
    background-color: rgba(255, 107, 107, 0.22);
    color: #ff6b6b;
}}
QPushButton#tabCloseBtn:pressed {{
    background-color: rgba(255, 107, 107, 0.4);
    color: #ff6b6b;
}}

QPushButton#addTabBtn {{
    background: transparent;
    color: {text_dim};
    border: none;
    border-radius: 5px;
    font-size: 17px;
    font-weight: bold;
    padding: 0px 4px;
    margin: 2px 4px;
}}
QPushButton#addTabBtn:hover {{
    background-color: {bg_panel};
    color: {accent};
}}
QPushButton#addTabBtn:pressed {{
    background-color: {accent};
    color: #ffffff;
}}

QLineEdit#panelSearch {{
    background-color: {bg_deep};
    color: {text};
    border: 1px solid {border};
    border-radius: 4px;
    padding: 2px 6px;
    font-size: 11px;
}}
QLineEdit#panelSearch:focus {{
    border-color: {accent};
}}
QLabel#searchCount {{
    color: {text_dim};
    font-size: 11px;
}}
QPushButton#searchNavBtn {{
    background-color: {bg_panel};
    color: {text_dim};
    border: 1px solid {border};
    border-radius: 5px;
    font-size: 12px;
    padding: 0px;
}}
QPushButton#searchNavBtn:hover {{
    background-color: {bg_panel_hover};
    color: {text};
    border-color: {border_hover};
}}
QPushButton#searchNavBtn:pressed {{
    background-color: {bg_deep};
}}

QPushButton {{
    background-color: {bg_panel};
    color: {text};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 6px 14px;
}}
QPushButton:hover {{
    background-color: {bg_panel_hover};
    border-color: {border_hover};
}}
QPushButton:pressed {{
    background-color: {bg_deep};
}}
QPushButton:disabled {{
    color: #5a606b;
    background-color: {bg_deep};
    border-color: {border};
}}
QPushButton#primaryButton {{
    background-color: {accent};
    color: #1b1d22;
    border: 1px solid {accent};
    font-weight: 700;
}}
QPushButton#primaryButton:hover {{
    background-color: {accent_hover};
    border-color: {accent_hover};
}}
QPushButton#primaryButton:pressed {{
    background-color: {accent_pressed};
    border-color: {accent_pressed};
}}
QPushButton#primaryButton:disabled {{
    background-color: #6b5634;
    color: #b9a079;
    border-color: #6b5634;
}}

QLineEdit, QSpinBox {{
    background-color: {bg_deep};
    color: {text};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 5px 8px;
    selection-background-color: {selection};
    selection-color: {text};
}}
QLineEdit:focus, QSpinBox:focus {{
    border: 1px solid {accent};
}}
QLineEdit:disabled, QSpinBox:disabled {{
    color: {text_dim};
    background-color: {bg_panel};
}}
QSpinBox::up-button, QSpinBox::down-button {{
    width: 16px;
    background-color: {bg_panel};
    border: none;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
    background-color: {bg_panel_hover};
}}

QPlainTextEdit {{
    background-color: {bg_deep};
    color: {text};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 8px;
    selection-background-color: {selection};
    selection-color: #ffffff;
}}
QPlainTextEdit:focus {{
    border: 1px solid {border_hover};
}}

QTableWidget {{
    background-color: {bg_deep};
    color: {text};
    border: 1px solid {border};
    border-radius: 8px;
    alternate-background-color: #20232a;
    gridline-color: transparent;
}}
QTableWidget::item {{
    padding: 2px 8px;
    border: none;
}}
QTableWidget::item:selected {{
    background-color: {selection};
    color: #ffffff;
}}
QTreeWidget {{
    background-color: {bg_deep};
    color: {text};
    border: 1px solid {border};
    border-radius: 8px;
    alternate-background-color: #20232a;
}}
QTreeWidget::item {{
    padding: 3px 6px;
    border: none;
}}
QTreeWidget::item:selected {{
    background-color: {selection};
    color: #ffffff;
}}
QTreeWidget::item:hover:!selected {{
    background-color: {bg_panel};
}}
QHeaderView::section {{
    background-color: {bg_panel};
    color: {text_dim};
    border: none;
    border-right: 1px solid {border};
    border-bottom: 1px solid {border};
    padding: 7px 8px;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
}}
QHeaderView::section:hover {{
    color: {text};
}}
QTableCornerButton::section {{
    background-color: {bg_panel};
    border: none;
}}

QScrollBar:vertical {{
    background-color: transparent;
    width: 12px;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background-color: {border_hover};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {text_dim};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QScrollBar:horizontal {{
    background-color: transparent;
    height: 12px;
    margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background-color: {border_hover};
    border-radius: 5px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background-color: {text_dim};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

QSplitter::handle {{
    background-color: transparent;
}}
QSplitter::handle:hover {{
    background-color: {accent};
}}
QCheckBox {{
    color: {text};
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    background-color: {bg_deep};
    border: 1px solid {border_hover};
    border-radius: 4px;
}}
QCheckBox::indicator:hover {{
    border: 1px solid {accent};
}}
QCheckBox::indicator:checked {{
    background-color: {accent};
    border: 1px solid {accent};
}}
QLabel {{
    background-color: transparent;
    color: {text};
}}
QMenu {{
    background-color: {bg_panel};
    color: {text};
    border: 1px solid {border_hover};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 18px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background-color: {accent};
    color: #1b1d22;
}}
QMessageBox {{
    background-color: {bg_base};
    color: {text};
}}
QToolTip {{
    background-color: {bg_panel};
    color: {text};
    border: 1px solid {border_hover};
    padding: 4px;
}}
QProgressBar {{
    background-color: {bg_deep};
    border: 1px solid {border};
    border-radius: 4px;
    text-align: center;
    color: {text_dim};
    font-size: 11px;
}}
QProgressBar::chunk {{
    background-color: {accent};
    border-radius: 3px;
}}
QPushButton#scopeBtn:checked {{
    background-color: {accent};
    color: #1b1d22;
    border-color: {accent};
    font-weight: 600;
}}
QPushButton#scopeBtn:checked:hover {{
    background-color: {accent_hover};
    border-color: {accent_hover};
}}

QPushButton#interceptBtn {{
    font-weight: 700;
    min-width: 150px;
}}
QPushButton#interceptBtn:checked {{
    background-color: #c0392b;
    color: #ffffff;
    border-color: #c0392b;
    font-weight: 700;
}}
QPushButton#interceptBtn:checked:hover {{
    background-color: #e74c3c;
    border-color: #e74c3c;
}}
""".format(
    bg_base=BG_BASE,
    bg_deep=BG_DEEP,
    bg_panel=BG_PANEL,
    bg_panel_hover="#343943",
    border=BORDER,
    border_hover="#4c525e",
    text=TEXT,
    text_dim=TEXT_DIM,
    accent=ACCENT,
    accent_hover=ACCENT_HOVER,
    accent_pressed=ACCENT_PRESSED,
    accent_green="#5fd38a",
    selection=SELECTION,
)
