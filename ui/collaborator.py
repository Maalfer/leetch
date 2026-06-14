"""Collaborator — servidor de callbacks OOB: modo Local HTTP y modo interactsh."""
from __future__ import annotations

import base64
import http.server
import json
import secrets
import socket
import socketserver
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QSpinBox, QSplitter,
    QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    QFrame,
)

from ui.style import MONO, TEXT_DIM, ACCENT

# ══════════════════════════════════════════════════════════════
# Signal bridge (cross-thread → Qt)
# ══════════════════════════════════════════════════════════════

class _Bridge(QObject):
    callback  = Signal(object)   # dict con los datos del callback
    status    = Signal(str)      # mensaje de estado


# ══════════════════════════════════════════════════════════════
# Utilidades de red
# ══════════════════════════════════════════════════════════════

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _token() -> str:
    return secrets.token_hex(8)


# ══════════════════════════════════════════════════════════════
# Modo 1 — Servidor HTTP local
# ══════════════════════════════════════════════════════════════

class _LocalServer:
    """Servidor HTTP embebido que registra todos los callbacks entrantes."""

    def __init__(self, port: int, bridge: _Bridge):
        self._port   = port
        self._bridge = bridge
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        """Arranca el servidor. Devuelve la URL base o lanza excepción."""
        bridge = self._bridge

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  self._handle("GET")
            def do_POST(self): self._handle("POST")
            def do_HEAD(self): self._handle("HEAD")
            def do_PUT(self):  self._handle("PUT")
            def do_DELETE(self): self._handle("DELETE")

            def _handle(self, method: str):
                length = int(self.headers.get("Content-Length", 0))
                body   = self.rfile.read(length) if length else b""
                headers_txt = str(self.headers).strip()
                token = self.path.strip("/").split("/")[-1] if self.path != "/" else "(raíz)"
                bridge.callback.emit({
                    "ts":       time.time(),
                    "protocol": "HTTP",
                    "token":    token,
                    "ip":       self.client_address[0],
                    "detail":   f"{method} {self.path}",
                    "raw":      (
                        f"{method} {self.path} HTTP/1.1\r\n"
                        f"{headers_txt}\r\n\r\n"
                        + body.decode("utf-8", "replace")
                    ),
                })
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, *_):
                pass  # silenciar log de consola

        socketserver.TCPServer.allow_reuse_address = True
        self._server = socketserver.TCPServer(("0.0.0.0", self._port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()
        ip = _local_ip()
        return f"http://{ip}:{self._port}"

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None


# ══════════════════════════════════════════════════════════════
# Modo 2 — interactsh
# ══════════════════════════════════════════════════════════════

_INTERACTSH_SERVERS = [
    "https://interact.sh",
    "https://oast.pro",
    "https://oast.site",
    "https://oast.fun",
    "https://oast.online",
    "https://oast.me",
]

_ALPHABET = string.ascii_lowercase + string.digits


def _rand_id(n: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


class _InteractshClient:
    """Cliente interactsh con cifrado RSA/AES según el protocolo oficial."""

    POLL_INTERVAL = 5   # segundos entre polls

    def __init__(self, server: str, bridge: _Bridge):
        self._server  = server.rstrip("/")
        self._bridge  = bridge
        self._running = False
        self._thread: threading.Thread | None = None
        self._priv_key  = None
        self._corr_id   = ""
        self._secret    = ""
        self._host      = ""

    # ── registro ──────────────────────────────────────────────

    def start(self) -> str:
        """Registra sesión y arranca el hilo de polling. Devuelve el host único."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        self._priv_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048)
        pub_pem = self._priv_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._corr_id = _rand_id(33)
        self._secret  = secrets.token_hex(16)

        payload = json.dumps({
            "public-key":     base64.b64encode(pub_pem).decode(),
            "secret-key":     self._secret,
            "correlation-id": self._corr_id,
        }).encode()

        req = urllib.request.Request(
            f"{self._server}/register",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)

        domain = self._server.split("//", 1)[-1]
        self._host = f"{self._corr_id}.{domain}"
        self._running = True
        self._thread  = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        return self._host

    def stop(self):
        self._running = False

    # ── polling y descifrado ──────────────────────────────────

    def _poll_loop(self):
        url = (f"{self._server}/poll"
               f"?id={self._corr_id}&secret={urllib.parse.quote(self._secret)}")
        while self._running:
            try:
                resp = urllib.request.urlopen(url, timeout=10)
                data = json.loads(resp.read())
                self._process(data)
            except urllib.error.HTTPError as e:
                if e.code != 404:   # 404 = sin interacciones nuevas
                    self._bridge.status.emit(f"Poll error: {e.code}")
            except Exception as e:
                self._bridge.status.emit(f"Poll error: {e}")
            time.sleep(self.POLL_INTERVAL)

    def _process(self, data: dict):
        if not data.get("data") or not data.get("aes_key"):
            return
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        try:
            enc_aes = base64.b64decode(data["aes_key"])
            aes_key = self._priv_key.decrypt(
                enc_aes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            self._bridge.status.emit(f"Decrypt AES key error: {e}")
            return

        for item in data.get("data", []) + data.get("extra", []):
            try:
                raw = base64.b64decode(item)
                iv  = raw[:16]
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                dec = cipher.decryptor()
                plain = dec.update(raw[16:]) + dec.finalize()
                interaction = json.loads(plain)
                self._emit(interaction)
            except Exception:
                pass

    def _emit(self, ix: dict):
        proto  = ix.get("protocol", "?").upper()
        raw_req = ix.get("raw-request", "")
        detail  = ""
        if proto == "HTTP":
            first = raw_req.split("\n", 1)[0].strip() if raw_req else ""
            detail = first
        elif proto == "DNS":
            detail = ix.get("full-id", ix.get("q-type", ""))
        elif proto == "SMTP":
            detail = ix.get("smtp-from", "")

        self._bridge.callback.emit({
            "ts":       time.time(),
            "protocol": proto,
            "token":    ix.get("full-id", ""),
            "ip":       ix.get("remote-address", "").split(":")[0],
            "detail":   detail,
            "raw":      raw_req or json.dumps(ix, indent=2),
        })


# ══════════════════════════════════════════════════════════════
# CollaboratorTab — UI principal
# ══════════════════════════════════════════════════════════════

_PROTO_COLOR = {
    "HTTP":  "#4fc3d6",
    "DNS":   "#ffb454",
    "SMTP":  "#5fd38a",
}


class CollaboratorTab(QWidget):
    def __init__(self):
        super().__init__()
        self._bridge  = _Bridge()
        self._bridge.callback.connect(self._on_callback)
        self._bridge.status.connect(self._on_status)
        self._active  = False
        self._backend: _LocalServer | _InteractshClient | None = None
        self._base_url = ""
        self._build_ui()

    # ── construcción ──────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── barra superior ────────────────────────────────────
        top = QHBoxLayout()
        top.setSpacing(8)

        top.addWidget(QLabel("Modo:"))
        self._mode_combo = QComboBox()
        self._mode_combo.addItems(["Local HTTP", "interactsh"])
        self._mode_combo.setFixedWidth(120)
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        top.addWidget(self._mode_combo)

        sep = QFrame(); sep.setFrameShape(QFrame.VLine); sep.setFixedWidth(1)
        top.addWidget(sep)

        self._status_dot = QLabel("●")
        self._status_dot.setStyleSheet("color: #555; font-size: 16px;")
        top.addWidget(self._status_dot)

        self._status_lbl = QLabel("Parado")
        self._status_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        top.addWidget(self._status_lbl)

        top.addStretch()

        self._start_btn = QPushButton("▶  Iniciar")
        self._start_btn.setObjectName("primaryButton")
        self._start_btn.clicked.connect(self._toggle)
        top.addWidget(self._start_btn)

        clear_btn = QPushButton("Limpiar")
        clear_btn.clicked.connect(self._clear)
        top.addWidget(clear_btn)

        root.addLayout(top)

        # ── panel de configuración (cambia según modo) ────────
        self._cfg_stack = QStackedWidget()
        self._cfg_stack.setMaximumHeight(70)

        # — panel Local —
        local_w = QWidget()
        ll = QHBoxLayout(local_w)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)
        ll.addWidget(QLabel("Puerto:"))
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1024, 65535)
        self._port_spin.setValue(7777)
        self._port_spin.setFixedWidth(80)
        ll.addWidget(self._port_spin)
        ll.addWidget(QLabel("URL base:"))
        self._local_url_lbl = QLabel(f"http://{_local_ip()}:7777")
        self._local_url_lbl.setStyleSheet(f"color: {ACCENT}; font-family: monospace;")
        ll.addWidget(self._local_url_lbl)
        ll.addStretch()
        self._cfg_stack.addWidget(local_w)

        # — panel interactsh —
        ix_w = QWidget()
        il = QHBoxLayout(ix_w)
        il.setContentsMargins(0, 0, 0, 0)
        il.setSpacing(8)
        il.addWidget(QLabel("Servidor:"))
        self._server_combo = QComboBox()
        self._server_combo.addItems(_INTERACTSH_SERVERS + ["Custom…"])
        self._server_combo.setFixedWidth(200)
        self._server_combo.currentTextChanged.connect(self._on_server_changed)
        il.addWidget(self._server_combo)
        self._custom_url = QLineEdit()
        self._custom_url.setPlaceholderText("https://mi-servidor.com")
        self._custom_url.setFixedWidth(200)
        self._custom_url.setVisible(False)
        il.addWidget(self._custom_url)
        il.addWidget(QLabel("Host asignado:"))
        self._ix_host_lbl = QLabel("—")
        self._ix_host_lbl.setStyleSheet(f"color: {ACCENT}; font-family: monospace;")
        il.addWidget(self._ix_host_lbl)
        il.addStretch()
        self._cfg_stack.addWidget(ix_w)

        root.addWidget(self._cfg_stack)

        # ── generador de payloads ─────────────────────────────
        pay_frame = QFrame()
        pay_frame.setObjectName("controlBar")
        pay_lay = QHBoxLayout(pay_frame)
        pay_lay.setContentsMargins(8, 6, 8, 6)
        pay_lay.setSpacing(8)

        pay_lay.addWidget(QLabel("Payload:"))
        self._payload_edit = QLineEdit()
        self._payload_edit.setFont(MONO)
        self._payload_edit.setReadOnly(True)
        self._payload_edit.setPlaceholderText("Inicia el servidor para generar payloads…")
        pay_lay.addWidget(self._payload_edit, 1)

        gen_btn = QPushButton("⟳ Nuevo token")
        gen_btn.clicked.connect(self._gen_payload)
        pay_lay.addWidget(gen_btn)

        copy_btn = QPushButton("Copiar")
        copy_btn.clicked.connect(
            lambda: __import__("PySide6.QtWidgets", fromlist=["QApplication"])
            .QApplication.clipboard().setText(self._payload_edit.text()))
        pay_lay.addWidget(copy_btn)

        root.addWidget(pay_frame)

        # ── splitter tabla / detalle ──────────────────────────
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(8)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Hora", "Protocolo", "IP origen", "Token / ID", "Detalle"])
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(26)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        hdr.setHighlightSections(False)
        self._table.setColumnWidth(0, 80)
        self._table.setColumnWidth(1, 85)
        self._table.setColumnWidth(2, 120)
        self._table.setColumnWidth(3, 220)
        self._table.itemSelectionChanged.connect(self._on_selection)
        splitter.addWidget(self._table)

        detail_box = QWidget()
        dl = QVBoxLayout(detail_box)
        dl.setContentsMargins(0, 4, 0, 0)
        dl.setSpacing(4)
        det_lbl = QLabel("Detalle del callback")
        det_lbl.setObjectName("paneCaption")
        dl.addWidget(det_lbl)
        self._detail_edit = QPlainTextEdit()
        self._detail_edit.setFont(MONO)
        self._detail_edit.setReadOnly(True)
        dl.addWidget(self._detail_edit)
        splitter.addWidget(detail_box)
        splitter.setSizes([320, 180])

        root.addWidget(splitter, 1)

        # ── contador ──────────────────────────────────────────
        self._count_lbl = QLabel("0 callbacks recibidos")
        self._count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        root.addWidget(self._count_lbl)

    # ── lógica de modo ────────────────────────────────────────

    def _on_mode_changed(self, idx: int):
        self._cfg_stack.setCurrentIndex(idx)
        if self._active:
            self._stop()

    def _on_server_changed(self, text: str):
        self._custom_url.setVisible(text == "Custom…")

    def _port_changed(self, _):
        ip = _local_ip()
        self._local_url_lbl.setText(f"http://{ip}:{self._port_spin.value()}")

    # ── arranque / parada ────────────────────────────────────

    def _toggle(self):
        if self._active:
            self._stop()
        else:
            self._start()

    def _start(self):
        mode = self._mode_combo.currentIndex()
        try:
            if mode == 0:
                self._backend = _LocalServer(self._port_spin.value(), self._bridge)
                self._base_url = self._backend.start()
                self._local_url_lbl.setText(self._base_url)
            else:
                srv = self._server_combo.currentText()
                if srv == "Custom…":
                    srv = self._custom_url.text().strip()
                    if not srv:
                        self._set_status("Introduce la URL del servidor custom.", error=True)
                        return
                self._bridge.status.emit("Registrando en interactsh…")
                self._backend = _InteractshClient(srv, self._bridge)
                host = self._backend.start()
                self._base_url = f"http://{host}"
                self._ix_host_lbl.setText(host)
        except Exception as e:
            self._set_status(f"Error al iniciar: {e}", error=True)
            return

        self._active = True
        self._start_btn.setText("■  Detener")
        self._mode_combo.setEnabled(False)
        self._port_spin.setEnabled(False)
        self._server_combo.setEnabled(False)
        self._set_status("Activo", ok=True)
        self._gen_payload()

    def _stop(self):
        if self._backend:
            self._backend.stop()
            self._backend = None
        self._active = False
        self._base_url = ""
        self._start_btn.setText("▶  Iniciar")
        self._mode_combo.setEnabled(True)
        self._port_spin.setEnabled(True)
        self._server_combo.setEnabled(True)
        self._set_status("Parado")
        self._payload_edit.clear()

    # ── generación de payloads ────────────────────────────────

    def _gen_payload(self):
        if not self._active:
            return
        tok = _token()
        mode = self._mode_combo.currentIndex()
        if mode == 0:
            url = f"{self._base_url}/collab/{tok}"
        else:
            host = self._ix_host_lbl.text()
            url  = f"http://{tok}.{host}"
        self._payload_edit.setText(url)

    # ── callbacks entrantes ───────────────────────────────────

    @Slot(object)
    def _on_callback(self, cb: dict):
        row = self._table.rowCount()
        self._table.insertRow(row)
        hora = datetime.fromtimestamp(cb["ts"]).strftime("%H:%M:%S")
        proto = cb.get("protocol", "?")
        color = QColor(_PROTO_COLOR.get(proto, "#dfe3ea"))
        for col, text in enumerate([
            hora, proto,
            cb.get("ip", ""),
            cb.get("token", ""),
            cb.get("detail", ""),
        ]):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, cb)
            if col == 1:
                item.setForeground(color)
            self._table.setItem(row, col, item)
        self._table.scrollToBottom()
        total = self._table.rowCount()
        self._count_lbl.setText(f"{total} callback{'s' if total != 1 else ''} recibido{'s' if total != 1 else ''}")

    @Slot(str)
    def _on_status(self, msg: str):
        self._status_lbl.setText(msg)

    def _on_selection(self):
        items = self._table.selectedItems()
        if not items:
            self._detail_edit.clear()
            return
        cb = items[0].data(Qt.UserRole)
        if cb:
            self._detail_edit.setPlainText(cb.get("raw", ""))

    # ── utilidades ────────────────────────────────────────────

    def _set_status(self, msg: str, ok: bool = False, error: bool = False):
        if ok:
            color = "#5fd38a"
        elif error:
            color = "#ff6b6b"
        else:
            color = "#555"
        self._status_dot.setStyleSheet(f"color: {color}; font-size: 16px;")
        self._status_lbl.setText(msg)

    def _clear(self):
        self._table.setRowCount(0)
        self._detail_edit.clear()
        self._count_lbl.setText("0 callbacks recibidos")
