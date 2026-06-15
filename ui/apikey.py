from __future__ import annotations

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QFrame, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QScrollArea,
    QSpinBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QVBoxLayout, QWidget,
)

from api.server import LeetchAPIServer
from ui.style import MONO, TEXT_DIM, ACCENT

_GREEN = "#5fd38a"
_RED   = "#ff6b6b"
_AMBER = "#ffb454"

_ENDPOINTS = [
    ("GET",    "/api/status",      "Estado del servidor y número de flows capturados"),
    ("GET",    "/api/flows",       "Lista de flows del HTTP History (soporta ?limit=, ?offset=, ?method=, ?host=, ?status=)"),
    ("GET",    "/api/flows/{id}",  "Flow completo: request, response (texto + base64), metadatos"),
    ("POST",   "/api/repeat",      "Envía una petición HTTP raw y devuelve la respuesta"),
]

_EXAMPLE_CURL = """\
# Listar flows
curl -s -H "Authorization: Bearer {key}" \\
     {url}/api/flows | python3 -m json.tool

# Ver flow completo
curl -s -H "Authorization: Bearer {key}" \\
     {url}/api/flows/1

# Repetir una petición
curl -s -X POST \\
     -H "Authorization: Bearer {key}" \\
     -H "Content-Type: application/json" \\
     -d '{{"request":"GET / HTTP/1.1\\r\\nHost: ejemplo.com\\r\\n\\r\\n","tls":false}}' \\
     {url}/api/repeat

# También se puede pasar la key como query param:
curl -s "{url}/api/flows?api_key={key}&limit=10"
"""


class _LogEmitter(QObject):
    line = Signal(str)


class APIKeyTab(QWidget):
    def __init__(self):
        super().__init__()
        self._server  = LeetchAPIServer()
        self._emitter = _LogEmitter()
        self._emitter.line.connect(self._append_log)
        self._server.log_cb = lambda msg: self._emitter.line.emit(msg)
        self._build_ui()


    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        root.addWidget(scroll)

        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(14)
        scroll.setWidget(inner)

        # ── título ────────────────────────────────────────────
        title = QLabel("API REST — Acceso programático a Leetch")
        title.setStyleSheet("font-size: 15px; font-weight: bold;")
        lay.addWidget(title)

        subtitle = QLabel(
            "El servidor escucha en localhost. Usa la API Key para autenticar "
            "peticiones desde la terminal, scripts o IAs.")
        subtitle.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        subtitle.setWordWrap(True)
        lay.addWidget(subtitle)

        # ── estado + controles ────────────────────────────────
        lay.addWidget(self._build_server_panel())

        # ── api key ───────────────────────────────────────────
        lay.addWidget(self._build_key_panel())

        # ── endpoints ─────────────────────────────────────────
        lay.addWidget(self._build_endpoints_panel())

        # ── ejemplos curl ─────────────────────────────────────
        lay.addWidget(self._build_examples_panel())

        # ── log ───────────────────────────────────────────────
        lay.addWidget(self._build_log_panel())

        lay.addStretch()

    def _build_server_panel(self) -> QGroupBox:
        box = QGroupBox("Servidor")
        lay = QHBoxLayout(box)
        lay.setSpacing(12)

        # indicador de estado
        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {_RED}; font-size: 18px;")
        lay.addWidget(self.status_dot)

        self.status_lbl = QLabel("Inactivo")
        self.status_lbl.setMinimumWidth(130)
        lay.addWidget(self.status_lbl)

        lay.addWidget(QLabel("Puerto:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(self._server.port)
        self.port_spin.setFixedWidth(75)
        lay.addWidget(self.port_spin)

        self.toggle_btn = QPushButton("▶  Iniciar servidor")
        self.toggle_btn.setObjectName("primaryButton")
        self.toggle_btn.setMinimumWidth(150)
        self.toggle_btn.clicked.connect(self._toggle_server)
        lay.addWidget(self.toggle_btn)

        lay.addStretch()
        return box

    def _build_key_panel(self) -> QGroupBox:
        box = QGroupBox("API Key")
        lay = QVBoxLayout(box)
        lay.setSpacing(8)

        note = QLabel(
            "Incluye esta clave en el header <b>Authorization: Bearer &lt;key&gt;</b> "
            "o como query param <b>?api_key=&lt;key&gt;</b>.")
        note.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        note.setWordWrap(True)
        lay.addWidget(note)

        key_row = QHBoxLayout()
        key_row.setSpacing(8)

        self.key_edit = QLineEdit(self._server.api_key)
        self.key_edit.setFont(MONO)
        self.key_edit.setReadOnly(True)
        self.key_edit.setStyleSheet(
            f"background: #13151a; color: {ACCENT}; padding: 4px 8px; border-radius: 4px;")
        key_row.addWidget(self.key_edit, 1)

        copy_btn = QPushButton("Copiar")
        copy_btn.setFixedWidth(70)
        copy_btn.clicked.connect(self._copy_key)
        key_row.addWidget(copy_btn)

        regen_btn = QPushButton("Regenerar")
        regen_btn.setFixedWidth(90)
        regen_btn.clicked.connect(self._regen_key)
        key_row.addWidget(regen_btn)

        lay.addLayout(key_row)

        warn = QLabel("Regenerar invalida la clave anterior inmediatamente.")
        warn.setStyleSheet(f"color: {_AMBER}; font-size: 10px;")
        lay.addWidget(warn)

        return box

    def _build_endpoints_panel(self) -> QGroupBox:
        box = QGroupBox("Endpoints disponibles")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(8, 8, 8, 8)

        tbl = QTableWidget(len(_ENDPOINTS), 3)
        tbl.setHorizontalHeaderLabels(["Método", "Ruta", "Descripción"])
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setSelectionMode(QTableWidget.NoSelection)
        tbl.setShowGrid(False)
        tbl.verticalHeader().setVisible(False)
        tbl.verticalHeader().setDefaultSectionSize(26)
        tbl.horizontalHeader().setHighlightSections(False)
        tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        tbl.setColumnWidth(0, 60)
        tbl.setColumnWidth(1, 180)

        _method_color = {
            "GET": _GREEN, "POST": _AMBER, "DELETE": _RED,
        }
        for row, (method, path, desc) in enumerate(_ENDPOINTS):
            m_item = QTableWidgetItem(method)
            m_item.setForeground(QColor(_method_color.get(method, TEXT_DIM)))
            m_item.setFont(MONO)
            tbl.setItem(row, 0, m_item)

            p_item = QTableWidgetItem(path)
            p_item.setFont(MONO)
            p_item.setForeground(QColor("#7fb3ff"))
            tbl.setItem(row, 1, p_item)

            tbl.setItem(row, 2, QTableWidgetItem(desc))

        tbl.setFixedHeight(26 * len(_ENDPOINTS) + tbl.horizontalHeader().height() + 4)
        lay.addWidget(tbl)
        return box

    def _build_examples_panel(self) -> QGroupBox:
        box = QGroupBox("Ejemplos de uso")
        lay = QVBoxLayout(box)

        self.example_edit = QPlainTextEdit()
        self.example_edit.setFont(MONO)
        self.example_edit.setReadOnly(True)
        self.example_edit.setFixedHeight(210)
        self.example_edit.setPlainText(self._render_example())
        lay.addWidget(self.example_edit)

        copy_ex_btn = QPushButton("Copiar ejemplos")
        copy_ex_btn.setFixedWidth(130)
        copy_ex_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self.example_edit.toPlainText()))
        lay.addWidget(copy_ex_btn)
        return box

    def _build_log_panel(self) -> QGroupBox:
        box = QGroupBox("Log de peticiones")
        lay = QVBoxLayout(box)

        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(MONO)
        self.log_edit.setFixedHeight(130)
        self.log_edit.setPlaceholderText("Las peticiones entrantes aparecerán aquí…")
        lay.addWidget(self.log_edit)

        clr_btn = QPushButton("Limpiar log")
        clr_btn.setFixedWidth(100)
        clr_btn.clicked.connect(self.log_edit.clear)
        lay.addWidget(clr_btn)
        return box


    def _render_example(self) -> str:
        return _EXAMPLE_CURL.format(
            key=self._server.api_key,
            url=self._server.base_url,
        )

    def _update_example(self):
        self.example_edit.setPlainText(self._render_example())

    def _set_status(self, active: bool):
        if active:
            self.status_dot.setStyleSheet(f"color: {_GREEN}; font-size: 18px;")
            self.status_lbl.setText(f"Activo en {self._server.base_url}")
            self.toggle_btn.setText("■  Detener servidor")
            self.port_spin.setEnabled(False)
        else:
            self.status_dot.setStyleSheet(f"color: {_RED}; font-size: 18px;")
            self.status_lbl.setText("Inactivo")
            self.toggle_btn.setText("▶  Iniciar servidor")
            self.port_spin.setEnabled(True)


    def _toggle_server(self):
        if self._server.running:
            self._server.stop()
            self._set_status(False)
            self._append_log("Servidor detenido.")
        else:
            err = self._server.start(port=self.port_spin.value())
            if err:
                self._append_log(f"Error al arrancar: {err}")
                return
            self._set_status(True)
            self._append_log(
                f"Servidor activo en {self._server.base_url}  "
                f"— key: {self._server.api_key[:8]}…")

    def _copy_key(self):
        QApplication.clipboard().setText(self._server.api_key)

    def _regen_key(self):
        new_key = self._server.regenerate_key()
        self.key_edit.setText(new_key)
        self._update_example()
        self._append_log(f"API Key regenerada: {new_key[:8]}…")

    @Slot(str)
    def _append_log(self, line: str):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_edit.appendPlainText(f"[{ts}]  {line}")
        # mantener máximo 200 líneas
        doc = self.log_edit.document()
        while doc.blockCount() > 200:
            cursor = self.log_edit.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.select(cursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()


    def set_flows_getter(self, getter):
        self._server.flows_getter = getter
