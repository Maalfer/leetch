"""Pestaña del Repeater: editor de peticiones HTTP crudas con respuesta en vivo."""
from __future__ import annotations

import threading
import time

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QAction, QTextDocument, QTextCursor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QPlainTextEdit, QLineEdit,
    QMessageBox, QMenu,
)

from net.http_client import send_raw_request
from net import http_message as hm
from ui.style import MONO, decode, decode_http
from ui.highlighter import HTTPHighlighter


class RepeaterWorker(QObject):
    finished = Signal(object, bytes, float)   # (tab, respuesta, segundos)
    failed = Signal(object, str)              # (tab, mensaje de error)


class RepeaterTab(QWidget):
    send_to_tool = Signal(str, str, int, bool, bytes)  # (tool, host, port, use_tls, raw)

    def __init__(self, worker: RepeaterWorker, host="", port=80, use_tls=False,
                 raw=b""):
        super().__init__()
        self.worker = worker
        self._host = host
        self._port = port
        self._use_tls = use_tls

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Fila superior: búsqueda | TLS | Enviar
        target_row = QHBoxLayout()
        target_row.setSpacing(8)

        target_row.addWidget(QLabel("Buscar:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Buscar en la petición…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setAccessibleName("Buscar en la petición")
        self.search_edit.setToolTip(
            "Busca texto dentro de la petición (Enter = siguiente)"
        )
        self.search_edit.returnPressed.connect(self._find_next)
        target_row.addWidget(self.search_edit, 2)

        prev_btn = QPushButton("↑")
        prev_btn.setObjectName("searchNavBtn")
        prev_btn.setFixedSize(26, 26)
        prev_btn.setCursor(Qt.PointingHandCursor)
        prev_btn.setToolTip("Coincidencia anterior")
        prev_btn.clicked.connect(self._find_prev)
        target_row.addWidget(prev_btn)

        next_btn = QPushButton("↓")
        next_btn.setObjectName("searchNavBtn")
        next_btn.setFixedSize(26, 26)
        next_btn.setCursor(Qt.PointingHandCursor)
        next_btn.setToolTip("Siguiente coincidencia")
        next_btn.clicked.connect(self._find_next)
        target_row.addWidget(next_btn)

        target_row.addStretch()

        self.send_btn = QPushButton("Enviar")
        self.send_btn.setObjectName("primaryButton")
        self.send_btn.setCursor(Qt.PointingHandCursor)
        self.send_btn.setAccessibleName("Enviar petición")
        self.send_btn.setToolTip("Envía la petición cruda al destino (Ctrl+Intro)")
        self.send_btn.setShortcut("Ctrl+Return")
        self.send_btn.clicked.connect(self.send)
        target_row.addWidget(self.send_btn)

        layout.addLayout(target_row)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(8)

        req_box = QWidget()
        req_layout = QVBoxLayout(req_box)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(6)
        req_caption = QLabel("Petición")
        req_caption.setObjectName("paneCaption")
        req_layout.addWidget(req_caption)
        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(MONO)
        self.request_edit.setPlainText(decode(raw))
        self.request_edit.setAccessibleName("Petición HTTP cruda")
        self.request_edit.setToolTip("Edita aquí la petición HTTP cruda antes de enviarla")
        self.request_edit.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_edit.customContextMenuRequested.connect(self._show_request_menu)
        HTTPHighlighter(self.request_edit.document())
        req_layout.addWidget(self.request_edit)
        splitter.addWidget(req_box)

        resp_box = QWidget()
        resp_layout = QVBoxLayout(resp_box)
        resp_layout.setContentsMargins(0, 0, 0, 0)
        resp_layout.setSpacing(6)
        self.resp_label = QLabel("Respuesta")
        self.resp_label.setObjectName("paneCaption")
        resp_layout.addWidget(self.resp_label)
        self.response_view = QPlainTextEdit()
        self.response_view.setFont(MONO)
        self.response_view.setReadOnly(True)
        self.response_view.setAccessibleName("Respuesta HTTP")
        self.response_view.setToolTip("Respuesta cruda recibida del destino")
        HTTPHighlighter(self.response_view.document())
        resp_layout.addWidget(self.response_view)
        splitter.addWidget(resp_box)

        splitter.setSizes([500, 500])
        layout.addWidget(splitter)

        self.setTabOrder(self.search_edit, self.send_btn)
        self.setTabOrder(self.send_btn, self.request_edit)
        self.setTabOrder(self.request_edit, self.response_view)

    def _show_request_menu(self, pos):
        menu = self.request_edit.createStandardContextMenu()
        menu.addSeparator()
        fuzzer_menu = QMenu("Enviar a Tools ▶", menu)
        for tool, label in [("fuzzing", "Fuzzing"), ("race", "Race Conditions"), ("jwt", "JWT Auditor")]:
            act = QAction(label, fuzzer_menu)
            act.triggered.connect(lambda checked=False, t=tool: self._emit_send_to(t))
            fuzzer_menu.addAction(act)
        menu.addMenu(fuzzer_menu)
        menu.exec(self.request_edit.viewport().mapToGlobal(pos))

    def _parse_target(self) -> tuple[str, int, bool]:
        """Extrae host, puerto y TLS del header Host: de la petición actual."""
        raw = self.request_edit.toPlainText().encode("utf-8", "replace")
        headers = hm.parse_headers(raw)
        host_val = headers.get("host", self._host).strip()
        if ":" in host_val:
            h, _, p = host_val.rpartition(":")
            try:
                port = int(p)
                return h.strip(), port, port in (443, 8443)
            except ValueError:
                pass
        port = self._port if self._port > 0 else 80
        return host_val, port, port in (443, 8443) or self._use_tls

    def _find_next(self):
        term = self.search_edit.text()
        if not term:
            return
        if not self.request_edit.find(term):
            cur = self.request_edit.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.Start)
            self.request_edit.setTextCursor(cur)
            self.request_edit.find(term)

    def _find_prev(self):
        term = self.search_edit.text()
        if not term:
            return
        if not self.request_edit.find(term, QTextDocument.FindFlag.FindBackward):
            cur = self.request_edit.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            self.request_edit.setTextCursor(cur)
            self.request_edit.find(term, QTextDocument.FindFlag.FindBackward)

    def _emit_send_to(self, tool: str):
        raw_text = self.request_edit.toPlainText()
        raw = raw_text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace")
        host, port, use_tls = self._parse_target()
        self.send_to_tool.emit(tool, host, port, use_tls, raw)

    def send(self):
        raw_text = self.request_edit.toPlainText()
        raw_text = raw_text.replace("\r\n", "\n").replace("\n", "\r\n")
        raw = raw_text.encode("utf-8", "replace")
        host, port, use_tls = self._parse_target()
        if not host:
            QMessageBox.warning(self, "Falta el host",
                                "La petición debe incluir un header Host:.")
            return

        self.send_btn.setEnabled(False)
        self.resp_label.setText("Respuesta — enviando…")

        def run():
            start = time.time()
            try:
                resp = send_raw_request(raw, host, port, use_tls)
                self.worker.finished.emit(self, resp, time.time() - start)
            except Exception as exc:  # noqa: BLE001
                self.worker.failed.emit(self, str(exc))

        threading.Thread(target=run, daemon=True).start()

    @Slot(bytes, float)
    def on_response(self, resp: bytes, elapsed: float):
        self.send_btn.setEnabled(True)
        status = hm.status_code(resp)
        self.resp_label.setText(
            f"Respuesta — {status}  ·  {len(resp)} bytes  ·  {elapsed*1000:.0f} ms"
        )
        self.response_view.setPlainText(decode_http(resp))

    @Slot(str)
    def on_error(self, message: str):
        self.send_btn.setEnabled(True)
        self.resp_label.setText("Respuesta — error")
        self.response_view.setPlainText(f"[Error de conexión]\n{message}")
