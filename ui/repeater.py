"""Pestaña del Repeater: editor de peticiones HTTP crudas con respuesta en vivo."""
from __future__ import annotations

import threading
import time

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QPlainTextEdit, QCheckBox, QSpinBox, QLineEdit,
    QMessageBox,
)

from net.http_client import send_raw_request
from net import http_message as hm
from ui.style import MONO, decode


class RepeaterWorker(QObject):
    finished = Signal(object, bytes, float)   # (tab, respuesta, segundos)
    failed = Signal(object, str)              # (tab, mensaje de error)


class RepeaterTab(QWidget):
    def __init__(self, worker: RepeaterWorker, host="", port=80, use_tls=False,
                 raw=b""):
        super().__init__()
        self.worker = worker

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Fila de destino
        target_row = QHBoxLayout()
        target_row.setSpacing(8)
        target_row.addWidget(QLabel("Host:"))
        self.host_edit = QLineEdit(host)
        self.host_edit.setAccessibleName("Host de destino")
        self.host_edit.setToolTip("Host o dirección del servidor de destino")
        target_row.addWidget(self.host_edit, 3)
        target_row.addWidget(QLabel("Puerto:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(port)
        self.port_spin.setAccessibleName("Puerto de destino")
        self.port_spin.setToolTip("Puerto del servidor de destino (1-65535)")
        target_row.addWidget(self.port_spin)
        self.tls_check = QCheckBox("HTTPS/TLS")
        self.tls_check.setChecked(use_tls)
        self.tls_check.setAccessibleName("Usar HTTPS/TLS")
        self.tls_check.setToolTip("Marca para enviar la petición cifrada por TLS (HTTPS)")
        target_row.addWidget(self.tls_check)
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
        resp_layout.addWidget(self.response_view)
        splitter.addWidget(resp_box)

        splitter.setSizes([500, 500])
        layout.addWidget(splitter)

        self.setTabOrder(self.host_edit, self.port_spin)
        self.setTabOrder(self.port_spin, self.tls_check)
        self.setTabOrder(self.tls_check, self.send_btn)
        self.setTabOrder(self.send_btn, self.request_edit)
        self.setTabOrder(self.request_edit, self.response_view)

    def send(self):
        raw_text = self.request_edit.toPlainText()
        raw_text = raw_text.replace("\r\n", "\n").replace("\n", "\r\n")
        raw = raw_text.encode("utf-8", "replace")
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        use_tls = self.tls_check.isChecked()
        if not host:
            QMessageBox.warning(self, "Falta el host", "Indica el host de destino.")
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
        self.response_view.setPlainText(decode(resp))

    @Slot(str)
    def on_error(self, message: str):
        self.send_btn.setEnabled(True)
        self.resp_label.setText("Respuesta — error")
        self.response_view.setPlainText(f"[Error de conexión]\n{message}")
