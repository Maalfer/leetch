"""Pestaña Intercept para Leech.

Permite pausar peticiones HTTP/HTTPS en vuelo, editarlas y decidir
Forward (reenviar al servidor, con posibles modificaciones) o Drop (descartar).
"""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QPlainTextEdit,
)

from proxy.flow import PendingRequest
from ui.style import MONO, decode


class InterceptBridge(QObject):
    pending_received = Signal(object)   # PendingRequest (emitido desde hilo proxy)


class InterceptTab(QWidget):
    """Panel de interceptación: muestra una petición a la vez y gestiona la cola."""

    def __init__(self):
        super().__init__()
        self._queue: list[PendingRequest] = []
        self._current: PendingRequest | None = None
        self._build_ui()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # Fila de controles
        top = QHBoxLayout()
        top.setSpacing(8)

        self.toggle_btn = QPushButton("Intercept: OFF")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setObjectName("interceptBtn")
        self.toggle_btn.setFixedWidth(168)
        self.toggle_btn.setToolTip(
            "Activa/desactiva la interceptación de peticiones en vuelo")
        self.toggle_btn.toggled.connect(self._on_toggle)
        top.addWidget(self.toggle_btn)

        self.forward_btn = QPushButton("Forward")
        self.forward_btn.setObjectName("primaryButton")
        self.forward_btn.setEnabled(False)
        self.forward_btn.setToolTip(
            "Reenvía la petición al servidor (puedes editarla antes)  [Ctrl+F]")
        self.forward_btn.setShortcut("Ctrl+F")
        self.forward_btn.clicked.connect(self._forward)
        top.addWidget(self.forward_btn)

        self.drop_btn = QPushButton("Drop")
        self.drop_btn.setEnabled(False)
        self.drop_btn.setToolTip("Descarta la petición — no se envía al servidor")
        self.drop_btn.clicked.connect(self._drop)
        top.addWidget(self.drop_btn)

        top.addStretch()

        self.queue_label = QLabel("")
        self.queue_label.setObjectName("paneCaption")
        top.addWidget(self.queue_label)

        root.addLayout(top)

        # Línea de estado
        self.info_label = QLabel(
            "Intercept desactivado — activa el toggle para capturar peticiones en vuelo.")
        self.info_label.setObjectName("paneCaption")
        self.info_label.setWordWrap(True)
        root.addWidget(self.info_label)

        cap = QLabel("Petición interceptada")
        cap.setObjectName("paneCaption")
        root.addWidget(cap)

        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(MONO)
        self.request_edit.setPlaceholderText(
            "Aquí aparecerá la siguiente petición interceptada.\n"
            "Puedes editarla antes de hacer Forward.")
        self.request_edit.setEnabled(False)
        root.addWidget(self.request_edit, 1)

    # ------------------------------------------------------------------ #
    # Toggle
    # ------------------------------------------------------------------ #
    def _on_toggle(self, checked: bool):
        self.toggle_btn.setText("Intercept: ON" if checked else "Intercept: OFF")
        if not checked:
            # Liberar cola y petición actual para no dejar el navegador colgado
            for p in self._queue:
                p.forward()
            self._queue.clear()
            if self._current:
                raw_text = self.request_edit.toPlainText()
                raw_text = raw_text.replace("\r\n", "\n").replace("\n", "\r\n")
                self._current.forward(raw_text.encode("utf-8", "replace") or None)
                self._current = None
            self._clear_editor()
        else:
            self.info_label.setText(
                "Intercept activado — esperando la siguiente petición…")

    # ------------------------------------------------------------------ #
    # Slots y lógica de cola
    # ------------------------------------------------------------------ #
    @Slot(object)
    def on_pending(self, pending: PendingRequest):
        if self._current is None:
            self._show(pending)
        else:
            self._queue.append(pending)
            self._update_queue_label()

    def _show(self, pending: PendingRequest):
        self._current = pending
        self.request_edit.setEnabled(True)
        self.forward_btn.setEnabled(True)
        self.drop_btn.setEnabled(True)
        self.request_edit.setPlainText(decode(pending.raw))
        self.info_label.setText(
            f"Detenida  —  {pending.scheme.upper()}  {pending.host}:{pending.port}")
        self._update_queue_label()

    def _forward(self):
        if self._current is None:
            return
        raw_text = self.request_edit.toPlainText()
        raw_text = raw_text.replace("\r\n", "\n").replace("\n", "\r\n")
        self._current.forward(raw_text.encode("utf-8", "replace"))
        self._current = None
        self._next()

    def _drop(self):
        if self._current is None:
            return
        self._current.drop()
        self._current = None
        self._next()

    def _next(self):
        if self._queue:
            self._show(self._queue.pop(0))
        else:
            self._clear_editor()

    def _clear_editor(self):
        self.request_edit.setEnabled(False)
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        self.request_edit.clear()
        self.info_label.setText(
            "Intercept activado — esperando la siguiente petición…"
            if self.toggle_btn.isChecked()
            else "Intercept desactivado — activa el toggle para capturar peticiones en vuelo."
        )
        self._update_queue_label()

    def _update_queue_label(self):
        n = len(self._queue)
        self.queue_label.setText(
            f"{n} petición{'es' if n != 1 else ''} en cola" if n else "")

    # ------------------------------------------------------------------ #
    # API pública
    # ------------------------------------------------------------------ #
    @property
    def is_enabled(self) -> bool:
        return self.toggle_btn.isChecked()
