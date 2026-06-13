"""Pestaña Fuzzer para MiniBurp.

Permite marcar una región de la petición con §marcador§, cargar una wordlist
y lanzar un ataque de fuzzing/bruteforce. Muestra los resultados en una tabla
con soporte de filtros por código de estado y longitud.
"""
from __future__ import annotations

import threading
import time

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QPlainTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QLineEdit, QSpinBox, QCheckBox,
    QFileDialog, QMessageBox, QFrame, QProgressBar,
)

from net.http_client import send_raw_request
from ui.style import MONO, TEXT_DIM

MARKER = "§"

_GREEN = "#5fd38a"
_CYAN = "#4fc3d6"
_AMBER = "#ffb454"
_RED = "#ff6b6b"


def _status_color(code: str) -> QColor | None:
    s = (code or "").strip()
    if not s[:1].isdigit():
        return None
    c = s[0]
    if c == "2":
        return QColor(_GREEN)
    if c == "3":
        return QColor(_CYAN)
    if c == "4":
        return QColor(_AMBER)
    if c == "5":
        return QColor(_RED)
    return QColor(TEXT_DIM)


class FuzzWorker(QObject):
    result = Signal(int, str, str, int, float)   # (index, payload, status, length, ms)
    finished = Signal()
    progress = Signal(int, int)                   # (done, total)


class FuzzerTab(QWidget):
    """Pestaña completa del Fuzzer."""

    def __init__(self):
        super().__init__()
        self._running = False
        self._thread: threading.Thread | None = None
        self._worker = FuzzWorker()
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_finished)
        self._worker.progress.connect(self._on_progress)
        self._results: list[dict] = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # Fila superior: host / puerto / TLS / controles
        top = QHBoxLayout()
        top.setSpacing(8)

        top.addWidget(QLabel("Host:"))
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("ejemplo.com")
        self.host_edit.setToolTip("Host de destino")
        self.host_edit.setAccessibleName("Host de destino del fuzzer")
        top.addWidget(self.host_edit, 3)

        top.addWidget(QLabel("Puerto:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(80)
        self.port_spin.setToolTip("Puerto de destino")
        self.port_spin.setAccessibleName("Puerto de destino del fuzzer")
        top.addWidget(self.port_spin)

        self.tls_check = QCheckBox("HTTPS")
        self.tls_check.setToolTip("Usa TLS/HTTPS")
        self.tls_check.setAccessibleName("Usar HTTPS en el fuzzer")
        self.tls_check.toggled.connect(
            lambda on: self.port_spin.setValue(443 if on else 80))
        top.addWidget(self.tls_check)

        top.addWidget(QLabel("Hilos:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        self.threads_spin.setToolTip("Peticiones simultáneas (1–50)")
        self.threads_spin.setAccessibleName("Número de hilos concurrentes")
        top.addWidget(self.threads_spin)

        self.start_btn = QPushButton("▶  Iniciar")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.setToolTip("Lanza el ataque de fuzzing")
        self.start_btn.setAccessibleName("Iniciar o detener el ataque de fuzzing")
        self.start_btn.clicked.connect(self.toggle_attack)
        top.addWidget(self.start_btn)

        self.clear_btn = QPushButton("Limpiar")
        self.clear_btn.setToolTip("Borra los resultados")
        self.clear_btn.setAccessibleName("Limpiar resultados del fuzzer")
        self.clear_btn.clicked.connect(self._clear_results)
        top.addWidget(self.clear_btn)

        root.addLayout(top)

        # Barra de progreso
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v / %m  (%p%)")
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setAccessibleName("Progreso del ataque de fuzzing")
        root.addWidget(self.progress_bar)

        # Splitter: petición | resultados
        main_split = QSplitter(Qt.Horizontal)
        main_split.setHandleWidth(8)

        # Panel izquierdo: petición + wordlist
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        req_label = QLabel("Petición  —  marca la zona a fuzzear con  §…§")
        req_label.setObjectName("paneCaption")
        left_layout.addWidget(req_label)

        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(MONO)
        self.request_edit.setPlaceholderText(
            "GET /login?user=§admin§ HTTP/1.1\r\nHost: ejemplo.com\r\n\r\n")
        self.request_edit.setToolTip(
            "Escribe la petición HTTP. Rodea el valor a fuzzear con § … §")
        self.request_edit.setAccessibleName("Plantilla de petición HTTP con marcadores")
        left_layout.addWidget(self.request_edit, 3)

        wl_caption = QLabel("Wordlist")
        wl_caption.setObjectName("paneCaption")
        left_layout.addWidget(wl_caption)

        wl_row = QHBoxLayout()
        self.wl_path_edit = QLineEdit()
        self.wl_path_edit.setReadOnly(True)
        self.wl_path_edit.setPlaceholderText("Sin wordlist cargada")
        self.wl_path_edit.setToolTip("Ruta del archivo de wordlist")
        self.wl_path_edit.setAccessibleName("Ruta del archivo wordlist")
        wl_row.addWidget(self.wl_path_edit)
        self.wl_btn = QPushButton("Cargar…")
        self.wl_btn.setToolTip("Selecciona un archivo de wordlist (una palabra por línea)")
        self.wl_btn.setAccessibleName("Cargar archivo wordlist")
        self.wl_btn.clicked.connect(self._load_wordlist)
        wl_row.addWidget(self.wl_btn)
        left_layout.addLayout(wl_row)

        self.wl_count_label = QLabel("0 entradas cargadas")
        self.wl_count_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        left_layout.addWidget(self.wl_count_label)

        self._wordlist: list[str] = []

        main_split.addWidget(left)

        # Panel derecho: filtros + tabla de resultados
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)

        filter_frame = QFrame()
        filter_frame.setObjectName("controlBar")
        filter_row = QHBoxLayout(filter_frame)
        filter_row.setContentsMargins(8, 6, 8, 6)
        filter_row.setSpacing(8)

        filter_row.addWidget(QLabel("Filtros:"))

        filter_row.addWidget(QLabel("Código:"))
        self.filter_code = QLineEdit()
        self.filter_code.setPlaceholderText("200,301…  o  !404")
        self.filter_code.setMaximumWidth(130)
        self.filter_code.setToolTip(
            "Muestra solo estos códigos (200,301) o excluye con ! (!404)")
        self.filter_code.setAccessibleName("Filtro por código de estado HTTP")
        self.filter_code.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.filter_code)

        filter_row.addWidget(QLabel("Long. ≠"))
        self.filter_len = QLineEdit()
        self.filter_len.setPlaceholderText("excluir bytes")
        self.filter_len.setMaximumWidth(110)
        self.filter_len.setToolTip("Oculta respuestas con exactamente este número de bytes")
        self.filter_len.setAccessibleName("Filtro por longitud de respuesta a excluir")
        self.filter_len.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.filter_len)

        filter_row.addWidget(QLabel("Texto:"))
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText("contiene…")
        self.filter_text.setMaximumWidth(130)
        self.filter_text.setToolTip("Muestra solo resultados cuyo payload contiene este texto")
        self.filter_text.setAccessibleName("Filtro por texto en payload")
        self.filter_text.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.filter_text)

        filter_row.addStretch()
        self.result_count_label = QLabel("0 resultados")
        self.result_count_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        filter_row.addWidget(self.result_count_label)

        right_layout.addWidget(filter_frame)

        self.result_table = QTableWidget(0, 5)
        self.result_table.setHorizontalHeaderLabels(
            ["#", "Payload", "Código", "Longitud", "ms"])
        self.result_table.setAccessibleName("Tabla de resultados del fuzzer")
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.result_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setShowGrid(False)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.verticalHeader().setDefaultSectionSize(26)
        rh = self.result_table.horizontalHeader()
        rh.setSectionResizeMode(1, QHeaderView.Stretch)
        rh.setHighlightSections(False)
        self.result_table.setColumnWidth(0, 50)
        self.result_table.setColumnWidth(2, 70)
        self.result_table.setColumnWidth(3, 90)
        self.result_table.setColumnWidth(4, 70)
        right_layout.addWidget(self.result_table)

        main_split.addWidget(right)
        main_split.setSizes([420, 700])

        root.addWidget(main_split, 1)

    # ------------------------------------------------------------------ #
    # Wordlist
    # ------------------------------------------------------------------ #
    def _load_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Cargar wordlist", "", "Texto (*.txt);;Todos (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = [l.rstrip("\r\n") for l in f if l.strip()]
        except Exception as exc:
            QMessageBox.critical(self, "Error al cargar", str(exc))
            return
        self._wordlist = lines
        self.wl_path_edit.setText(path)
        self.wl_count_label.setText(f"{len(lines):,} entradas cargadas")

    # ------------------------------------------------------------------ #
    # Ataque
    # ------------------------------------------------------------------ #
    def toggle_attack(self):
        if self._running:
            self._running = False
            self.start_btn.setText("▶  Iniciar")
            self.start_btn.setObjectName("primaryButton")
            return

        template = self.request_edit.toPlainText()
        if template.count(MARKER) < 2:
            QMessageBox.warning(
                self, "Marcador faltante",
                f"Rodea la zona a fuzzear con {MARKER}…{MARKER}\n"
                f"Ejemplo:  GET /user/§admin§ HTTP/1.1")
            return
        if not self._wordlist:
            QMessageBox.warning(self, "Wordlist vacía", "Carga una wordlist primero.")
            return
        host = self.host_edit.text().strip()
        if not host:
            QMessageBox.warning(self, "Host vacío", "Indica el host de destino.")
            return

        self._running = True
        self.start_btn.setText("■  Detener")
        self.progress_bar.setMaximum(len(self._wordlist))
        self.progress_bar.setValue(0)

        port = self.port_spin.value()
        use_tls = self.tls_check.isChecked()
        n_threads = self.threads_spin.value()
        wordlist = list(self._wordlist)

        first = template.index(MARKER)
        second = template.index(MARKER, first + 1)
        prefix = template[:first]
        suffix = template[second + 1:]

        self._thread = threading.Thread(
            target=self._run_attack,
            args=(prefix, suffix, wordlist, host, port, use_tls, n_threads),
            daemon=True,
        )
        self._thread.start()

    def _run_attack(self, prefix: str, suffix: str, wordlist: list[str],
                    host: str, port: int, use_tls: bool, n_threads: int):
        sem = threading.Semaphore(n_threads)
        lock = threading.Lock()
        done_count = [0]
        total = len(wordlist)

        def send_one(idx: int, payload: str):
            if not self._running:
                return
            raw_text = prefix + payload + suffix
            raw_text = raw_text.replace("\r\n", "\n").replace("\n", "\r\n")
            raw = raw_text.encode("utf-8", "replace")
            t0 = time.perf_counter()
            try:
                resp = send_raw_request(raw, host, port, use_tls)
                elapsed = (time.perf_counter() - t0) * 1000
                first_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                parts = first_line.split(" ", 2)
                status = parts[1] if len(parts) >= 2 else "???"
                length = len(resp)
            except Exception:
                elapsed = (time.perf_counter() - t0) * 1000
                status = "ERR"
                length = 0
            finally:
                sem.release()

            self._worker.result.emit(idx, payload, status, length, elapsed)
            with lock:
                done_count[0] += 1
                self._worker.progress.emit(done_count[0], total)

        threads = []
        for idx, payload in enumerate(wordlist):
            if not self._running:
                break
            sem.acquire()
            t = threading.Thread(target=send_one, args=(idx, payload), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self._worker.finished.emit()

    # ------------------------------------------------------------------ #
    # Slots
    # ------------------------------------------------------------------ #
    @Slot(int, str, str, int, float)
    def _on_result(self, idx: int, payload: str, status: str, length: int, ms: float):
        entry = {"idx": idx, "payload": payload, "status": status,
                 "length": length, "ms": ms}
        self._results.append(entry)
        if self._matches_filters(entry):
            self._add_row(entry)

    @Slot()
    def _on_finished(self):
        self._running = False
        self.start_btn.setText("▶  Iniciar")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.style().unpolish(self.start_btn)
        self.start_btn.style().polish(self.start_btn)

    @Slot(int, int)
    def _on_progress(self, done: int, total: int):
        self.progress_bar.setValue(done)

    # ------------------------------------------------------------------ #
    # Tabla y filtros
    # ------------------------------------------------------------------ #
    def _add_row(self, entry: dict):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        cells = [
            str(entry["idx"] + 1),
            entry["payload"],
            entry["status"],
            str(entry["length"]),
            f"{entry['ms']:.0f}",
        ]
        for col, val in enumerate(cells):
            item = QTableWidgetItem(val)
            item.setData(Qt.UserRole, entry)
            if col == 2:
                color = _status_color(entry["status"])
                if color:
                    item.setForeground(color)
            self.result_table.setItem(row, col, item)
        self.result_count_label.setText(
            f"{self.result_table.rowCount()} resultados")

    def _matches_filters(self, entry: dict) -> bool:
        code_filter = self.filter_code.text().strip()
        if code_filter:
            status = entry["status"]
            if code_filter.startswith("!"):
                excluded = [c.strip() for c in code_filter[1:].split(",")]
                if status in excluded:
                    return False
            else:
                allowed = [c.strip() for c in code_filter.split(",")]
                if status not in allowed:
                    return False

        len_filter = self.filter_len.text().strip()
        if len_filter:
            try:
                if entry["length"] == int(len_filter):
                    return False
            except ValueError:
                pass

        text_filter = self.filter_text.text().strip()
        if text_filter and text_filter.lower() not in entry["payload"].lower():
            return False

        return True

    def _apply_filters(self):
        self.result_table.setRowCount(0)
        for entry in self._results:
            if self._matches_filters(entry):
                self._add_row(entry)

    def _clear_results(self):
        self._results.clear()
        self.result_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.result_count_label.setText("0 resultados")

    # ------------------------------------------------------------------ #
    # API pública
    # ------------------------------------------------------------------ #
    def load_from_flow(self, host: str, port: int, use_tls: bool, raw: bytes):
        """Rellena el panel de petición desde un Flow del History."""
        self.host_edit.setText(host)
        # tls_check.toggled auto-ajusta el puerto — ponemos el check primero
        # y luego sobreescribimos con el puerto real del flow.
        self.tls_check.setChecked(use_tls)
        self.port_spin.setValue(port)
        self.request_edit.setPlainText(raw.decode("utf-8", "replace"))
