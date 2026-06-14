"""Módulo Fuzzer: contenedor con herramientas Fuzzing, Race Conditions y JWT."""
from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import json
import re
import threading
import time

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QPlainTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QLineEdit, QSpinBox,
    QFileDialog, QMessageBox, QFrame, QProgressBar, QComboBox, QMenu,
    QTabBar,
)

from net.http_client import send_raw_request
from net import http_message as hm
from ui.style import MONO, TEXT_DIM, decode, decode_http
from ui.highlighter import HTTPHighlighter, JSONHighlighter

MARKER = "§"

_GREEN = "#5fd38a"
_CYAN  = "#4fc3d6"
_AMBER = "#ffb454"
_RED   = "#ff6b6b"


class _SortItem(QTableWidgetItem):
    """Item que ordena numéricamente cuando el texto lo permite."""
    def __lt__(self, other: QTableWidgetItem) -> bool:
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return self.text() < other.text()


def _status_color(code: str) -> QColor | None:
    s = (code or "").strip()
    if not s[:1].isdigit():
        return None
    c = s[0]
    if c == "2": return QColor(_GREEN)
    if c == "3": return QColor(_CYAN)
    if c == "4": return QColor(_AMBER)
    if c == "5": return QColor(_RED)
    return QColor(TEXT_DIM)


def _parse_target(raw_text: str, fallback_host: str = "", fallback_port: int = 80,
                  fallback_tls: bool = False) -> tuple[str, int, bool]:
    """Extrae host, puerto y TLS del header Host: del texto de petición."""
    raw = raw_text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace")
    headers = hm.parse_headers(raw)
    host_val = headers.get("host", fallback_host).strip()
    if ":" in host_val:
        h, _, p = host_val.rpartition(":")
        try:
            port = int(p)
            return h.strip(), port, port in (443, 8443)
        except ValueError:
            pass
    port = 443 if fallback_tls else fallback_port
    return host_val, port, port in (443, 8443) or fallback_tls


# ──────────────────────────────────────── helpers marcadores ──
def _parse_markers(template: str) -> list[tuple[int, int]]:
    """Devuelve lista de (start, end) para cada par §…§ en el template."""
    positions, i = [], 0
    while True:
        start = template.find(MARKER, i)
        if start == -1:
            break
        end = template.find(MARKER, start + 1)
        if end == -1:
            break
        positions.append((start, end))
        i = end + 1
    return positions


def _substitute(template: str, markers: list[tuple[int, int]], payloads: list[str]) -> str:
    """Sustituye cada par §…§ por el payload correspondiente."""
    parts, prev = [], 0
    for (start, end), payload in zip(markers, payloads):
        parts.append(template[prev:start])
        parts.append(payload)
        prev = end + 1
    parts.append(template[prev:])
    return "".join(parts)


# ─────────────────────────────────────────────── helpers JWT ──
def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _verify_hs(hdr_b64: str, pay_b64: str, sig_b64: str, secret: str, alg: str) -> bool:
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if fn is None:
        return False
    msg = f"{hdr_b64}.{pay_b64}".encode()
    try:
        sig = _b64url_decode(sig_b64)
    except Exception:
        return False
    expected = hmac.new(secret.encode("utf-8", "replace"), msg, fn).digest()
    return hmac.compare_digest(sig, expected)


def _extract_jwt(text: str) -> str | None:
    m = re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', text)
    return m.group(0) if m else None


# ══════════════════════════════════════════════════════════════
# Fuzzing
# ══════════════════════════════════════════════════════════════
class _WLRow(QWidget):
    """Fila de wordlist para una posición de marcador."""
    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        self._lbl = QLabel(label)
        self._lbl.setMinimumWidth(72)
        lay.addWidget(self._lbl)
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText("Sin wordlist")
        lay.addWidget(self.path_edit, 1)
        btn = QPushButton("Cargar…")
        btn.setMaximumWidth(70)
        btn.clicked.connect(self._load)
        lay.addWidget(btn)
        self.count_lbl = QLabel("0")
        self.count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        self.count_lbl.setMinimumWidth(70)
        lay.addWidget(self.count_lbl)
        self.words: list[str] = []

    def set_label(self, text: str):
        self._lbl.setText(text)

    def _load(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Cargar wordlist", "", "Texto (*.txt);;Todos (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = [l.rstrip("\r\n") for l in f if l.strip()]
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return
        self.words = lines
        self.path_edit.setText(path)
        self.count_lbl.setText(f"{len(lines):,} entradas")


class _FuzzWorker(QObject):
    result   = Signal(int, str, str, int, float, bytes, bytes)  # idx, payload, status, length, ms, req, resp
    finished = Signal()
    progress = Signal(int, int)


class FuzzingTab(QWidget):
    def __init__(self, use_tls: bool = False, raw: bytes = b""):
        super().__init__()
        self._running = False
        self._thread: threading.Thread | None = None
        self._worker = _FuzzWorker()
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_finished)
        self._worker.progress.connect(self._on_progress)
        self._results: list[dict] = []
        self._wl_rows: list[_WLRow] = []
        self._fallback_tls = use_tls
        self._build_ui()
        if raw:
            self.request_edit.setPlainText(decode(raw))

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(QLabel("Hilos:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        top.addWidget(self.threads_spin)
        top.addWidget(QLabel("Ataque:"))
        self.attack_combo = QComboBox()
        self.attack_combo.addItems(["Sniper", "Pitchfork", "Cluster Bomb"])
        self.attack_combo.setToolTip(
            "Sniper: un marcador, una wordlist\n"
            "Pitchfork: N marcadores, N wordlists en paralelo (zip)\n"
            "Cluster Bomb: N marcadores, producto cartesiano de N wordlists")
        self.attack_combo.currentTextChanged.connect(self._on_attack_type_changed)
        top.addWidget(self.attack_combo)
        top.addStretch()
        self.start_btn = QPushButton("▶  Iniciar")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.clicked.connect(self.toggle_attack)
        top.addWidget(self.start_btn)
        self.clear_btn = QPushButton("Limpiar")
        self.clear_btn.clicked.connect(self._clear_results)
        top.addWidget(self.clear_btn)
        root.addLayout(top)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v / %m  (%p%)")
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        root.addWidget(self.progress_bar)

        main_split = QSplitter(Qt.Horizontal)
        main_split.setHandleWidth(8)

        # Panel izquierdo: petición + wordlist
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)
        lbl = QLabel("Petición  —  marca la zona a fuzzear con  §…§")
        lbl.setObjectName("paneCaption")
        ll.addWidget(lbl)
        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(MONO)
        self.request_edit.setPlaceholderText(
            "GET /login?user=§admin§ HTTP/1.1\r\nHost: ejemplo.com\r\n\r\n")
        self.request_edit.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_edit.customContextMenuRequested.connect(self._show_request_menu)
        self.request_edit.textChanged.connect(self._on_template_changed)
        HTTPHighlighter(self.request_edit.document())
        ll.addWidget(self.request_edit, 3)
        wl_lbl = QLabel("Wordlists")
        wl_lbl.setObjectName("paneCaption")
        ll.addWidget(wl_lbl)
        for i in range(5):
            row = _WLRow(f"Posición {i + 1}:")
            ll.addWidget(row)
            self._wl_rows.append(row)
            row.setVisible(i == 0)
        main_split.addWidget(left)

        # Panel derecho: filtros + tabla + preview req/resp
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)

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
        self.filter_code.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.filter_code)
        filter_row.addWidget(QLabel("Long. ≠"))
        self.filter_len = QLineEdit()
        self.filter_len.setPlaceholderText("excluir bytes")
        self.filter_len.setMaximumWidth(110)
        self.filter_len.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.filter_len)
        filter_row.addWidget(QLabel("Texto:"))
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText("contiene…")
        self.filter_text.setMaximumWidth(130)
        self.filter_text.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.filter_text)
        filter_row.addStretch()
        self.result_count_label = QLabel("0 resultados")
        self.result_count_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        filter_row.addWidget(self.result_count_label)
        rl.addWidget(filter_frame)

        # Splitter vertical: tabla arriba, preview abajo
        vsplit = QSplitter(Qt.Vertical)
        vsplit.setHandleWidth(8)

        self.result_table = QTableWidget(0, 5)
        self.result_table.setHorizontalHeaderLabels(["#", "Payload", "Código", "Longitud", "ms"])
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
        rh.setSortIndicatorShown(True)
        rh.setSectionsClickable(True)
        self.result_table.setColumnWidth(0, 50)
        self.result_table.setColumnWidth(2, 70)
        self.result_table.setColumnWidth(3, 90)
        self.result_table.setColumnWidth(4, 70)
        self.result_table.itemSelectionChanged.connect(self._on_selection)
        vsplit.addWidget(self.result_table)

        # Preview req / resp
        preview = QWidget()
        pl = QVBoxLayout(preview)
        pl.setContentsMargins(0, 4, 0, 0)
        pl.setSpacing(0)
        preview_split = QSplitter(Qt.Horizontal)
        preview_split.setHandleWidth(8)

        req_box = QWidget()
        req_bl = QVBoxLayout(req_box)
        req_bl.setContentsMargins(0, 0, 0, 0)
        req_bl.setSpacing(4)
        req_lbl = QLabel("Petición")
        req_lbl.setObjectName("paneCaption")
        req_bl.addWidget(req_lbl)
        self.req_preview = QPlainTextEdit()
        self.req_preview.setFont(MONO)
        self.req_preview.setReadOnly(True)
        HTTPHighlighter(self.req_preview.document())
        req_bl.addWidget(self.req_preview)
        preview_split.addWidget(req_box)

        resp_box = QWidget()
        resp_bl = QVBoxLayout(resp_box)
        resp_bl.setContentsMargins(0, 0, 0, 0)
        resp_bl.setSpacing(4)
        resp_lbl = QLabel("Respuesta")
        resp_lbl.setObjectName("paneCaption")
        resp_bl.addWidget(resp_lbl)
        self.resp_preview = QPlainTextEdit()
        self.resp_preview.setFont(MONO)
        self.resp_preview.setReadOnly(True)
        HTTPHighlighter(self.resp_preview.document())
        resp_bl.addWidget(self.resp_preview)
        preview_split.addWidget(resp_box)

        pl.addWidget(preview_split)
        vsplit.addWidget(preview)
        vsplit.setSizes([280, 250])

        rl.addWidget(vsplit, 1)
        main_split.addWidget(right)
        main_split.setSizes([380, 720])
        root.addWidget(main_split, 1)

    def _show_request_menu(self, pos):
        menu = self.request_edit.createStandardContextMenu()
        cursor = self.request_edit.textCursor()
        if cursor.hasSelection():
            menu.addSeparator()
            from PySide6.QtGui import QAction as _QAction
            act = _QAction("Añadir Posicionador  §…§", menu)
            act.triggered.connect(self._add_marker)
            menu.addAction(act)
        menu.exec(self.request_edit.viewport().mapToGlobal(pos))

    def _add_marker(self):
        cursor = self.request_edit.textCursor()
        if cursor.hasSelection():
            cursor.insertText(f"§{cursor.selectedText()}§")

    def _refresh_wl_rows(self, n: int):
        n = max(1, min(n, len(self._wl_rows)))
        for i, row in enumerate(self._wl_rows):
            row.setVisible(i < n)

    def _on_attack_type_changed(self, mode: str):
        if mode == "Sniper":
            self._refresh_wl_rows(1)
        else:
            n = max(2, len(_parse_markers(self.request_edit.toPlainText())))
            self._refresh_wl_rows(n)

    def _on_template_changed(self):
        if self.attack_combo.currentText() != "Sniper":
            n = max(2, len(_parse_markers(self.request_edit.toPlainText())))
            self._refresh_wl_rows(n)

    def toggle_attack(self):
        if self._running:
            self._running = False
            self.start_btn.setText("▶  Iniciar")
            return
        template = self.request_edit.toPlainText()
        markers = _parse_markers(template)
        if not markers:
            QMessageBox.warning(self, "Marcador faltante",
                f"Rodea la zona a fuzzear con {MARKER}…{MARKER}")
            return

        mode = self.attack_combo.currentText()

        if mode == "Sniper":
            active_markers = markers[:1]
            wl = self._wl_rows[0].words if self._wl_rows else []
            if not wl:
                QMessageBox.warning(self, "Wordlist vacía", "Carga una wordlist.")
                return
            payload_list = [(w,) for w in wl]

        elif mode == "Pitchfork":
            n = len(markers)
            active_markers = markers
            if len(self._wl_rows) < n or any(not r.words for r in self._wl_rows[:n]):
                QMessageBox.warning(self, "Wordlist vacía",
                    f"Carga una wordlist para cada una de las {n} posiciones.")
                return
            payload_list = list(zip(*[r.words for r in self._wl_rows[:n]]))

        else:  # Cluster Bomb
            n = len(markers)
            active_markers = markers
            if len(self._wl_rows) < n or any(not r.words for r in self._wl_rows[:n]):
                QMessageBox.warning(self, "Wordlist vacía",
                    f"Carga una wordlist para cada una de las {n} posiciones.")
                return
            payload_list = list(itertools.product(*[r.words for r in self._wl_rows[:n]]))
            if len(payload_list) > 100_000:
                from PySide6.QtWidgets import QMessageBox as _MB
                reply = _MB.question(self, "Ataque muy grande",
                    f"Cluster Bomb generará {len(payload_list):,} peticiones. ¿Continuar?",
                    _MB.Yes | _MB.No)
                if reply != _MB.Yes:
                    return

        host, port, use_tls = _parse_target(template, fallback_tls=self._fallback_tls)
        if not host:
            QMessageBox.warning(self, "Host vacío",
                                "La petición debe incluir un header Host:.")
            return

        self._running = True
        self.result_table.setSortingEnabled(False)
        self.start_btn.setText("■  Detener")
        self.progress_bar.setMaximum(len(payload_list))
        self.progress_bar.setValue(0)
        n_threads = self.threads_spin.value()
        self._thread = threading.Thread(
            target=self._run_attack,
            args=(template, active_markers, payload_list, host, port, use_tls, n_threads),
            daemon=True)
        self._thread.start()

    def _run_attack(self, template, markers, payload_list, host, port, use_tls, n_threads):
        sem = threading.Semaphore(n_threads)
        lock = threading.Lock()
        done_count = [0]
        total = len(payload_list)

        def send_one(idx, payloads):
            if not self._running:
                return
            raw_text = _substitute(template, markers, list(payloads))
            raw_text = raw_text.replace("\r\n", "\n").replace("\n", "\r\n")
            raw_req = raw_text.encode("utf-8", "replace")
            t0 = time.perf_counter()
            raw_resp = b""
            try:
                raw_resp = send_raw_request(raw_req, host, port, use_tls)
                elapsed = (time.perf_counter() - t0) * 1000
                first_line = raw_resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                parts = first_line.split(" ", 2)
                status = parts[1] if len(parts) >= 2 else "???"
                length = len(raw_resp)
            except Exception:
                elapsed = (time.perf_counter() - t0) * 1000
                status = "ERR"
                length = 0
            finally:
                sem.release()
            payload_str = " | ".join(payloads) if len(payloads) > 1 else payloads[0]
            self._worker.result.emit(idx, payload_str, status, length, elapsed, raw_req, raw_resp)
            with lock:
                done_count[0] += 1
                self._worker.progress.emit(done_count[0], total)

        threads = []
        for idx, payloads in enumerate(payload_list):
            if not self._running:
                break
            sem.acquire()
            t = threading.Thread(target=send_one, args=(idx, payloads), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        self._worker.finished.emit()

    @Slot(int, str, str, int, float, bytes, bytes)
    def _on_result(self, idx, payload, status, length, ms, raw_req, raw_resp):
        entry = {
            "idx": idx, "payload": payload, "status": status,
            "length": length, "ms": ms,
            "raw_req": raw_req, "raw_resp": raw_resp,
        }
        self._results.append(entry)
        if self._matches_filters(entry):
            self._add_row(entry)

    @Slot()
    def _on_finished(self):
        self._running = False
        self.result_table.setSortingEnabled(True)
        self.start_btn.setText("▶  Iniciar")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.style().unpolish(self.start_btn)
        self.start_btn.style().polish(self.start_btn)

    @Slot(int, int)
    def _on_progress(self, done, total):
        self.progress_bar.setValue(done)

    def _on_selection(self):
        items = self.result_table.selectedItems()
        if not items:
            self.req_preview.clear()
            self.resp_preview.clear()
            return
        entry = items[0].data(Qt.UserRole)
        if not entry:
            return
        self.req_preview.setPlainText(decode(entry.get("raw_req", b"")))
        self.resp_preview.setPlainText(decode_http(entry.get("raw_resp", b"")))

    def _add_row(self, entry):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        for col, val in enumerate([str(entry["idx"] + 1), entry["payload"],
                                    entry["status"], str(entry["length"]), f"{entry['ms']:.0f}"]):
            item = _SortItem(val)
            item.setData(Qt.UserRole, entry)
            if col == 2:
                color = _status_color(entry["status"])
                if color:
                    item.setForeground(color)
            self.result_table.setItem(row, col, item)
        self.result_count_label.setText(f"{self.result_table.rowCount()} resultados")

    def _matches_filters(self, entry):
        code_filter = self.filter_code.text().strip()
        if code_filter:
            status = entry["status"]
            if code_filter.startswith("!"):
                if status in [c.strip() for c in code_filter[1:].split(",")]:
                    return False
            else:
                if status not in [c.strip() for c in code_filter.split(",")]:
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
        self.result_table.setSortingEnabled(False)
        self.result_table.setRowCount(0)
        for entry in self._results:
            if self._matches_filters(entry):
                self._add_row(entry)
        if not self._running:
            self.result_table.setSortingEnabled(True)

    def _clear_results(self):
        self._results.clear()
        self.result_table.setRowCount(0)
        self.req_preview.clear()
        self.resp_preview.clear()
        self.progress_bar.setValue(0)
        self.result_count_label.setText("0 resultados")

    def load_from_flow(self, raw: bytes, use_tls: bool = False):
        self._fallback_tls = use_tls
        self.request_edit.setPlainText(decode(raw))


# ══════════════════════════════════════════════════════════════
# Race Conditions
# ══════════════════════════════════════════════════════════════
class _RaceWorker(QObject):
    result   = Signal(int, str, int, float)
    finished = Signal()


class RaceTab(QWidget):
    def __init__(self, use_tls: bool = False, raw: bytes = b""):
        super().__init__()
        self._running = False
        self._worker = _RaceWorker()
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_finished)
        self._fallback_tls = use_tls
        self._build_ui()
        if raw:
            self.request_edit.setPlainText(decode(raw))

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(QLabel("Peticiones simultáneas:"))
        self.count_spin = QSpinBox()
        self.count_spin.setRange(2, 500)
        self.count_spin.setValue(20)
        self.count_spin.setToolTip("Número de peticiones a lanzar simultáneamente")
        top.addWidget(self.count_spin)
        top.addStretch()
        self.start_btn = QPushButton("▶  Lanzar")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.clicked.connect(self.launch)
        top.addWidget(self.start_btn)
        self.clear_btn = QPushButton("Limpiar")
        self.clear_btn.clicked.connect(self._clear)
        top.addWidget(self.clear_btn)
        root.addLayout(top)

        main_split = QSplitter(Qt.Horizontal)
        main_split.setHandleWidth(8)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)
        lbl = QLabel("Petición a enviar en paralelo")
        lbl.setObjectName("paneCaption")
        ll.addWidget(lbl)
        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(MONO)
        self.request_edit.setPlaceholderText(
            "POST /api/redeem HTTP/1.1\r\nHost: ejemplo.com\r\n\r\n{\"code\":\"GIFT50\"}")
        HTTPHighlighter(self.request_edit.document())
        ll.addWidget(self.request_edit)
        main_split.addWidget(left)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        self.result_lbl = QLabel("Resultados")
        self.result_lbl.setObjectName("paneCaption")
        rl.addWidget(self.result_lbl)
        self.result_table = QTableWidget(0, 4)
        self.result_table.setHorizontalHeaderLabels(["#", "Código", "Longitud", "ms"])
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.result_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setShowGrid(False)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.verticalHeader().setDefaultSectionSize(26)
        rh = self.result_table.horizontalHeader()
        rh.setSectionResizeMode(0, QHeaderView.Stretch)
        rh.setHighlightSections(False)
        self.result_table.setColumnWidth(1, 70)
        self.result_table.setColumnWidth(2, 90)
        self.result_table.setColumnWidth(3, 70)
        rl.addWidget(self.result_table)
        main_split.addWidget(right)
        main_split.setSizes([500, 500])
        root.addWidget(main_split, 1)

    def launch(self):
        if self._running:
            return
        raw_text = self.request_edit.toPlainText()
        if not raw_text.strip():
            QMessageBox.warning(self, "Petición vacía", "Escribe la petición a enviar.")
            return
        host, port, use_tls = _parse_target(raw_text, fallback_tls=self._fallback_tls)
        if not host:
            QMessageBox.warning(self, "Host vacío",
                                "La petición debe incluir un header Host:.")
            return
        count = self.count_spin.value()
        raw = raw_text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace")
        self._running = True
        self.start_btn.setEnabled(False)
        self.result_lbl.setText(f"Lanzando {count} peticiones simultáneas…")
        threading.Thread(
            target=self._run, args=(raw, host, port, use_tls, count), daemon=True
        ).start()

    def _run(self, raw, host, port, use_tls, count):
        start_ev = threading.Event()

        def send_one(idx):
            start_ev.wait()
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
            self._worker.result.emit(idx, status, length, elapsed)

        threads = [threading.Thread(target=send_one, args=(i,), daemon=True)
                   for i in range(count)]
        for t in threads:
            t.start()
        start_ev.set()
        for t in threads:
            t.join()
        self._worker.finished.emit()

    @Slot(int, str, int, float)
    def _on_result(self, idx, status, length, ms):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        for col, val in enumerate([str(idx + 1), status, str(length), f"{ms:.0f}"]):
            item = QTableWidgetItem(val)
            if col == 1:
                color = _status_color(status)
                if color:
                    item.setForeground(color)
            self.result_table.setItem(row, col, item)

    @Slot()
    def _on_finished(self):
        self._running = False
        self.start_btn.setEnabled(True)
        self.result_lbl.setText(f"Resultados — {self.result_table.rowCount()} respuestas")

    def _clear(self):
        self.result_table.setRowCount(0)
        self.result_lbl.setText("Resultados")

    def load_from_flow(self, raw: bytes, use_tls: bool = False):
        self._fallback_tls = use_tls
        self.request_edit.setPlainText(decode(raw))


# ══════════════════════════════════════════════════════════════
# JWT Auditor
# ══════════════════════════════════════════════════════════════
class _JWTWorker(QObject):
    found    = Signal(str)
    progress = Signal(int, int)
    finished = Signal()


class JWTTab(QWidget):
    def __init__(self):
        super().__init__()
        self._running = False
        self._worker = _JWTWorker()
        self._worker.found.connect(self._on_found)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._wordlist: list[str] = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        token_row = QHBoxLayout()
        token_row.setSpacing(8)
        lbl = QLabel("Token JWT:")
        lbl.setObjectName("paneCaption")
        token_row.addWidget(lbl)
        self.token_edit = QLineEdit()
        self.token_edit.setFont(MONO)
        self.token_edit.setPlaceholderText("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…")
        self.token_edit.setAccessibleName("Token JWT a analizar")
        self.token_edit.textChanged.connect(self._decode_token)
        token_row.addWidget(self.token_edit)
        decode_btn = QPushButton("Decodificar")
        decode_btn.clicked.connect(self._decode_token)
        token_row.addWidget(decode_btn)
        root.addLayout(token_row)

        decode_split = QSplitter(Qt.Horizontal)
        decode_split.setHandleWidth(8)

        for attr, title in [("header_view", "Header"), ("payload_view", "Payload"), ("sig_view", "Firma (base64url)")]:
            box = QWidget()
            bl = QVBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(4)
            lbl2 = QLabel(title)
            lbl2.setObjectName("paneCaption")
            bl.addWidget(lbl2)
            view = QPlainTextEdit()
            view.setFont(MONO)
            view.setReadOnly(True)
            if attr != "sig_view":
                JSONHighlighter(view.document())
            bl.addWidget(view)
            setattr(self, attr, view)
            decode_split.addWidget(box)

        decode_split.setSizes([400, 400, 250])
        root.addWidget(decode_split)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setObjectName("controlBar")
        root.addWidget(sep)

        bf_lbl = QLabel("Bruteforce de secreto  —  HS256 / HS384 / HS512")
        bf_lbl.setObjectName("paneCaption")
        root.addWidget(bf_lbl)

        bf_row = QHBoxLayout()
        bf_row.setSpacing(8)
        bf_row.addWidget(QLabel("Algoritmo:"))
        self.alg_combo = QComboBox()
        self.alg_combo.addItems(["Auto", "HS256", "HS384", "HS512"])
        self.alg_combo.setToolTip("Auto detecta el alg del header; o fuerza uno concreto")
        bf_row.addWidget(self.alg_combo)
        bf_row.addWidget(QLabel("Hilos:"))
        self.bf_threads_spin = QSpinBox()
        self.bf_threads_spin.setRange(1, 50)
        self.bf_threads_spin.setValue(10)
        self.bf_threads_spin.setToolTip("Número de hilos paralelos para el bruteforce")
        bf_row.addWidget(self.bf_threads_spin)
        bf_row.addWidget(QLabel("Wordlist:"))
        self.bf_wl_path = QLineEdit()
        self.bf_wl_path.setReadOnly(True)
        self.bf_wl_path.setPlaceholderText("Sin wordlist cargada")
        bf_row.addWidget(self.bf_wl_path, 2)
        load_btn = QPushButton("Cargar…")
        load_btn.clicked.connect(self._load_wordlist)
        bf_row.addWidget(load_btn)
        self.wl_count_lbl = QLabel("0 palabras")
        self.wl_count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        bf_row.addWidget(self.wl_count_lbl)
        self.bf_start_btn = QPushButton("▶  Iniciar BF")
        self.bf_start_btn.setObjectName("primaryButton")
        self.bf_start_btn.clicked.connect(self.toggle_bruteforce)
        bf_row.addWidget(self.bf_start_btn)
        root.addLayout(bf_row)

        self.bf_progress = QProgressBar()
        self.bf_progress.setTextVisible(True)
        self.bf_progress.setFormat("%v / %m  (%p%)")
        self.bf_progress.setValue(0)
        self.bf_progress.setFixedHeight(14)
        root.addWidget(self.bf_progress)

        self.bf_result_lbl = QLabel("")
        self.bf_result_lbl.setStyleSheet(
            f"color: {_GREEN}; font-size: 13px; font-weight: bold;")
        root.addWidget(self.bf_result_lbl)

    def _decode_token(self):
        token = self.token_edit.text().strip()
        parts = token.split(".")
        if len(parts) != 3:
            self.header_view.setPlainText("")
            self.payload_view.setPlainText("")
            self.sig_view.setPlainText("")
            return
        try:
            hdr = json.dumps(
                json.loads(_b64url_decode(parts[0])), indent=2, ensure_ascii=False)
        except Exception:
            hdr = decode(_b64url_decode(parts[0]))
        try:
            pay = json.dumps(
                json.loads(_b64url_decode(parts[1])), indent=2, ensure_ascii=False)
        except Exception:
            pay = decode(_b64url_decode(parts[1]))
        self.header_view.setPlainText(hdr)
        self.payload_view.setPlainText(pay)
        self.sig_view.setPlainText(parts[2])
        try:
            alg = json.loads(_b64url_decode(parts[0])).get("alg", "")
            if alg in ("HS256", "HS384", "HS512"):
                idx = self.alg_combo.findText(alg)
                if idx >= 0:
                    self.alg_combo.setCurrentIndex(idx)
        except Exception:
            pass

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
        self.bf_wl_path.setText(path)
        self.wl_count_lbl.setText(f"{len(lines):,} palabras")

    def toggle_bruteforce(self):
        if self._running:
            self._running = False
            self.bf_start_btn.setText("▶  Iniciar BF")
            return
        token = self.token_edit.text().strip()
        parts = token.split(".")
        if len(parts) != 3:
            QMessageBox.warning(self, "Token no válido",
                "Introduce un token JWT válido primero.")
            return
        if not self._wordlist:
            QMessageBox.warning(self, "Wordlist vacía", "Carga una wordlist primero.")
            return
        sel = self.alg_combo.currentText()
        algs = ["HS256", "HS384", "HS512"] if sel == "Auto" else [sel]
        self._running = True
        self.bf_start_btn.setText("■  Detener")
        self.bf_result_lbl.setText("")
        self.bf_result_lbl.setStyleSheet(
            f"color: {_GREEN}; font-size: 13px; font-weight: bold;")
        self.bf_progress.setMaximum(len(self._wordlist))
        self.bf_progress.setValue(0)
        n_threads = self.bf_threads_spin.value()
        threading.Thread(
            target=self._run_bf,
            args=(parts[0], parts[1], parts[2], list(self._wordlist), algs, n_threads),
            daemon=True,
        ).start()

    def _run_bf(self, hdr_b64, pay_b64, sig_b64, wordlist, algs, n_threads):
        sem = threading.Semaphore(n_threads)
        lock = threading.Lock()
        done_count = [0]
        total = len(wordlist)
        threads = []

        def check(secret):
            try:
                if not self._running:
                    return
                for alg in algs:
                    if _verify_hs(hdr_b64, pay_b64, sig_b64, secret, alg):
                        self._worker.found.emit(secret)
                        self._running = False
                        return
                with lock:
                    done_count[0] += 1
                    self._worker.progress.emit(done_count[0], total)
            finally:
                sem.release()

        for secret in wordlist:
            if not self._running:
                break
            sem.acquire()
            t = threading.Thread(target=check, args=(secret,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
        self._worker.finished.emit()

    @Slot(str)
    def _on_found(self, secret: str):
        self.bf_result_lbl.setText(f"✓  Secreto encontrado: {secret}")

    @Slot(int, int)
    def _on_progress(self, done, total):
        self.bf_progress.setValue(done)

    @Slot()
    def _on_finished(self):
        self._running = False
        self.bf_start_btn.setText("▶  Iniciar BF")
        if not self.bf_result_lbl.text():
            self.bf_result_lbl.setStyleSheet(f"color: {_AMBER}; font-size: 12px;")
            self.bf_result_lbl.setText("Secreto no encontrado con la wordlist dada.")

    def load_from_flow(self, raw: bytes, use_tls: bool = False):
        text = decode(raw)
        jwt = _extract_jwt(text)
        if jwt:
            self.token_edit.setText(jwt)


# ══════════════════════════════════════════════════════════════
# Contenedor principal — agrupa las tres herramientas
# ══════════════════════════════════════════════════════════════
class FuzzerTab(QWidget):
    """Pestaña raíz del Fuzzer: contiene sub-pestañas por herramienta."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        tool_bar = QFrame()
        tool_bar.setObjectName("controlBar")
        tbl = QHBoxLayout(tool_bar)
        tbl.setContentsMargins(12, 8, 12, 8)
        tbl.setSpacing(10)

        lbl = QLabel("Nueva sesión:")
        lbl.setObjectName("paneCaption")
        tbl.addWidget(lbl)

        for text, slot in [
            ("Fuzzing",         lambda: self.add_fuzzing_tab()),
            ("Race Conditions", lambda: self.add_race_tab()),
            ("JWT Auditor",     lambda: self.add_jwt_tab()),
        ]:
            btn = QPushButton(text)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(slot)
            tbl.addWidget(btn)

        tbl.addStretch()
        self._toolbar_layout = tbl
        layout.addWidget(tool_bar)

        self._tabs = QTabWidget()
        self._tabs.setTabsClosable(False)
        self._tabs.tabBar().setExpanding(False)
        layout.addWidget(self._tabs)

        self._tool_titles: dict = {}

    def _add_tab(self, widget: QWidget, title: str) -> int:
        idx = self._tabs.addTab(widget, title)
        btn = QPushButton("✕")
        btn.setObjectName("tabCloseBtn")
        btn.setFixedSize(16, 16)
        btn.setCursor(Qt.PointingHandCursor)
        btn.clicked.connect(lambda checked=False, w=widget: self._tabs.removeTab(self._tabs.indexOf(w)))
        self._tabs.tabBar().setTabButton(idx, QTabBar.RightSide, btn)
        return idx

    # ── API pública ──────────────────────────────────────────
    def add_fuzzing_tab(self, raw: bytes = b"", use_tls: bool = False) -> FuzzingTab:
        tab = FuzzingTab(use_tls=use_tls, raw=raw)
        idx = self._add_tab(tab, f"Fuzzing {self._tabs.count() + 1}")
        self._tabs.setCurrentIndex(idx)
        return tab

    def add_race_tab(self, raw: bytes = b"", use_tls: bool = False) -> RaceTab:
        tab = RaceTab(use_tls=use_tls, raw=raw)
        idx = self._add_tab(tab, f"Race {self._tabs.count() + 1}")
        self._tabs.setCurrentIndex(idx)
        return tab

    def add_jwt_tab(self, raw: bytes = b"", use_tls: bool = False) -> JWTTab:
        tab = JWTTab()
        if raw:
            tab.load_from_flow(raw, use_tls)
        idx = self._add_tab(tab, f"JWT {self._tabs.count() + 1}")
        self._tabs.setCurrentIndex(idx)
        return tab

    def register_tool(self, button_text: str, widget: QWidget,
                      tab_name: str | None = None) -> None:
        """Registra una herramienta singleton como botón en la fila 'Nueva sesión'.

        Al pulsar el botón se abre el widget como pestaña (o se enfoca si ya
        estaba abierta). El widget se conserva entre cierres y reaperturas.
        """
        self._tool_titles[widget] = tab_name or button_text.strip()
        btn = QPushButton(button_text)
        btn.setCursor(Qt.PointingHandCursor)
        btn.clicked.connect(lambda checked=False, w=widget: self.open_tool(w))
        # Insertar justo antes del stretch final para que quede tras JWT Auditor
        self._toolbar_layout.insertWidget(self._toolbar_layout.count() - 1, btn)

    def open_tool(self, widget: QWidget) -> int:
        """Abre (o enfoca) la pestaña de una herramienta registrada."""
        idx = self._tabs.indexOf(widget)
        if idx == -1:
            idx = self._add_tab(widget, self._tool_titles.get(widget, "Tool"))
        self._tabs.setCurrentIndex(idx)
        return idx

    def load_from_flow(self, raw: bytes, use_tls: bool = False):
        """Abre una pestaña de Fuzzing con el flow dado."""
        self.add_fuzzing_tab(raw=raw, use_tls=use_tls)
