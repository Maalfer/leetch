from __future__ import annotations

import itertools
import random
import threading
import time
from collections import defaultdict

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFrame,
    QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QRadioButton,
    QScrollArea, QSpinBox, QSplitter, QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from net.http_client import send_raw_request
from net import http_message as hm
from ui.style import MONO, TEXT_DIM, decode, decode_http
from ui.highlighter import HTTPHighlighter

MARKER = "§"

_GREEN  = "#5fd38a"
_CYAN   = "#4fc3d6"
_AMBER  = "#ffb454"
_RED    = "#ff6b6b"
_HIT_BG = "#1a4a1a"   # fondo verde oscuro para filas que hacen match

_IP_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
    "X-Client-IP", "True-Client-IP", "CF-Connecting-IP", "X-Cluster-Client-IP",
]
_PRIVATE_PREFIXES = (10, 127, 169, 172, 192, 198, 203, 224, 240, 0)

_SPECIAL_PAYLOADS_DEFAULT = "\n".join([
    "",
    "null",
    "undefined",
    "true",
    "false",
    "0",
    "-1",
    "999999",
    "000000",
    "00000000",
    "1234567890",
    "' OR '1'='1",
    "' OR 1=1--",
    '{\"$gt\":\"\"}',
    "[123456]",
    "123456789012345678",
    "%00",
    "\\n",
    "<script>alert(1)</script>",
    "NaN",
    "Infinity",
])

_CHARSETS: dict[str, str] = {
    "Numérico (0-9)":            "0123456789",
    "Hex minúsculas (0-9, a-f)": "0123456789abcdef",
    "Hex mayúsculas (0-9, A-F)": "0123456789ABCDEF",
    "Alfanum. minúsculas":       "0123456789abcdefghijklmnopqrstuvwxyz",
    "Alfanum. mayúsculas":       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
}

_MODE_BRUTE   = "Fuerza bruta (todas las combinaciones)"
_MODE_SPECIAL = "Payloads especiales (fuzzing lógico)"


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


def _parse_target(raw_text: str, fallback_tls: bool = False) -> tuple[str, int, bool]:
    raw = raw_text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace")
    headers = hm.parse_headers(raw)
    host_val = headers.get("host", "").strip()
    if ":" in host_val:
        h, _, p = host_val.rpartition(":")
        try:
            port = int(p)
            return h.strip(), port, port in (443, 8443)
        except ValueError:
            pass
    port = 443 if fallback_tls else 80
    return host_val, port, port in (443, 8443) or fallback_tls


def _find_marker(template: str) -> tuple[int, int] | None:
    start = template.find(MARKER)
    if start == -1:
        return None
    end = template.find(MARKER, start + 1)
    return (start, end) if end != -1 else None


def _substitute(template: str, marker: tuple[int, int], value: str) -> str:
    s, e = marker
    return template[:s] + value + template[e + 1:]


def _generate_otp_list(digits: int, charset: str) -> list[str]:
    return ["".join(c) for c in itertools.product(charset, repeat=digits)]


def _random_public_ip() -> str:
    for _ in range(100):
        a = random.randint(1, 223)
        if a in _PRIVATE_PREFIXES:
            continue
        b = random.randint(0, 255)
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        return f"{a}.{b}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"1.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _gen_range_ips(prefix: str, lo: int, hi: int) -> list[str]:
    return [f"{prefix}.{i}" for i in range(lo, hi + 1)]


def _inject_ip_headers(raw: bytes, names: list[str], ip: str) -> bytes:
    if b"\r\n\r\n" not in raw:
        return raw
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    names_lower = {n.lower().encode() for n in names}
    filtered = [l for l in lines
                if not any(l.lower().startswith(nl + b":") for nl in names_lower)]
    for n in names:
        val = f"for={ip}" if n.lower() == "forwarded" else ip
        filtered.append(f"{n}: {val}".encode("latin-1"))
    return b"\r\n".join(filtered) + b"\r\n\r\n" + body


def _check_match(status: str, raw_resp: bytes,
                 status_filter: str, grep_text: str, grep_ci: bool) -> bool:
    if not status_filter and not grep_text:
        return False
    if status_filter:
        parts = [p.strip() for p in status_filter.split(",") if p.strip()]
        hit = False
        for p in parts:
            if p.startswith("!"):
                if status != p[1:]:
                    hit = True
            else:
                if status == p:
                    hit = True
        if not hit:
            return False
    if grep_text:
        body = raw_resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw_resp else raw_resp
        haystack = body.decode("latin-1", "replace")
        needle = grep_text
        if grep_ci:
            haystack = haystack.lower()
            needle = needle.lower()
        if needle not in haystack:
            return False
    return True


class _OTPWorker(QObject):
    result   = Signal(int, str, str, str, int, float, bytes, bytes)
    finished = Signal()
    progress = Signal(int, int)


class _SortItem(QTableWidgetItem):
    def __lt__(self, other: QTableWidgetItem) -> bool:
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return self.text() < other.text()


class OTPTab(QWidget):
    def __init__(self, use_tls: bool = False, raw: bytes = b""):
        super().__init__()
        self._running      = False
        self._thread: threading.Thread | None = None
        self._worker       = _OTPWorker()
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_finished)
        self._worker.progress.connect(self._on_progress)
        self._results: list[dict] = []
        self._fallback_tls = use_tls
        # stats
        self._stats_status: dict[str, int] = defaultdict(int)
        self._stats_length: dict[int, int]  = defaultdict(int)
        self._hit_count = 0
        # match criteria captured at attack start (read from UI in main thread)
        self._match_status = ""
        self._match_grep   = ""
        self._match_ci     = True
        self._stop_on_hit  = False
        self._build_ui()
        if raw:
            self.request_edit.setPlainText(decode(raw))

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # fila de controles superiores
        ctrl = QHBoxLayout()
        ctrl.setSpacing(8)

        ctrl.addWidget(QLabel("Modo:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([_MODE_BRUTE, _MODE_SPECIAL])
        self.mode_combo.setMinimumWidth(260)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        ctrl.addWidget(self.mode_combo)

        self._bf_widget = QWidget()
        bf_lay = QHBoxLayout(self._bf_widget)
        bf_lay.setContentsMargins(0, 0, 0, 0)
        bf_lay.setSpacing(8)
        bf_lay.addWidget(QLabel("Dígitos:"))
        self.digits_spin = QSpinBox()
        self.digits_spin.setRange(1, 12)
        self.digits_spin.setValue(6)
        self.digits_spin.valueChanged.connect(self._update_count_label)
        bf_lay.addWidget(self.digits_spin)
        bf_lay.addWidget(QLabel("Charset:"))
        self.charset_combo = QComboBox()
        self.charset_combo.addItems(list(_CHARSETS.keys()))
        self.charset_combo.setMinimumWidth(165)
        self.charset_combo.currentIndexChanged.connect(self._update_count_label)
        bf_lay.addWidget(self.charset_combo)
        self.count_lbl = QLabel("")
        self.count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        bf_lay.addWidget(self.count_lbl)
        ctrl.addWidget(self._bf_widget)

        ctrl.addWidget(QLabel("Hilos:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        ctrl.addWidget(self.threads_spin)

        ctrl.addStretch()
        self.start_btn = QPushButton("▶  Iniciar")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.clicked.connect(self.toggle_attack)
        ctrl.addWidget(self.start_btn)
        root.addLayout(ctrl)

        main_split = QSplitter(Qt.Horizontal)
        root.addWidget(main_split, 1)

        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        left_scroll.setWidget(self._build_left_panel())
        main_split.addWidget(left_scroll)
        main_split.addWidget(self._build_right_panel())
        main_split.setSizes([460, 580])

        self._update_count_label()

    def _build_left_panel(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        hint = QLabel(
            f"Pon <b>{MARKER}placeholder{MARKER}</b> alrededor del campo OTP "
            f"en la petición.")
        hint.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        self._req_stack = QStackedWidget()

        req_page = QWidget()
        rp_lay = QVBoxLayout(req_page)
        rp_lay.setContentsMargins(0, 0, 0, 0)
        rp_lay.setSpacing(4)
        rp_lay.addWidget(QLabel("Petición (marca el OTP con §…§):"))
        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(MONO)
        self.request_edit.setPlaceholderText(
            'POST /api/verify HTTP/1.1\r\nHost: ejemplo.com\r\n\r\n'
            '{"code":"§000000§"}')
        self._hl_req = HTTPHighlighter(self.request_edit.document())
        self.request_edit.setMinimumHeight(160)
        rp_lay.addWidget(self.request_edit)
        mark_row = QHBoxLayout()
        mark_row.setSpacing(6)
        mark_btn = QPushButton(f"Marcar selección ({MARKER}…{MARKER})")
        mark_btn.clicked.connect(self._mark_selection)
        mark_row.addWidget(mark_btn)
        clr_btn = QPushButton("Limpiar marcadores")
        clr_btn.clicked.connect(self._clear_markers)
        mark_row.addWidget(clr_btn)
        mark_row.addStretch()
        rp_lay.addLayout(mark_row)
        self._req_stack.addWidget(req_page)

        sp_page = QWidget()
        sp_lay = QVBoxLayout(sp_page)
        sp_lay.setContentsMargins(0, 0, 0, 0)
        sp_lay.setSpacing(4)
        sp_lay.addWidget(QLabel("Petición (marca el campo con §…§):"))
        self.request_edit_sp = QPlainTextEdit()
        self.request_edit_sp.setFont(MONO)
        self.request_edit_sp.setPlaceholderText(
            'POST /api/verify HTTP/1.1\r\nHost: ejemplo.com\r\n\r\n'
            '{"code":"§OTP§"}')
        self._hl_req_sp = HTTPHighlighter(self.request_edit_sp.document())
        self.request_edit_sp.setMinimumHeight(160)
        sp_lay.addWidget(self.request_edit_sp)
        mark_row2 = QHBoxLayout()
        mark_row2.setSpacing(6)
        mark_btn2 = QPushButton(f"Marcar selección ({MARKER}…{MARKER})")
        mark_btn2.clicked.connect(self._mark_selection_sp)
        mark_row2.addWidget(mark_btn2)
        clr_btn2 = QPushButton("Limpiar marcadores")
        clr_btn2.clicked.connect(self._clear_markers_sp)
        mark_row2.addWidget(clr_btn2)
        mark_row2.addStretch()
        sp_lay.addLayout(mark_row2)

        sp_lay.addWidget(QLabel("Payloads (uno por línea — editable):"))
        self.special_edit = QPlainTextEdit()
        self.special_edit.setFont(MONO)
        self.special_edit.setFixedHeight(130)
        self.special_edit.setPlainText(_SPECIAL_PAYLOADS_DEFAULT)
        sp_lay.addWidget(self.special_edit)
        self._req_stack.addWidget(sp_page)

        lay.addWidget(self._req_stack)

        lay.addWidget(self._build_ip_panel())
        lay.addWidget(self._build_detection_panel())
        lay.addStretch()

        return w

    def _build_right_panel(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFixedHeight(14)
        lay.addWidget(self.progress_bar)

        hdr_row = QHBoxLayout()
        hdr_row.addWidget(QLabel("Resultados:"))
        self.hits_lbl = QLabel("")
        self.hits_lbl.setStyleSheet(f"color: {_GREEN}; font-size: 11px; font-weight: bold;")
        hdr_row.addWidget(self.hits_lbl)
        hdr_row.addStretch()
        lay.addLayout(hdr_row)

        self.result_table = QTableWidget(0, 6)
        self.result_table.setHorizontalHeaderLabels(
            ["#", "Payload", "IP usada", "Estado", "Long.", "ms"])
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.result_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setShowGrid(False)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.verticalHeader().setDefaultSectionSize(24)
        self.result_table.setAlternatingRowColors(True)
        rh = self.result_table.horizontalHeader()
        rh.setSectionResizeMode(1, QHeaderView.Stretch)
        rh.setHighlightSections(False)
        self.result_table.setColumnWidth(0, 42)
        self.result_table.setColumnWidth(2, 108)
        self.result_table.setColumnWidth(3, 62)
        self.result_table.setColumnWidth(4, 68)
        self.result_table.setColumnWidth(5, 62)
        self.result_table.itemSelectionChanged.connect(self._on_row_selected)
        lay.addWidget(self.result_table, 2)

        lay.addWidget(self._build_stats_panel())

        view_split = QSplitter(Qt.Horizontal)

        req_frame = QFrame()
        rv = QVBoxLayout(req_frame)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.addWidget(QLabel("Petición enviada:"))
        self.sent_edit = QPlainTextEdit()
        self.sent_edit.setReadOnly(True)
        self.sent_edit.setFont(MONO)
        self._hl_sent = HTTPHighlighter(self.sent_edit.document())
        rv.addWidget(self.sent_edit)
        view_split.addWidget(req_frame)

        resp_frame = QFrame()
        rs = QVBoxLayout(resp_frame)
        rs.setContentsMargins(0, 0, 0, 0)
        rs.addWidget(QLabel("Respuesta:"))
        self.resp_edit = QPlainTextEdit()
        self.resp_edit.setReadOnly(True)
        self.resp_edit.setFont(MONO)
        self._hl_resp = HTTPHighlighter(self.resp_edit.document())
        rs.addWidget(self.resp_edit)
        view_split.addWidget(resp_frame)

        lay.addWidget(view_split, 1)
        return w

    def _build_ip_panel(self) -> QGroupBox:
        box = QGroupBox("Rotación IP — Rate Limit Bypass")
        box.setCheckable(True)
        box.setChecked(False)
        self._ip_group = box
        lay = QVBoxLayout(box)
        lay.setSpacing(6)

        hdr_lbl = QLabel("Cabeceras a inyectar:")
        hdr_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        lay.addWidget(hdr_lbl)

        grid = QGridLayout()
        grid.setSpacing(4)
        self._ip_header_checks: dict[str, QCheckBox] = {}
        defaults = {"X-Forwarded-For", "X-Real-IP"}
        for i, name in enumerate(_IP_HEADERS):
            cb = QCheckBox(name)
            cb.setChecked(name in defaults)
            self._ip_header_checks[name] = cb
            grid.addWidget(cb, i // 2, i % 2)
        lay.addLayout(grid)

        custom_row = QHBoxLayout()
        custom_row.addWidget(QLabel("Personalizada:"))
        self.custom_header_edit = QLineEdit()
        self.custom_header_edit.setPlaceholderText("X-Forwarded-IP")
        custom_row.addWidget(self.custom_header_edit, 1)
        lay.addLayout(custom_row)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color: #3a3f4b;")
        lay.addWidget(sep)

        src_lbl = QLabel("Fuente de IPs:")
        src_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        lay.addWidget(src_lbl)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(10)
        self._ip_mode_range  = QRadioButton("Rango")
        self._ip_mode_random = QRadioButton("Aleatorias")
        self._ip_mode_list   = QRadioButton("Lista")
        self._ip_mode_range.setChecked(True)
        for rb in (self._ip_mode_range, self._ip_mode_random, self._ip_mode_list):
            mode_row.addWidget(rb)
        mode_row.addStretch()
        lay.addLayout(mode_row)

        self._ip_stack = QStackedWidget()

        range_page = QWidget()
        rp = QHBoxLayout(range_page)
        rp.setContentsMargins(0, 0, 0, 0)
        rp.setSpacing(4)
        rp.addWidget(QLabel("Prefijo:"))
        self.ip_prefix_edit = QLineEdit("10.0.0")
        self.ip_prefix_edit.setMaximumWidth(100)
        rp.addWidget(self.ip_prefix_edit)
        rp.addWidget(QLabel("."))
        rp.addWidget(QLabel("De:"))
        self.ip_min_spin = QSpinBox()
        self.ip_min_spin.setRange(1, 254)
        self.ip_min_spin.setValue(1)
        self.ip_min_spin.setMaximumWidth(52)
        rp.addWidget(self.ip_min_spin)
        rp.addWidget(QLabel("a:"))
        self.ip_max_spin = QSpinBox()
        self.ip_max_spin.setRange(1, 254)
        self.ip_max_spin.setValue(254)
        self.ip_max_spin.setMaximumWidth(52)
        rp.addWidget(self.ip_max_spin)
        rp.addStretch()
        self._ip_stack.addWidget(range_page)

        rand_page = QWidget()
        QHBoxLayout(rand_page).addWidget(
            QLabel("IP pública aleatoria diferente por petición."))
        self._ip_stack.addWidget(rand_page)

        list_page = QWidget()
        lp = QVBoxLayout(list_page)
        lp.setContentsMargins(0, 0, 0, 0)
        lp.addWidget(QLabel("Una IP por línea:"))
        self.ip_list_edit = QPlainTextEdit()
        self.ip_list_edit.setFont(MONO)
        self.ip_list_edit.setFixedHeight(60)
        self.ip_list_edit.setPlaceholderText("192.168.1.1\n10.0.0.1")
        lp.addWidget(self.ip_list_edit)
        self._ip_stack.addWidget(list_page)

        lay.addWidget(self._ip_stack)

        self._ip_mode_range.toggled.connect(
            lambda on: on and self._ip_stack.setCurrentIndex(0))
        self._ip_mode_random.toggled.connect(
            lambda on: on and self._ip_stack.setCurrentIndex(1))
        self._ip_mode_list.toggled.connect(
            lambda on: on and self._ip_stack.setCurrentIndex(2))

        note = QLabel("IPs rotan una por petición; si el pool se agota, se reutiliza.")
        note.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px;")
        note.setWordWrap(True)
        lay.addWidget(note)
        return box

    def _build_detection_panel(self) -> QGroupBox:
        box = QGroupBox("Detección automática de OTP válido")
        box.setCheckable(True)
        box.setChecked(False)
        self._det_group = box
        lay = QVBoxLayout(box)
        lay.setSpacing(6)

        row1 = QHBoxLayout()
        row1.setSpacing(6)
        row1.addWidget(QLabel("Estado HTTP:"))
        self.match_status_edit = QLineEdit()
        self.match_status_edit.setPlaceholderText('200   ó   200,302   ó   !400')
        self.match_status_edit.setToolTip(
            "Códigos separados por comas. Prefija con ! para \"diferente de\".\n"
            "Ej: 200  →  solo respuestas 200\n"
            "    !400 →  cualquier código que no sea 400")
        row1.addWidget(self.match_status_edit, 1)
        lay.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(6)
        row2.addWidget(QLabel("Cuerpo contiene:"))
        self.match_grep_edit = QLineEdit()
        self.match_grep_edit.setPlaceholderText('"success":true   ó   "token":')
        row2.addWidget(self.match_grep_edit, 1)
        self.match_ci_cb = QCheckBox("Ignorar mayúsculas")
        self.match_ci_cb.setChecked(True)
        row2.addWidget(self.match_ci_cb)
        lay.addLayout(row2)

        opts = QHBoxLayout()
        opts.setSpacing(12)
        self.stop_on_hit_cb = QCheckBox("Parar al primer acierto")
        self.stop_on_hit_cb.setChecked(True)
        opts.addWidget(self.stop_on_hit_cb)
        opts.addStretch()
        lay.addLayout(opts)

        note = QLabel(
            "Las filas que hagan match se resaltan en verde. "
            "Los filtros se aplican con AND (ambos deben cumplirse si están rellenos).")
        note.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px;")
        note.setWordWrap(True)
        lay.addWidget(note)
        return box

    def _build_stats_panel(self) -> QGroupBox:
        box = QGroupBox("Estadísticas en tiempo real")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(8, 4, 8, 6)
        lay.setSpacing(4)

        status_row = QHBoxLayout()
        status_row.addWidget(QLabel("Estados:"))
        self.stats_status_lbl = QLabel("—")
        self.stats_status_lbl.setFont(MONO)
        self.stats_status_lbl.setWordWrap(True)
        status_row.addWidget(self.stats_status_lbl, 1)
        lay.addLayout(status_row)

        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Longitudes:"))
        self.stats_len_lbl = QLabel("—")
        self.stats_len_lbl.setFont(MONO)
        self.stats_len_lbl.setWordWrap(True)
        len_row.addWidget(self.stats_len_lbl, 1)
        lay.addLayout(len_row)

        anom_row = QHBoxLayout()
        anom_row.addWidget(QLabel("Anomalías:"))
        self.stats_anom_lbl = QLabel("—")
        self.stats_anom_lbl.setStyleSheet(f"color: {_GREEN}; font-weight: bold;")
        self.stats_anom_lbl.setFont(MONO)
        anom_row.addWidget(self.stats_anom_lbl, 1)
        lay.addLayout(anom_row)

        return box

    def _on_mode_changed(self, idx: int):
        is_special = (self.mode_combo.currentText() == _MODE_SPECIAL)
        self._bf_widget.setVisible(not is_special)
        self._req_stack.setCurrentIndex(1 if is_special else 0)

    def _update_count_label(self):
        digits  = self.digits_spin.value()
        charset = _CHARSETS[self.charset_combo.currentText()]
        total   = len(charset) ** digits
        if total > 10_000_000:
            self.count_lbl.setText(f"⚠ {total:,} combinaciones")
            self.count_lbl.setStyleSheet(f"color: {_AMBER}; font-size: 11px;")
        else:
            self.count_lbl.setText(f"{total:,} combinaciones")
            self.count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")

    def _mark_selection(self):
        c = self.request_edit.textCursor()
        if c.selectedText():
            c.insertText(f"{MARKER}{c.selectedText()}{MARKER}")

    def _clear_markers(self):
        self.request_edit.setPlainText(
            self.request_edit.toPlainText().replace(MARKER, ""))

    def _mark_selection_sp(self):
        c = self.request_edit_sp.textCursor()
        if c.selectedText():
            c.insertText(f"{MARKER}{c.selectedText()}{MARKER}")

    def _clear_markers_sp(self):
        self.request_edit_sp.setPlainText(
            self.request_edit_sp.toPlainText().replace(MARKER, ""))

    def _update_stats(self):
        if self._stats_status:
            parts = sorted(self._stats_status.items(), key=lambda x: -x[1])
            self.stats_status_lbl.setText(
                "  ".join(f"<b style='color:{_status_color(k).name() if _status_color(k) else TEXT_DIM}'>{k}</b>:{v:,}"
                          for k, v in parts))
        else:
            self.stats_status_lbl.setText("—")

        if self._stats_length:
            top = sorted(self._stats_length.items(), key=lambda x: -x[1])[:6]
            self.stats_len_lbl.setText(
                "  ".join(f"{l}b:{c:,}" for l, c in top))
        else:
            self.stats_len_lbl.setText("—")

        anom_payloads = self._anomaly_rows()
        if anom_payloads:
            self.stats_anom_lbl.setText(
                f"{len(anom_payloads)} fila(s) con longitud atípica — "
                f"payload(s): {', '.join(anom_payloads[:3])}"
                + (" …" if len(anom_payloads) > 3 else ""))
        else:
            self.stats_anom_lbl.setText("—")

    def _anomaly_rows(self) -> list[str]:
        if len(self._stats_length) < 2:
            return []
        baseline = max(self._stats_length, key=lambda k: self._stats_length[k])
        return [
            r["otp"] for r in self._results
            if r["length"] != baseline and r["length"] != 0
        ]

    def _build_ip_pool(self) -> list[str]:
        if self._ip_mode_random.isChecked():
            return []
        if self._ip_mode_list.isChecked():
            ips = [l.strip() for l in self.ip_list_edit.toPlainText().splitlines()
                   if l.strip()]
            return ips or ["127.0.0.1"]
        prefix = self.ip_prefix_edit.text().strip()
        lo, hi = self.ip_min_spin.value(), self.ip_max_spin.value()
        if lo > hi:
            lo, hi = hi, lo
        return _gen_range_ips(prefix, lo, hi)

    def _get_ip(self, idx: int, pool: list[str]) -> str:
        if self._ip_mode_random.isChecked():
            return _random_public_ip()
        return pool[idx % len(pool)] if pool else _random_public_ip()

    def _active_ip_headers(self) -> list[str]:
        selected = [n for n, cb in self._ip_header_checks.items() if cb.isChecked()]
        custom = self.custom_header_edit.text().strip()
        if custom:
            selected.append(custom)
        return selected

    def toggle_attack(self):
        if self._running:
            self._running = False
            self.start_btn.setText("▶  Iniciar")
            return

        is_special = (self.mode_combo.currentText() == _MODE_SPECIAL)
        template = (self.request_edit_sp if is_special else self.request_edit).toPlainText()

        marker = _find_marker(template)
        if marker is None:
            QMessageBox.warning(self, "Marcador faltante",
                f"Rodea el campo OTP con {MARKER}…{MARKER} en la petición.")
            return

        host, port, use_tls = _parse_target(template, self._fallback_tls)
        if not host:
            QMessageBox.warning(self, "Host vacío",
                "La petición debe incluir el header Host:.")
            return

        ip_enabled = self._ip_group.isChecked()
        if ip_enabled and not self._active_ip_headers():
            QMessageBox.warning(self, "Sin cabeceras IP",
                "Marca al menos una cabecera de IP o escribe una personalizada.")
            return

        if is_special:
            otp_list = [l for l in self.special_edit.toPlainText().splitlines()]
        else:
            digits  = self.digits_spin.value()
            charset = _CHARSETS[self.charset_combo.currentText()]
            total   = len(charset) ** digits
            if total > 1_000_000:
                from PySide6.QtWidgets import QMessageBox as _MB
                if _MB.question(self, "Ataque muy grande",
                        f"Se generarán {total:,} peticiones. ¿Continuar?",
                        _MB.Yes | _MB.No) != _MB.Yes:
                    return
            otp_list = _generate_otp_list(digits, charset)

        ip_pool    = self._build_ip_pool() if ip_enabled else []
        ip_headers = self._active_ip_headers() if ip_enabled else []

        # capturar criterios de detección en el hilo principal
        det_enabled = self._det_group.isChecked()
        self._match_status = self.match_status_edit.text().strip() if det_enabled else ""
        self._match_grep   = self.match_grep_edit.text().strip()   if det_enabled else ""
        self._match_ci     = self.match_ci_cb.isChecked()
        self._stop_on_hit  = self.stop_on_hit_cb.isChecked() and det_enabled

        self._results.clear()
        self._stats_status.clear()
        self._stats_length.clear()
        self._hit_count = 0
        self.result_table.setRowCount(0)
        self.sent_edit.clear()
        self.resp_edit.clear()
        self.hits_lbl.setText("")
        self.stats_status_lbl.setText("—")
        self.stats_len_lbl.setText("—")
        self.stats_anom_lbl.setText("—")

        self._running = True
        self.result_table.setSortingEnabled(False)
        self.start_btn.setText("■  Detener")
        self.progress_bar.setMaximum(len(otp_list))
        self.progress_bar.setValue(0)

        self._thread = threading.Thread(
            target=self._run_attack,
            args=(template, marker, otp_list, host, port, use_tls,
                  self.threads_spin.value(), ip_enabled, ip_pool, ip_headers),
            daemon=True)
        self._thread.start()

    def _run_attack(self, template, marker, otp_list, host, port, use_tls,
                    n_threads, ip_enabled, ip_pool, ip_headers):
        sem  = threading.Semaphore(n_threads)
        lock = threading.Lock()
        done = [0]
        total = len(otp_list)

        def send_one(idx: int, otp: str):
            if not self._running:
                return
            try:
                raw_text = _substitute(template, marker, otp)
                raw_text = raw_text.replace("\r\n", "\n").replace("\n", "\r\n")
                raw_req  = raw_text.encode("utf-8", "replace")

                ip_used = ""
                if ip_enabled:
                    ip_used = self._get_ip(idx, ip_pool)
                    raw_req = _inject_ip_headers(raw_req, ip_headers, ip_used)

                t0       = time.perf_counter()
                raw_resp = b""
                try:
                    raw_resp = send_raw_request(raw_req, host, port, use_tls)
                    elapsed  = (time.perf_counter() - t0) * 1000
                    first    = raw_resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                    parts    = first.split(" ", 2)
                    status   = parts[1] if len(parts) >= 2 else "???"
                    length   = len(raw_resp)
                except Exception:
                    elapsed = (time.perf_counter() - t0) * 1000
                    status  = "ERR"
                    length  = 0

                self._worker.result.emit(
                    idx, otp, ip_used, status, length, elapsed, raw_req, raw_resp)
                with lock:
                    done[0] += 1
                    self._worker.progress.emit(done[0], total)
            finally:
                sem.release()

        threads = []
        for idx, otp in enumerate(otp_list):
            if not self._running:
                break
            sem.acquire()
            t = threading.Thread(target=send_one, args=(idx, otp), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        self._worker.finished.emit()

    @Slot(int, str, str, str, int, float, bytes, bytes)
    def _on_result(self, idx: int, otp: str, ip: str, status: str,
                   length: int, ms: float, raw_req: bytes, raw_resp: bytes):
        self._results.append({
            "idx": idx, "otp": otp, "ip": ip, "status": status,
            "length": length, "ms": ms,
            "raw_req": raw_req, "raw_resp": raw_resp,
        })

        self._stats_status[status] += 1
        self._stats_length[length] += 1

        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        items = [
            _SortItem(str(idx)),
            _SortItem(repr(otp) if otp == "" else otp),
            _SortItem(ip if ip else "—"),
            _SortItem(status),
            _SortItem(str(length)),
            _SortItem(f"{ms:.1f}"),
        ]
        sc = _status_color(status)
        if sc:
            items[3].setForeground(sc)
        if ip:
            items[2].setForeground(QColor(_CYAN))

        for col, it in enumerate(items):
            self.result_table.setItem(row, col, it)

        # detección: comprobar criterios
        is_hit = _check_match(status, raw_resp,
                               self._match_status, self._match_grep, self._match_ci)
        if is_hit:
            self._hit_count += 1
            hit_brush = QBrush(QColor(_HIT_BG))
            for col in range(self.result_table.columnCount()):
                it = self.result_table.item(row, col)
                if it:
                    it.setBackground(hit_brush)
            self.hits_lbl.setText(
                f"  {self._hit_count} acierto{'s' if self._hit_count != 1 else ''} encontrado{'s' if self._hit_count != 1 else ''}")
            if self._stop_on_hit:
                self._running = False

        # actualizar stats cada 25 resultados para no sobrecargar la UI
        if len(self._results) % 25 == 0 or is_hit:
            self._update_stats()

    @Slot(int, int)
    def _on_progress(self, done: int, total: int):
        self.progress_bar.setValue(done)
        pct = int(done / total * 100) if total else 0
        self.progress_bar.setFormat(f"{done:,} / {total:,}  ({pct}%)")

    @Slot()
    def _on_finished(self):
        self._running = False
        self.start_btn.setText("▶  Iniciar")
        self.result_table.setSortingEnabled(True)
        self._update_stats()

    def _on_row_selected(self):
        sel = self.result_table.selectedItems()
        if not sel:
            return
        row = self.result_table.row(sel[0])
        if row < len(self._results):
            r = self._results[row]
            self.sent_edit.setPlainText(decode(r["raw_req"]))
            self.resp_edit.setPlainText(decode_http(r["raw_resp"]))

    def load_from_flow(self, raw: bytes, use_tls: bool = False):
        self._fallback_tls = use_tls
        self.request_edit.setPlainText(decode(raw))
        self.request_edit_sp.setPlainText(decode(raw))
