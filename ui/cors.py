from __future__ import annotations

import threading
import time

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QSpinBox, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from net.http_client import send_raw_request
from net import http_message as hm
from ui.style import MONO, TEXT_DIM, decode, decode_http
from ui.highlighter import HTTPHighlighter

_CRITICAL = "CRITICAL"
_HIGH     = "HIGH"
_MEDIUM   = "MEDIUM"
_INFO     = "INFO"
_SAFE     = "SAFE"
_ERR      = "ERR"

_SEV_FG: dict[str, str] = {
    _CRITICAL: "#ff6b6b",
    _HIGH:     "#ffb454",
    _MEDIUM:   "#f0e040",
    _INFO:     "#4fc3d6",
    _SAFE:     "#5fd38a",
    _ERR:      "#9aa1ad",
}
_SEV_BG: dict[str, str] = {
    _CRITICAL: "#3d1010",
    _HIGH:     "#3d2800",
    _MEDIUM:   "#28280a",
    _INFO:     "#0a1e2a",
    _SAFE:     "#0a2010",
    _ERR:      "#1e1e1e",
}


def _gen_origins(host: str, scheme: str) -> list[tuple[str, str]]:
    origins: list[tuple[str, str]] = []

    base = f"{scheme}://{host}"
    origins.append((base, "Origen legítimo (baseline)"))
    origins.append(("null", "null origin — explotable via <iframe sandbox>"))

    parts = host.split(".")
    if len(parts) >= 2:
        tld    = parts[-1]
        name   = parts[-2]
        domain = f"{name}.{tld}"

        if host != domain:
            origins.append((f"{scheme}://{domain}", "Dominio padre (sin subdominio)"))
            origins.append((f"{scheme}://evil.{domain}", "Subdominio arbitrario del target"))

        origins.append((f"{scheme}://evil-{name}.{tld}", "Prefijo 'evil-' en nombre"))
        origins.append((f"{scheme}://{name}attacker.{tld}", "Sufijo en el nombre del dominio"))
        origins.append((f"{scheme}://{host}.attacker.com", "Host como subdominio del atacante"))
        origins.append((f"{scheme}://{domain}.attacker.com", "Dominio como subdominio del atacante"))

        other_scheme = "http" if scheme == "https" else "https"
        origins.append((f"{other_scheme}://{host}", f"Cambio de protocolo ({other_scheme}://)"))

    origins.append((f"{scheme}://attacker.com", "Dominio atacante genérico"))
    origins.append(("https://evil.com", "evil.com — dominio de referencia"))

    return origins


def _inject_origin(raw: bytes, origin: str) -> bytes:
    if b"\r\n\r\n" not in raw:
        return raw
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    filtered = [l for l in lines if not l.lower().startswith(b"origin:")]
    filtered.append(f"Origin: {origin}".encode("latin-1"))
    return b"\r\n".join(filtered) + b"\r\n\r\n" + body


def _make_preflight(raw: bytes, origin: str) -> bytes:
    if b"\r\n\r\n" not in raw:
        return raw
    head = raw.split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    if not lines:
        return raw

    rl_parts = lines[0].split(b" ")
    original_method = rl_parts[0].decode("latin-1", "replace") if rl_parts else "GET"
    if len(rl_parts) >= 1:
        rl_parts[0] = b"OPTIONS"
    request_line = b" ".join(rl_parts)

    skip = (b"origin:", b"content-length:", b"content-type:",
            b"transfer-encoding:", b"access-control-")
    new_lines = [request_line]
    for line in lines[1:]:
        if any(line.lower().startswith(p) for p in skip):
            continue
        new_lines.append(line)

    new_lines.append(f"Origin: {origin}".encode("latin-1"))
    new_lines.append(f"Access-Control-Request-Method: {original_method}".encode("latin-1"))
    new_lines.append(b"Access-Control-Request-Headers: authorization, content-type")

    return b"\r\n".join(new_lines) + b"\r\n\r\n"


def _parse_cors(raw_resp: bytes) -> dict[str, str]:
    if not raw_resp or b"\r\n\r\n" not in raw_resp:
        return {}
    head = raw_resp.split(b"\r\n\r\n", 1)[0]
    _KEY_MAP = {
        "access-control-allow-origin":      "acao",
        "access-control-allow-credentials": "acac",
        "access-control-allow-methods":     "acam",
        "access-control-allow-headers":     "acah",
        "vary":                             "vary",
    }
    result: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        k_lower = k.strip().lower().decode("latin-1", "replace")
        key = _KEY_MAP.get(k_lower)
        if key:
            result[key] = v.strip().decode("latin-1", "replace")
    return result


def _http_status(raw_resp: bytes) -> str:
    if not raw_resp:
        return ""
    first = raw_resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = first.split(" ", 2)
    return parts[1] if len(parts) >= 2 else ""


def _classify(origin_sent: str, cors: dict[str, str]) -> tuple[str, str]:
    acao = cors.get("acao", "")
    acac = cors.get("acac", "").strip().lower() == "true"

    if not acao:
        return _SAFE, "Sin header ACAO — CORS no habilitado para este origen"

    if acao == "*":
        if acac:
            return _INFO, "Wildcard '*' + credentials — los navegadores ignoran credentials con '*'"
        return _MEDIUM, "Wildcard '*' — datos sin autenticar accesibles desde cualquier origen"

    if acao == "null":
        if acac:
            return _CRITICAL, "null + credentials=true — exfiltración posible vía <iframe sandbox>"
        return _HIGH, "ACAO: null reflejado — explotable con <iframe sandbox>"

    if acao == origin_sent:
        if acac:
            return _CRITICAL, "Origin reflejado + credentials=true — CORS bypass total, exfiltración de datos"
        return _HIGH, "Origin reflejado sin credentials — acceso cross-origin a respuesta"

    return _INFO, f"ACAO fijo: {acao}"


class _CORSWorker(QObject):
    result   = Signal(object)
    finished = Signal()
    progress = Signal(int, int)


class CORSTab(QWidget):
    def __init__(self, raw: bytes = b"", use_tls: bool = False):
        super().__init__()
        self._running = False
        self._thread: threading.Thread | None = None
        self._fallback_tls = use_tls
        self._results: list[dict] = []
        self._worker = _CORSWorker()
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_finished)
        self._worker.progress.connect(self._on_progress)
        self._build_ui()
        if raw:
            self.request_edit.setPlainText(decode(raw))

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(8)

        self.start_btn = QPushButton("▶  Iniciar")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.clicked.connect(self._toggle)
        top.addWidget(self.start_btn)

        self.clear_btn = QPushButton("Limpiar")
        self.clear_btn.clicked.connect(self._clear)
        top.addWidget(self.clear_btn)

        top.addWidget(QLabel("Hilos:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 20)
        self.threads_spin.setValue(5)
        top.addWidget(self.threads_spin)

        self.preflight_chk = QCheckBox("Probar preflight OPTIONS")
        self.preflight_chk.setToolTip(
            "Envía también una petición OPTIONS con Access-Control-Request-Method "
            "para comprobar cómo responde el servidor a preflights CORS")
        top.addWidget(self.preflight_chk)

        top.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v / %m")
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setFixedWidth(180)
        top.addWidget(self.progress_bar)

        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        top.addWidget(self.status_lbl)

        root.addLayout(top)

        main_split = QSplitter(Qt.Horizontal)
        main_split.setHandleWidth(8)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)

        req_lbl = QLabel("Petición HTTP")
        req_lbl.setObjectName("paneCaption")
        ll.addWidget(req_lbl)

        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(MONO)
        self.request_edit.setPlaceholderText(
            "GET /api/profile HTTP/1.1\r\nHost: ejemplo.com\r\n"
            "Authorization: Bearer eyJ…\r\n\r\n")
        HTTPHighlighter(self.request_edit.document())
        ll.addWidget(self.request_edit, 3)

        extra_lbl = QLabel("Origins adicionales  (uno por línea)")
        extra_lbl.setObjectName("paneCaption")
        ll.addWidget(extra_lbl)

        self.extra_origins = QPlainTextEdit()
        self.extra_origins.setFont(MONO)
        self.extra_origins.setMaximumHeight(90)
        self.extra_origins.setPlaceholderText(
            "https://staging.empresa.com\nhttps://mi-otro-dominio.com")
        ll.addWidget(self.extra_origins)

        legend = QFrame()
        legend.setObjectName("controlBar")
        leg_lay = QHBoxLayout(legend)
        leg_lay.setContentsMargins(8, 4, 8, 4)
        leg_lay.setSpacing(10)
        for sev in (_CRITICAL, _HIGH, _MEDIUM, _INFO, _SAFE):
            dot = QLabel(f"● {sev}")
            dot.setStyleSheet(f"color: {_SEV_FG[sev]}; font-size: 10px;")
            leg_lay.addWidget(dot)
        leg_lay.addStretch()
        ll.addWidget(legend)

        main_split.addWidget(left)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)

        self.summary_box = QFrame()
        self.summary_box.setObjectName("controlBar")
        sum_lay = QHBoxLayout(self.summary_box)
        sum_lay.setContentsMargins(10, 6, 10, 6)
        self.sum_lbl = QLabel("Inicia el análisis para ver los resultados de seguridad CORS")
        self.sum_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        self.sum_lbl.setWordWrap(True)
        sum_lay.addWidget(self.sum_lbl, 1)
        rl.addWidget(self.summary_box)

        vsplit = QSplitter(Qt.Vertical)
        vsplit.setHandleWidth(8)

        self.result_table = QTableWidget(0, 6)
        self.result_table.setHorizontalHeaderLabels(
            ["#", "Origin enviado", "ACAO", "ACAC", "Estado", "Severidad"])
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.result_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setShowGrid(False)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.verticalHeader().setDefaultSectionSize(26)
        rh = self.result_table.horizontalHeader()
        rh.setSectionResizeMode(1, QHeaderView.Stretch)
        rh.setSectionResizeMode(2, QHeaderView.Stretch)
        rh.setHighlightSections(False)
        rh.setSortIndicatorShown(True)
        self.result_table.setColumnWidth(0, 40)
        self.result_table.setColumnWidth(3, 55)
        self.result_table.setColumnWidth(4, 65)
        self.result_table.setColumnWidth(5, 100)
        self.result_table.itemSelectionChanged.connect(self._on_selection)
        vsplit.addWidget(self.result_table)

        detail = QWidget()
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(0, 4, 0, 0)
        dl.setSpacing(0)
        det_split = QSplitter(Qt.Horizontal)
        det_split.setHandleWidth(8)

        for attr, title in [("detail_req", "Petición enviada"), ("detail_resp", "Respuesta recibida")]:
            box = QWidget()
            bl = QVBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(4)
            cap = QLabel(title)
            cap.setObjectName("paneCaption")
            bl.addWidget(cap)
            edit = QPlainTextEdit()
            edit.setFont(MONO)
            edit.setReadOnly(True)
            HTTPHighlighter(edit.document())
            bl.addWidget(edit)
            setattr(self, attr, edit)
            det_split.addWidget(box)

        dl.addWidget(det_split)
        vsplit.addWidget(detail)
        vsplit.setSizes([300, 220])

        rl.addWidget(vsplit, 1)
        main_split.addWidget(right)
        main_split.setSizes([360, 740])
        root.addWidget(main_split, 1)

    def _toggle(self):
        if self._running:
            self._running = False
            self.start_btn.setText("▶  Iniciar")
        else:
            self._start()

    def _start(self):
        raw_text = self.request_edit.toPlainText().strip()
        if not raw_text:
            QMessageBox.warning(self, "Petición vacía", "Introduce una petición HTTP.")
            return

        raw = raw_text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace")
        headers = hm.parse_headers(raw)
        host_val = headers.get("host", "").strip()
        if not host_val:
            QMessageBox.warning(self, "Host no encontrado",
                                "La petición debe incluir un header Host:")
            return

        if ":" in host_val:
            host, _, p_str = host_val.rpartition(":")
            try:
                port = int(p_str)
            except ValueError:
                host = host_val
                port = 443 if self._fallback_tls else 80
        else:
            host = host_val
            port = 443 if self._fallback_tls else 80
        use_tls = port in (443, 8443) or self._fallback_tls
        scheme  = "https" if use_tls else "http"

        origins = _gen_origins(host, scheme)
        for line in self.extra_origins.toPlainText().splitlines():
            line = line.strip()
            if line and not any(o == line for o, _ in origins):
                origins.append((line, "Origen personalizado"))

        do_preflight = self.preflight_chk.isChecked()
        total = len(origins) * (2 if do_preflight else 1)

        self._running = True
        self.result_table.setRowCount(0)
        self._results.clear()
        self.detail_req.clear()
        self.detail_resp.clear()
        self.start_btn.setText("■  Detener")
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(0)
        self.status_lbl.setText(f"Probando {len(origins)} origins…")
        self.sum_lbl.setText("Analizando…")
        self.sum_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")

        n_threads = self.threads_spin.value()
        self._thread = threading.Thread(
            target=self._run,
            args=(raw, host, port, use_tls, origins, do_preflight, n_threads),
            daemon=True,
        )
        self._thread.start()

    def _run(self, raw, host, port, use_tls, origins, do_preflight, n_threads):
        sem  = threading.Semaphore(n_threads)
        lock = threading.Lock()
        done = [0]

        tasks: list[tuple[int, str, str, bool]] = []
        for origin, desc in origins:
            tasks.append((len(tasks), origin, desc, False))
            if do_preflight:
                tasks.append((len(tasks), origin, desc, True))

        total = len(tasks)

        def send_one(idx, origin, desc, is_preflight):
            if not self._running:
                sem.release()
                return
            req = _make_preflight(raw, origin) if is_preflight else _inject_origin(raw, origin)
            t0 = time.perf_counter()
            raw_resp = b""
            error = ""
            try:
                raw_resp = send_raw_request(req, host, port, use_tls)
            except Exception as exc:
                error = str(exc)
            finally:
                sem.release()

            ms   = (time.perf_counter() - t0) * 1000
            cors = _parse_cors(raw_resp) if raw_resp else {}
            http_status = _http_status(raw_resp) if raw_resp else "ERR"

            if error:
                severity, sev_desc = _ERR, f"Error de conexión: {error}"
                acao = acac = ""
            else:
                acao = cors.get("acao", "")
                acac = cors.get("acac", "")
                severity, sev_desc = _classify(origin, cors)

            self._worker.result.emit({
                "idx":          idx,
                "origin":       origin,
                "desc":         desc,
                "is_preflight": is_preflight,
                "acao":         acao,
                "acac":         acac,
                "acam":         cors.get("acam", ""),
                "http_status":  http_status,
                "severity":     severity,
                "sev_desc":     sev_desc,
                "ms":           ms,
                "raw_req":      req,
                "raw_resp":     raw_resp,
            })
            with lock:
                done[0] += 1
                self._worker.progress.emit(done[0], total)

        threads = []
        for idx, origin, desc, is_pf in tasks:
            if not self._running:
                break
            sem.acquire()
            t = threading.Thread(target=send_one, args=(idx, origin, desc, is_pf), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        self._worker.finished.emit()

    @Slot(object)
    def _on_result(self, entry: dict):
        self._results.append(entry)
        self._add_row(entry)
        self._refresh_summary()

    @Slot()
    def _on_finished(self):
        self._running = False
        self.start_btn.setText("▶  Iniciar")
        self.status_lbl.setText(f"{len(self._results)} probados")
        self._refresh_summary()

    @Slot(int, int)
    def _on_progress(self, done, total):
        self.progress_bar.setValue(done)

    def _on_selection(self):
        items = self.result_table.selectedItems()
        if not items:
            self.detail_req.clear()
            self.detail_resp.clear()
            return
        entry = items[0].data(Qt.UserRole)
        if not entry:
            return
        self.detail_req.setPlainText(decode(entry.get("raw_req", b"")))
        self.detail_resp.setPlainText(decode_http(entry.get("raw_resp", b"")))

    def _add_row(self, entry: dict):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)

        sev    = entry["severity"]
        sev_bg = QColor(_SEV_BG.get(sev, "#1e1e1e"))
        sev_fg = QColor(_SEV_FG.get(sev, "#dfe3ea"))

        prefix = "[PF] " if entry.get("is_preflight") else ""
        acac   = entry.get("acac", "")
        acac_display = ("✓" if acac.lower() == "true" else "✗") if acac else "—"

        cols = [
            str(entry["idx"] + 1),
            prefix + entry["origin"],
            entry["acao"] or "—",
            acac_display,
            entry["http_status"],
            sev,
        ]
        for col, text in enumerate(cols):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, entry)
            item.setToolTip(entry.get("sev_desc", ""))
            if col == 5:
                item.setBackground(sev_bg)
                item.setForeground(sev_fg)
            elif col == 3 and acac:
                color = "#ff6b6b" if acac.lower() == "true" else "#5fd38a"
                item.setForeground(QColor(color))
            self.result_table.setItem(row, col, item)

    def _refresh_summary(self):
        if not self._results:
            return
        counts = {s: 0 for s in (_CRITICAL, _HIGH, _MEDIUM, _INFO, _SAFE, _ERR)}
        for r in self._results:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1

        parts = []
        if counts[_CRITICAL]:
            parts.append(f'<span style="color:{_SEV_FG[_CRITICAL]};font-weight:bold">'
                         f'● {counts[_CRITICAL]} CRITICAL</span>')
        if counts[_HIGH]:
            parts.append(f'<span style="color:{_SEV_FG[_HIGH]};font-weight:bold">'
                         f'● {counts[_HIGH]} HIGH</span>')
        if counts[_MEDIUM]:
            parts.append(f'<span style="color:{_SEV_FG[_MEDIUM]}">'
                         f'● {counts[_MEDIUM]} MEDIUM</span>')

        total = len(self._results)
        dim = TEXT_DIM
        if parts:
            self.sum_lbl.setText(
                "  |  ".join(parts)
                + f'  <span style="color:{dim}">— {total} probados</span>')
        elif counts[_SAFE] or counts[_INFO]:
            self.sum_lbl.setText(
                f'<span style="color:{_SEV_FG[_SAFE]}">✓ Sin misconfig grave detectada</span>'
                f'  <span style="color:{dim}">— {total} probados</span>')
        else:
            self.sum_lbl.setText(f'<span style="color:{dim}">{total} probados</span>')

    def _clear(self):
        self._results.clear()
        self.result_table.setRowCount(0)
        self.detail_req.clear()
        self.detail_resp.clear()
        self.progress_bar.setValue(0)
        self.status_lbl.setText("")
        self.sum_lbl.setText("Inicia el análisis para ver los resultados de seguridad CORS")
        self.sum_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")

    def load_from_flow(self, raw: bytes, use_tls: bool = False):
        self._fallback_tls = use_tls
        self.request_edit.setPlainText(decode(raw))
