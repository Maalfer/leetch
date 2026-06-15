from __future__ import annotations

import re
from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
    QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from ui.style import MONO, TEXT_DIM, decode, decode_http
from ui.highlighter import HTTPHighlighter

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SEV_BG = {
    "CRITICAL": "#3d1010",
    "HIGH":     "#3d2800",
    "MEDIUM":   "#28280a",
    "LOW":      "#0a1e2a",
    "INFO":     "#1e1e2e",
}
_SEV_FG = {
    "CRITICAL": "#ff6b6b",
    "HIGH":     "#ffb454",
    "MEDIUM":   "#f5e642",
    "LOW":      "#4fc3d6",
    "INFO":     "#9aa1ad",
}


@dataclass
class Finding:
    severity: str
    check: str
    host: str
    url: str
    detail: str
    flow: object



def _parse_headers(raw: bytes, skip_first_line: bool = True) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    head = raw.split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    for line in (lines[1:] if skip_first_line else lines):
        if b":" not in line:
            continue
        name, _, val = line.partition(b":")
        key = name.strip().lower().decode("latin-1", "replace")
        out.setdefault(key, []).append(val.strip().decode("latin-1", "replace"))
    return out

def _body(raw: bytes) -> bytes:
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""

def _status(raw: bytes) -> int:
    try:
        return int(raw.split(b" ", 2)[1])
    except Exception:
        return 0

def _method(raw: bytes) -> str:
    try:
        return raw.split(b" ", 1)[0].decode("latin-1").upper()
    except Exception:
        return ""



def _check_security_headers(flow) -> list[Finding]:
    findings = []
    resp  = _parse_headers(flow.raw_response)
    status = _status(flow.raw_response)
    ct = " ".join(resp.get("content-type", []))

    if "html" not in ct or status not in range(200, 400):
        return findings

    if flow.use_tls and "strict-transport-security" not in resp:
        findings.append(Finding("MEDIUM", "Missing HSTS", flow.host, flow.url,
            "Falta Strict-Transport-Security en respuesta HTTPS"))

    if "content-security-policy" not in resp:
        findings.append(Finding("MEDIUM", "Missing CSP", flow.host, flow.url,
            "Falta Content-Security-Policy"))

    xfo = resp.get("x-frame-options", [])
    csp_val = " ".join(resp.get("content-security-policy", []))
    if not xfo and "frame-ancestors" not in csp_val:
        findings.append(Finding("MEDIUM", "Clickjacking", flow.host, flow.url,
            "Falta X-Frame-Options / CSP frame-ancestors — posible clickjacking"))

    if "x-content-type-options" not in resp:
        findings.append(Finding("LOW", "Missing X-Content-Type-Options", flow.host, flow.url,
            "Falta X-Content-Type-Options: nosniff — riesgo de MIME sniffing"))

    if "referrer-policy" not in resp:
        findings.append(Finding("INFO", "Missing Referrer-Policy", flow.host, flow.url,
            "Falta Referrer-Policy"))

    return findings


_SESSION_NAME_RE = re.compile(
    r"^(session|token|auth|jwt|sid|phpsessid|jsessionid|asp\.net_sessionid|"
    r"connect\.sid|remember|csrf|xsrf)", re.I)

def _check_cookies(flow) -> list[Finding]:
    findings = []
    resp = _parse_headers(flow.raw_response)
    for cookie in resp.get("set-cookie", []):
        name = cookie.split("=", 1)[0].strip()
        cl   = cookie.lower()
        is_session = bool(_SESSION_NAME_RE.match(name))

        if "httponly" not in cl:
            sev = "HIGH" if is_session else "MEDIUM"
            findings.append(Finding(sev, "Cookie sin HttpOnly", flow.host, flow.url,
                f"Cookie «{name}» sin HttpOnly — accesible por JavaScript"))

        if flow.use_tls and "secure" not in cl:
            sev = "HIGH" if is_session else "MEDIUM"
            findings.append(Finding(sev, "Cookie sin Secure", flow.host, flow.url,
                f"Cookie «{name}» sin Secure en HTTPS — puede enviarse por HTTP"))

        if "samesite" not in cl:
            findings.append(Finding("LOW", "Cookie sin SameSite", flow.host, flow.url,
                f"Cookie «{name}» sin SameSite — expuesta a CSRF cross-site"))

    return findings


_TRACE_RE = re.compile(
    r"(Traceback \(most recent call last\)|"
    r"at \w[\w.$]+\([\w/\\.-]+:\d+\)|"
    r"System\.Web\.HttpException|"
    r"java\.lang\.\w+Exception|"
    r"PHP (?:Fatal|Parse) error|"
    r"Warning: \w+\(\) (?:expects|called)|"
    r"mysqli?_error\(|"
    r"ORA-\d{5}|"
    r"Microsoft OLE DB Provider|"
    r"#\d+ /\S+\.php\(\d+\))", re.I)

_PATH_RE = re.compile(r"[A-Za-z]:\\[\w\\. ]{6,}|/(?:home|var|usr|etc|opt|srv|root)/[\w/.]{4,}")

def _check_info_disclosure(flow) -> list[Finding]:
    findings = []
    resp = _parse_headers(flow.raw_response)

    for s in resp.get("server", []):
        if re.search(r"\d+\.\d+", s):
            findings.append(Finding("LOW", "Server version disclosure", flow.host, flow.url,
                f"Header Server expone versión: {s}"))

    for h in resp.get("x-powered-by", []):
        findings.append(Finding("LOW", "X-Powered-By disclosure", flow.host, flow.url,
            f"X-Powered-By: {h}"))

    for h in resp.get("x-aspnet-version", []) + resp.get("x-aspnetmvc-version", []):
        findings.append(Finding("LOW", "ASP.NET version disclosure", flow.host, flow.url,
            f"Versión ASP.NET expuesta: {h}"))

    body = _body(flow.raw_response).decode("utf-8", "replace")

    if _TRACE_RE.search(body):
        findings.append(Finding("HIGH", "Stack trace / error disclosure", flow.host, flow.url,
            "Respuesta contiene stack trace o error detallado del servidor"))

    m = _PATH_RE.search(body)
    if m:
        findings.append(Finding("MEDIUM", "Path disclosure", flow.host, flow.url,
            f"Ruta interna expuesta en respuesta: {m.group()[:80]}"))

    return findings


_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY")
_AWS_KEY_RE     = re.compile(r"AKIA[0-9A-Z]{16}")
_SECRET_JSON_RE = re.compile(
    r'"(?:password|passwd|secret|api_key|apikey|api_secret|access_token|'
    r'refresh_token|client_secret|private_key|auth_token)"\s*:\s*"([^"]{4,})"', re.I)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")

def _check_sensitive_data(flow) -> list[Finding]:
    findings = []
    body = _body(flow.raw_response).decode("utf-8", "replace")

    if _PRIVATE_KEY_RE.search(body):
        findings.append(Finding("CRITICAL", "Private key exposed", flow.host, flow.url,
            "Clave privada encontrada en el body de la respuesta"))

    if _AWS_KEY_RE.search(body):
        findings.append(Finding("CRITICAL", "AWS Access Key exposed", flow.host, flow.url,
            "AWS Access Key ID (AKIA…) encontrada en la respuesta"))

    m = _SECRET_JSON_RE.search(body)
    if m:
        findings.append(Finding("HIGH", "Credential in JSON response", flow.host, flow.url,
            f"Campo sensible en JSON: {m.group()[:100]}"))

    if _JWT_RE.search(body):
        findings.append(Finding("MEDIUM", "JWT in response body", flow.host, flow.url,
            "JWT encontrado en el body — verificar si debería estar aquí"))

    return findings


_SENSITIVE_PARAM_RE = re.compile(
    r"[?&](?:password|passwd|pass|pwd|secret|token|api_key|apikey|"
    r"auth|access_token|jwt|key|credential)=([^&\s#]{1,})", re.I)

def _check_sensitive_in_url(flow) -> list[Finding]:
    findings = []
    m = _SENSITIVE_PARAM_RE.search(flow.url)
    if m:
        findings.append(Finding("HIGH", "Sensitive data in URL", flow.host, flow.url,
            f"Parámetro sensible en URL: {m.group()[:80]} — puede quedar en logs"))

    if _JWT_RE.search(flow.path):
        findings.append(Finding("HIGH", "JWT in URL", flow.host, flow.url,
            "JWT encontrado en la URL — quedará en logs del servidor/proxy"))

    return findings


_CSRF_TOKEN_RE = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|"
    r"nonce|state)", re.I)

def _check_csrf(flow) -> list[Finding]:
    method = _method(flow.raw_request)
    if method not in ("POST", "PUT", "PATCH", "DELETE"):
        return []

    req_h = _parse_headers(flow.raw_request)
    ct    = " ".join(req_h.get("content-type", []))
    if "multipart" in ct:
        return []

    body_bytes = _body(flow.raw_request)
    body_str   = body_bytes.decode("utf-8", "replace")

    has_csrf = (
        any(_CSRF_TOKEN_RE.search(h) for h in req_h)
        or bool(_CSRF_TOKEN_RE.search(body_str))
    )
    if not has_csrf:
        return [Finding("MEDIUM", "Posible CSRF", flow.host, flow.url,
            f"{method} sin token CSRF aparente — verificar si el endpoint requiere autenticación")]
    return []


def _check_cors(flow) -> list[Finding]:
    findings = []
    resp = _parse_headers(flow.raw_response)
    acac = any("true" in v.lower() for v in resp.get("access-control-allow-credentials", []))

    for val in resp.get("access-control-allow-origin", []):
        v = val.strip()
        if v == "*":
            findings.append(Finding("MEDIUM", "CORS wildcard (*)", flow.host, flow.url,
                "Access-Control-Allow-Origin: * — cualquier origen puede leer la respuesta"))
        elif v not in ("", "null") and acac:
            findings.append(Finding("HIGH", "CORS + Credentials", flow.host, flow.url,
                f"ACAO: {v} + ACAC: true — posible CORS misconfiguration con credenciales"))
        elif v == "null":
            findings.append(Finding("MEDIUM", "CORS origin null", flow.host, flow.url,
                "ACAO: null — puede ser explotable con iframe sandbox"))

    return findings


def _check_https_downgrade(flow) -> list[Finding]:
    findings = []
    if not flow.use_tls:
        return findings
    resp = _parse_headers(flow.raw_response)
    for loc in resp.get("location", []):
        if loc.strip().lower().startswith("http://"):
            findings.append(Finding("HIGH", "HTTPS → HTTP redirect", flow.host, flow.url,
                f"Redirect de HTTPS a HTTP: {loc.strip()[:100]}"))
    return findings


_SENSITIVE_FORM_RE = re.compile(r'type=["\']?password', re.I)

def _check_cache(flow) -> list[Finding]:
    resp   = _parse_headers(flow.raw_response)
    status = _status(flow.raw_response)
    if status not in range(200, 300):
        return []
    if "html" not in " ".join(resp.get("content-type", [])):
        return []
    body = _body(flow.raw_response).decode("utf-8", "replace")
    if not _SENSITIVE_FORM_RE.search(body):
        return []
    cc     = " ".join(resp.get("cache-control", [])).lower()
    pragma = " ".join(resp.get("pragma", [])).lower()
    if "no-store" not in cc and "no-cache" not in cc and "no-cache" not in pragma:
        return [Finding("LOW", "Sensitive page cacheable", flow.host, flow.url,
            "Página con campo password sin Cache-Control: no-store — puede cachearse")]
    return []


def _check_mixed_content(flow) -> list[Finding]:
    if not flow.use_tls:
        return []
    body = _body(flow.raw_response).decode("utf-8", "replace")
    _MC_RE = re.compile(r'(?:src|href|action)\s*=\s*["\']http://[^"\']+', re.I)
    m = _MC_RE.search(body)
    if m:
        return [Finding("MEDIUM", "Mixed content", flow.host, flow.url,
            f"Recurso HTTP embebido en página HTTPS: {m.group()[:100]}")]
    return []



_CHECKS = [
    _check_security_headers,
    _check_cookies,
    _check_info_disclosure,
    _check_sensitive_data,
    _check_sensitive_in_url,
    _check_csrf,
    _check_cors,
    _check_https_downgrade,
    _check_cache,
    _check_mixed_content,
]

# Checks que se deduplan por (host, check) — nivel de host, no de petición
_HOST_LEVEL_CHECKS = {
    "Missing HSTS", "Missing CSP", "Clickjacking",
    "Missing X-Content-Type-Options", "Missing Referrer-Policy",
    "Server version disclosure", "X-Powered-By disclosure",
    "ASP.NET version disclosure", "CORS wildcard (*)",
}


def analyze_flow(flow) -> list[Finding]:
    if not flow.raw_response:
        return []
    findings = []
    for check in _CHECKS:
        try:
            findings.extend(check(flow))
        except Exception:
            pass
    return findings



class PassiveScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self._findings: list[Finding] = []
        self._seen: set[tuple] = set()
        self._build_ui()


    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # barra superior
        top = QHBoxLayout()
        top.setSpacing(8)

        self._count_lbl = QLabel("0 hallazgos")
        self._count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        top.addWidget(self._count_lbl)

        top.addWidget(QLabel("Severidad:"))
        self._sev_combo = QComboBox()
        self._sev_combo.addItems(["Todos"] + SEVERITY_ORDER)
        self._sev_combo.setFixedWidth(110)
        self._sev_combo.currentTextChanged.connect(self._apply_filter)
        top.addWidget(self._sev_combo)

        top.addStretch()

        self._clear_btn = QPushButton("Limpiar")
        self._clear_btn.clicked.connect(self.clear)
        top.addWidget(self._clear_btn)

        root.addLayout(top)

        # splitter tabla / detalle
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(8)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Severidad", "Check", "Host", "URL", "Detalle"])
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
        self._table.setColumnWidth(1, 210)
        self._table.setColumnWidth(2, 160)
        self._table.setColumnWidth(3, 260)
        self._table.itemSelectionChanged.connect(self._on_selection)
        splitter.addWidget(self._table)

        # detalle req / resp
        det_split = QSplitter(Qt.Horizontal)
        det_split.setHandleWidth(8)
        for attr, title in [("_req_view", "Petición"), ("_resp_view", "Respuesta")]:
            box = QWidget()
            bl  = QVBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(4)
            lbl = QLabel(title)
            lbl.setObjectName("paneCaption")
            bl.addWidget(lbl)
            edit = QPlainTextEdit()
            edit.setFont(MONO)
            edit.setReadOnly(True)
            HTTPHighlighter(edit.document())
            bl.addWidget(edit)
            setattr(self, attr, edit)
            det_split.addWidget(box)

        splitter.addWidget(det_split)
        splitter.setSizes([380, 220])
        root.addWidget(splitter, 1)


    def analyze(self, flow) -> None:
        new_findings = analyze_flow(flow)
        added = False
        for f in new_findings:
            # dedup por host+check para checks de nivel de host
            if f.check in _HOST_LEVEL_CHECKS:
                key = (f.host, f.check)
            else:
                key = (f.host, f.check, f.detail[:60])
            if key in self._seen:
                continue
            self._seen.add(key)
            self._findings.append(f)
            if self._visible(f):
                self._add_row(f)
            added = True
        if added:
            self._update_count()

    def clear(self) -> None:
        self._findings.clear()
        self._seen.clear()
        self._table.setRowCount(0)
        self._req_view.clear()
        self._resp_view.clear()
        self._count_lbl.setText("0 hallazgos")

    def full_refresh(self, flows: list) -> None:
        self.clear()
        for flow in flows:
            self.analyze(flow)


    def _visible(self, f: Finding) -> bool:
        sev = self._sev_combo.currentText()
        return sev == "Todos" or f.severity == sev

    def _apply_filter(self):
        self._table.setRowCount(0)
        for f in self._findings:
            if self._visible(f):
                self._add_row(f)
        self._update_count()

    def _add_row(self, f: Finding):
        row = self._table.rowCount()
        self._table.insertRow(row)
        bg = QColor(_SEV_BG.get(f.severity, "#1e1e2e"))
        fg = QColor(_SEV_FG.get(f.severity, "#dfe3ea"))
        for col, text in enumerate([f.severity, f.check, f.host, f.url, f.detail]):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, f)
            item.setBackground(bg)
            if col == 0:
                item.setForeground(fg)
            self._table.setItem(row, col, item)

    def _on_selection(self):
        items = self._table.selectedItems()
        if not items:
            self._req_view.clear()
            self._resp_view.clear()
            return
        f = items[0].data(Qt.UserRole)
        if f and f.flow:
            self._req_view.setPlainText(decode(f.flow.raw_request))
            self._resp_view.setPlainText(decode_http(f.flow.raw_response))

    def _update_count(self):
        total  = len(self._findings)
        by_sev = {}
        for f in self._findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        parts = [f"{s}: {by_sev[s]}" for s in SEVERITY_ORDER if s in by_sev]
        self._count_lbl.setText(f"{total} hallazgos  —  " + "  /  ".join(parts))
