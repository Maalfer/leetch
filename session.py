"""(De)serialización de la sesión de MiniBurp.

Formato del archivo (JSON):

    {
        "format": "miniburp_session",
        "version": 1,
        "proxy": {"listen_host": "127.0.0.1", "listen_port": 8080},
        "flows": [ { ... }, ... ],
        "repeater": [ { ... }, ... ]
    }
"""
from __future__ import annotations

import base64
import json

from proxy.flow import Flow

SESSION_FORMAT = "miniburp_session"
SESSION_VERSION = 1


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data or b"").decode("ascii")


def _b64decode(text: str) -> bytes:
    if not text:
        return b""
    return base64.b64decode(text.encode("ascii"))


def _flow_to_dict(flow: Flow) -> dict:
    return {
        "id": flow.id,
        "method": flow.method,
        "host": flow.host,
        "port": flow.port,
        "scheme": flow.scheme,
        "path": flow.path,
        "status": flow.status,
        "use_tls": flow.use_tls,
        "timestamp": flow.timestamp,
        "raw_request": _b64encode(flow.raw_request),
        "raw_response": _b64encode(flow.raw_response),
    }


def _flow_from_dict(d: dict) -> Flow:
    return Flow(
        id=int(d.get("id", 0)),
        method=d.get("method", ""),
        host=d.get("host", ""),
        port=int(d.get("port", 0)),
        scheme=d.get("scheme", "http"),
        path=d.get("path", "/"),
        raw_request=_b64decode(d.get("raw_request", "")),
        raw_response=_b64decode(d.get("raw_response", "")),
        status=d.get("status", ""),
        use_tls=bool(d.get("use_tls", False)),
        timestamp=float(d.get("timestamp", 0.0)),
    )


def session_to_dict(window) -> dict:
    """Construye el dict serializable a partir de la ventana principal."""
    repeater = []
    rep_tabs = window.repeater_tabs
    for i in range(rep_tabs.count()):
        tab = rep_tabs.widget(i)
        if not hasattr(tab, "request_edit"):
            continue
        repeater.append({
            "host": tab.host_edit.text(),
            "port": tab.port_spin.value(),
            "use_tls": tab.tls_check.isChecked(),
            "request": tab.request_edit.toPlainText(),
            "response": tab.response_view.toPlainText(),
        })

    return {
        "format": SESSION_FORMAT,
        "version": SESSION_VERSION,
        "proxy": {
            "listen_host": window.listen_host.text(),
            "listen_port": window.listen_port.value(),
        },
        "flows": [_flow_to_dict(f) for f in window.flows],
        "repeater": repeater,
    }


def restore_session(window, data: dict) -> None:
    """Restaura el estado en la ventana a partir de un dict de sesión."""
    if not isinstance(data, dict):
        raise ValueError("El archivo no contiene una sesión válida.")
    if data.get("format") != SESSION_FORMAT:
        raise ValueError("El archivo no es una sesión de MiniBurp.")
    version = data.get("version")
    if version != SESSION_VERSION:
        raise ValueError(f"Versión de sesión no soportada: {version!r}.")

    proxy = data.get("proxy", {}) or {}
    host = proxy.get("listen_host")
    if host is not None:
        window.listen_host.setText(str(host))
    port = proxy.get("listen_port")
    if port is not None:
        try:
            window.listen_port.setValue(int(port))
        except (TypeError, ValueError):
            pass

    window.flows.clear()
    window._flow_by_id.clear()
    window.table.setRowCount(0)
    for fd in data.get("flows", []) or []:
        window.add_flow(_flow_from_dict(fd))

    max_id = max((f.id for f in window.flows), default=0)
    if getattr(window, "proxy", None) is not None:
        try:
            if window.proxy._counter < max_id:
                window.proxy._counter = max_id
        except AttributeError:
            pass

    rep_tabs = window.repeater_tabs
    while rep_tabs.count():
        w = rep_tabs.widget(0)
        rep_tabs.removeTab(0)
        if w is not None:
            w.deleteLater()

    for rd in data.get("repeater", []) or []:
        request_text = rd.get("request", "")
        tab = window.add_repeater_tab()
        tab.host_edit.setText(str(rd.get("host", "")))
        try:
            tab.port_spin.setValue(int(rd.get("port", 80)))
        except (TypeError, ValueError):
            pass
        tab.tls_check.setChecked(bool(rd.get("use_tls", False)))
        tab.request_edit.setPlainText(request_text)
        response_text = rd.get("response", "")
        if response_text:
            tab.response_view.setPlainText(response_text)
        host = rd.get("host", "")
        if host:
            rep_tabs.setTabText(rep_tabs.indexOf(tab), host[:25])

    if rep_tabs.count() == 0:
        window.add_repeater_tab()


def save_session_to_file(window, path: str) -> None:
    data = session_to_dict(window)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_session_from_file(window, path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    restore_session(window, data)
