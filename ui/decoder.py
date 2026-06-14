"""Pestaña Decoder para Leetch.

Transformaciones encadenables (Base64, URL, HTML, Hex, hashes) y
JWT Inspector con detección de alg:none y re-firma HS256.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import re as _re
import urllib.parse
from html import escape as _html_esc, unescape as _html_unesc
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTabWidget,
    QVBoxLayout, QWidget,
)

from ui.style import MONO
from ui.highlighter import JSONHighlighter


# ── Transformaciones ──────────────────────────────────────────────────────────
def _pad(s: bytes) -> bytes:
    return s + b"=" * ((4 - len(s) % 4) % 4)


_OPS: dict[str, tuple[Callable, Callable | None]] = {
    "Base64": (
        lambda d: base64.b64encode(d),
        lambda d: base64.b64decode(_pad(d.replace(b" ", b"").replace(b"\n", b""))),
    ),
    "Base64 URL-safe": (
        lambda d: base64.urlsafe_b64encode(d).rstrip(b"="),
        lambda d: base64.urlsafe_b64decode(_pad(d)),
    ),
    "URL (completa)": (
        lambda d: urllib.parse.quote(d.decode("utf-8", "replace"), safe="").encode(),
        lambda d: urllib.parse.unquote_to_bytes(d),
    ),
    "URL (componente)": (
        lambda d: urllib.parse.quote_plus(d.decode("utf-8", "replace")).encode(),
        lambda d: urllib.parse.unquote_plus(d.decode("utf-8", "replace")).encode(),
    ),
    "HTML": (
        lambda d: _html_esc(d.decode("utf-8", "replace"), quote=True).encode(),
        lambda d: _html_unesc(d.decode("utf-8", "replace")).encode(),
    ),
    "Hex": (
        lambda d: d.hex().encode(),
        lambda d: bytes.fromhex(d.decode("ascii", "replace").strip()),
    ),
    "MD5":    (lambda d: hashlib.md5(d).hexdigest().encode(), None),
    "SHA-1":  (lambda d: hashlib.sha1(d).hexdigest().encode(), None),
    "SHA-256": (lambda d: hashlib.sha256(d).hexdigest().encode(), None),
    "SHA-512": (lambda d: hashlib.sha512(d).hexdigest().encode(), None),
}

_HASH_OPS = {"MD5", "SHA-1", "SHA-256", "SHA-512"}


def _apply_op(data: bytes, op_name: str, encode: bool) -> bytes:
    fn_enc, fn_dec = _OPS[op_name]
    if encode:
        return fn_enc(data)
    if fn_dec is None:
        raise ValueError(f"'{op_name}' no soporta decodificación")
    return fn_dec(data)


# ── Widget de un paso ─────────────────────────────────────────────────────────
class _StepRow(QFrame):
    def __init__(self, number: int, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(6)

        self._num = QLabel(f"{number}.")
        self._num.setFixedWidth(22)
        layout.addWidget(self._num)

        self.op_combo = QComboBox()
        self.op_combo.addItems(list(_OPS.keys()))
        self.op_combo.setMinimumWidth(165)
        self.op_combo.currentTextChanged.connect(self._on_op_changed)
        layout.addWidget(self.op_combo)

        self.dir_combo = QComboBox()
        self.dir_combo.addItems(["Decodificar", "Codificar"])
        layout.addWidget(self.dir_combo)
        layout.addStretch()

    def _on_op_changed(self, op: str) -> None:
        if op in _HASH_OPS:
            self.dir_combo.setCurrentIndex(1)
            self.dir_combo.setEnabled(False)
        else:
            self.dir_combo.setEnabled(True)

    @property
    def op_name(self) -> str:
        return self.op_combo.currentText()

    @property
    def encode(self) -> bool:
        return self.dir_combo.currentIndex() == 1


# ── Pestaña Transformar ───────────────────────────────────────────────────────
class _TransformTab(QWidget):
    def __init__(self):
        super().__init__()
        self._steps: list[_StepRow] = []
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Entrada
        in_hdr = QHBoxLayout()
        in_lbl = QLabel("Entrada")
        in_lbl.setObjectName("paneCaption")
        in_hdr.addWidget(in_lbl)
        in_hdr.addStretch()
        clear_btn = QPushButton("Limpiar")
        clear_btn.clicked.connect(lambda: self.input_edit.clear())
        in_hdr.addWidget(clear_btn)
        root.addLayout(in_hdr)

        self.input_edit = QPlainTextEdit()
        self.input_edit.setFont(MONO)
        self.input_edit.setFixedHeight(100)
        self.input_edit.setPlaceholderText("Pega aquí el texto a transformar…")
        root.addWidget(self.input_edit)

        # Pasos
        steps_hdr = QHBoxLayout()
        steps_lbl = QLabel("Pasos encadenados")
        steps_lbl.setObjectName("paneCaption")
        steps_hdr.addWidget(steps_lbl)
        steps_hdr.addStretch()
        add_btn = QPushButton("+ Añadir paso")
        add_btn.clicked.connect(self._add_step)
        steps_hdr.addWidget(add_btn)
        rem_btn = QPushButton("− Quitar")
        rem_btn.clicked.connect(self._remove_step)
        steps_hdr.addWidget(rem_btn)
        root.addLayout(steps_hdr)

        self._steps_container = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_container)
        self._steps_layout.setContentsMargins(0, 0, 0, 0)
        self._steps_layout.setSpacing(2)
        root.addWidget(self._steps_container)

        self._add_step()

        # Botones
        btn_row = QHBoxLayout()
        apply_btn = QPushButton("▶  Aplicar")
        apply_btn.setObjectName("primaryButton")
        apply_btn.clicked.connect(self._apply)
        btn_row.addWidget(apply_btn)
        btn_row.addStretch()
        swap_btn = QPushButton("↕  Usar salida como entrada")
        swap_btn.setToolTip("Mueve el resultado al campo de entrada para seguir encadenando")
        swap_btn.clicked.connect(self._swap)
        btn_row.addWidget(swap_btn)
        root.addLayout(btn_row)

        self.err_label = QLabel()
        self.err_label.setStyleSheet("color: #ff6b6b;")
        self.err_label.setVisible(False)
        root.addWidget(self.err_label)

        # Salida
        out_hdr = QHBoxLayout()
        out_lbl = QLabel("Resultado")
        out_lbl.setObjectName("paneCaption")
        out_hdr.addWidget(out_lbl)
        out_hdr.addStretch()
        copy_btn = QPushButton("Copiar")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(
            self.output_edit.toPlainText()))
        out_hdr.addWidget(copy_btn)
        root.addLayout(out_hdr)

        self.output_edit = QPlainTextEdit()
        self.output_edit.setFont(MONO)
        self.output_edit.setReadOnly(True)
        root.addWidget(self.output_edit, 1)

    def _add_step(self) -> None:
        step = _StepRow(len(self._steps) + 1)
        self._steps_layout.addWidget(step)
        self._steps.append(step)

    def _remove_step(self) -> None:
        if not self._steps:
            return
        step = self._steps.pop()
        self._steps_layout.removeWidget(step)
        step.deleteLater()

    def _apply(self) -> None:
        self.err_label.setVisible(False)
        data = self.input_edit.toPlainText().encode("utf-8")
        try:
            for step in self._steps:
                data = _apply_op(data, step.op_name, step.encode)
        except Exception as exc:
            self.err_label.setText(f"Error: {exc}")
            self.err_label.setVisible(True)
            return
        try:
            result = data.decode("utf-8")
        except UnicodeDecodeError:
            result = data.hex()
        self.output_edit.setPlainText(result)

    def _swap(self) -> None:
        self.input_edit.setPlainText(self.output_edit.toPlainText())

    def load_text(self, text: str) -> None:
        self.input_edit.setPlainText(text)
        self.output_edit.clear()
        self.err_label.setVisible(False)


# ── JWT Inspector ─────────────────────────────────────────────────────────────
_JWT_RE = _re.compile(
    r'^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$')


def _b64url_dec(s: str) -> bytes:
    pad = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def _b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class _JWTTab(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Token input
        tok_hdr = QHBoxLayout()
        tok_lbl = QLabel("Token JWT")
        tok_lbl.setObjectName("paneCaption")
        tok_hdr.addWidget(tok_lbl)
        tok_hdr.addStretch()
        parse_btn = QPushButton("Analizar")
        parse_btn.setObjectName("primaryButton")
        parse_btn.clicked.connect(self._parse)
        tok_hdr.addWidget(parse_btn)
        root.addLayout(tok_hdr)

        self.token_edit = QPlainTextEdit()
        self.token_edit.setFont(MONO)
        self.token_edit.setFixedHeight(70)
        self.token_edit.setPlaceholderText("Pega el JWT aquí (eyJ…)")
        root.addWidget(self.token_edit)

        self.warn_label = QLabel()
        self.warn_label.setWordWrap(True)
        self.warn_label.setVisible(False)
        root.addWidget(self.warn_label)

        # Tres paneles: Header | Payload | Firma
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(8)

        for attr, title, editable in [
            ("header_edit",  "Header (editable)",   True),
            ("payload_edit", "Payload (editable)",  True),
            ("sig_edit",     "Firma (base64url)",   False),
        ]:
            box = QWidget()
            bl = QVBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(4)
            lbl = QLabel(title)
            lbl.setObjectName("paneCaption")
            bl.addWidget(lbl)
            edit = QPlainTextEdit()
            edit.setFont(MONO)
            edit.setReadOnly(not editable)
            if editable:
                JSONHighlighter(edit.document())
            bl.addWidget(edit)
            setattr(self, attr, edit)
            splitter.addWidget(box)

        root.addWidget(splitter, 1)

        # Controles de re-firma / ataque
        attack_row = QHBoxLayout()
        attack_row.setSpacing(8)
        attack_row.addWidget(QLabel("Secreto:"))
        self.secret_edit = QLineEdit()
        self.secret_edit.setPlaceholderText("secret")
        self.secret_edit.setFixedWidth(180)
        attack_row.addWidget(self.secret_edit)

        resign_btn = QPushButton("Re-firmar HS256")
        resign_btn.setToolTip("Re-firma el JWT editado con HS256 y el secreto indicado")
        resign_btn.clicked.connect(self._resign_hs256)
        attack_row.addWidget(resign_btn)

        none_btn = QPushButton("Ataque alg:none")
        none_btn.setToolTip(
            "Genera JWT con alg:none y firma vacía.\n"
            "Servidores vulnerables lo aceptan sin verificar la firma.")
        none_btn.clicked.connect(self._attack_alg_none)
        attack_row.addWidget(none_btn)

        attack_row.addStretch()
        copy_btn = QPushButton("Copiar JWT resultado")
        copy_btn.clicked.connect(self._copy_result)
        attack_row.addWidget(copy_btn)
        root.addLayout(attack_row)

        self.result_edit = QLineEdit()
        self.result_edit.setFont(MONO)
        self.result_edit.setReadOnly(True)
        self.result_edit.setPlaceholderText("El JWT modificado aparecerá aquí…")
        root.addWidget(self.result_edit)

    # ── Parseo ────────────────────────────────────────────────────────────
    def _parse(self) -> None:
        token = self.token_edit.toPlainText().strip()
        m = _JWT_RE.match(token)
        if not m:
            self._warn(
                "⚠ No es un JWT válido (necesita 3 segmentos separados por '.')",
                "#ffb454")
            return

        h_raw, p_raw, s_raw = m.group(1), m.group(2), m.group(3)

        for raw, edit in [(h_raw, self.header_edit), (p_raw, self.payload_edit)]:
            try:
                obj = json.loads(_b64url_dec(raw))
                edit.setPlainText(json.dumps(obj, indent=2, ensure_ascii=False))
            except Exception as exc:
                edit.setPlainText(f"[Error: {exc}]")

        self.sig_edit.setPlainText(
            s_raw if s_raw else "(vacía — posible alg:none)")

        try:
            hdr = json.loads(_b64url_dec(h_raw))
            alg = str(hdr.get("alg", "")).lower()
            if alg in ("none", ""):
                self._warn(
                    "⚠ VULNERABLE: alg:none — Token sin firma. "
                    "El servidor podría aceptar payloads arbitrarios sin verificación.",
                    "#ff6b6b", bold=True)
            else:
                self._warn(
                    f"✓ Algoritmo: {hdr.get('alg', '?')}  ·  Token analizado correctamente",
                    "#5fd38a")
        except Exception:
            pass

    def _warn(self, msg: str, color: str, bold: bool = False) -> None:
        weight = "bold" if bold else "normal"
        self.warn_label.setStyleSheet(
            f"color: {color}; font-weight: {weight};")
        self.warn_label.setText(msg)
        self.warn_label.setVisible(True)

    # ── Generación ────────────────────────────────────────────────────────
    def _get_enc_parts(self) -> tuple[str, str] | None:
        try:
            hdr = json.loads(self.header_edit.toPlainText())
            pay = json.loads(self.payload_edit.toPlainText())
        except json.JSONDecodeError as exc:
            QMessageBox.warning(self, "JSON inválido", str(exc))
            return None
        hdr_enc = _b64url_enc(
            json.dumps(hdr, separators=(",", ":"), ensure_ascii=False).encode())
        pay_enc = _b64url_enc(
            json.dumps(pay, separators=(",", ":"), ensure_ascii=False).encode())
        return hdr_enc, pay_enc

    def _resign_hs256(self) -> None:
        try:
            hdr = json.loads(self.header_edit.toPlainText())
            pay = json.loads(self.payload_edit.toPlainText())
        except json.JSONDecodeError as exc:
            QMessageBox.warning(self, "JSON inválido", str(exc))
            return
        hdr["alg"] = "HS256"
        hdr_enc = _b64url_enc(
            json.dumps(hdr, separators=(",", ":"), ensure_ascii=False).encode())
        pay_enc = _b64url_enc(
            json.dumps(pay, separators=(",", ":"), ensure_ascii=False).encode())
        signing_input = f"{hdr_enc}.{pay_enc}".encode()
        secret = self.secret_edit.text().encode("utf-8")
        sig = _hmac.new(secret, signing_input, hashlib.sha256).digest()
        self.result_edit.setText(f"{hdr_enc}.{pay_enc}.{_b64url_enc(sig)}")

    def _attack_alg_none(self) -> None:
        try:
            hdr = json.loads(self.header_edit.toPlainText())
            pay = json.loads(self.payload_edit.toPlainText())
        except json.JSONDecodeError as exc:
            QMessageBox.warning(self, "JSON inválido", str(exc))
            return
        hdr["alg"] = "none"
        hdr_enc = _b64url_enc(
            json.dumps(hdr, separators=(",", ":"), ensure_ascii=False).encode())
        pay_enc = _b64url_enc(
            json.dumps(pay, separators=(",", ":"), ensure_ascii=False).encode())
        self.result_edit.setText(f"{hdr_enc}.{pay_enc}.")

    def _copy_result(self) -> None:
        t = self.result_edit.text()
        if t:
            QApplication.clipboard().setText(t)

    def load_text(self, text: str) -> None:
        self.token_edit.setPlainText(text.strip())
        self._parse()


# ── Pestaña principal ─────────────────────────────────────────────────────────
class DecoderTab(QWidget):
    """Decoder + JWT Inspector para Leetch."""

    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self._inner = QTabWidget()
        root.addWidget(self._inner)

        self._transform = _TransformTab()
        self._inner.addTab(self._transform, "Transformar")

        self._jwt = _JWTTab()
        self._inner.addTab(self._jwt, "JWT Inspector")

    def load_text(self, text: str) -> None:
        """Carga texto en la pestaña de transformación."""
        self._transform.load_text(text)
        self._inner.setCurrentIndex(0)

    def load_jwt(self, token: str) -> None:
        """Carga y analiza un JWT directamente."""
        self._jwt.load_text(token)
        self._inner.setCurrentIndex(1)
