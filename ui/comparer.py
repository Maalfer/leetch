from __future__ import annotations

import difflib
import html as _html
from itertools import zip_longest

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QPlainTextEdit, QTextEdit,
    QComboBox, QApplication, QFrame,
)

from ui.style import MONO, TEXT, TEXT_DIM, BG_DEEP, BG_PANEL, BG_BASE, BORDER

_BG_DEL      = "rgba(255,107,107,0.22)"   # rojo   — solo en A
_BG_INS      = "rgba(95,211,138,0.22)"    # verde  — solo en B
_BG_MOD      = "rgba(255,180,84,0.22)"    # ámbar  — diferente en ambos
_BG_EMPTY    = "rgba(0,0,0,0.35)"         # placeholder (línea vacía de relleno)
_HL_DEL      = "rgba(255,107,107,0.55)"   # word highlight en A
_HL_INS      = "rgba(95,211,138,0.55)"    # word highlight en B
_HL_MOD_A    = "rgba(255,180,84,0.60)"    # word highlight ámbar en A
_HL_MOD_B    = "rgba(255,180,84,0.60)"    # word highlight ámbar en B


def _esc(text: str) -> str:
    return _html.escape(text, quote=False)


def _span(text: str, bg: str = "", extra_css: str = "") -> str:
    css = f"background-color:{bg};" if bg else ""
    css += extra_css
    if css:
        return f'<span style="{css}">{_esc(text)}</span>'
    return _esc(text)


def _line_html(text: str, bg: str) -> str:
    style = f"display:block;white-space:pre;background-color:{bg};" if bg else "display:block;white-space:pre;"
    return f'<div style="{style}">{_esc(text) or "&nbsp;"}</div>'


def _word_diff_html(a: str, b: str) -> tuple[str, str]:
    def tokenize(s: str) -> list[str]:
        tokens, cur = [], []
        for ch in s:
            if ch in " \t,:;()[]{}\"'=&|<>!?/\\@#%^*~`":
                if cur:
                    tokens.append("".join(cur))
                    cur = []
                tokens.append(ch)
            else:
                cur.append(ch)
        if cur:
            tokens.append("".join(cur))
        return tokens

    ta, tb = tokenize(a.rstrip("\n")), tokenize(b.rstrip("\n"))
    sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
    out_a, out_b = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        chunk_a = "".join(ta[i1:i2])
        chunk_b = "".join(tb[j1:j2])
        if tag == "equal":
            out_a.append(_esc(chunk_a))
            out_b.append(_esc(chunk_b))
        elif tag == "replace":
            out_a.append(_span(chunk_a, _HL_MOD_A))
            out_b.append(_span(chunk_b, _HL_MOD_B))
        elif tag == "delete":
            out_a.append(_span(chunk_a, _HL_DEL))
        elif tag == "insert":
            out_b.append(_span(chunk_b, _HL_INS))

    def wrap(parts: list[str], bg: str) -> str:
        inner = "".join(parts) or "&nbsp;"
        return f'<div style="display:block;white-space:pre;background-color:{bg};">{inner}</div>'

    return wrap(out_a, _BG_MOD), wrap(out_b, _BG_MOD)


def _build_diff_html(text_a: str, text_b: str,
                     mode: str) -> tuple[str, str, dict]:
    lines_a = text_a.splitlines(keepends=True)
    lines_b = text_b.splitlines(keepends=True)

    sm = difflib.SequenceMatcher(None, lines_a, lines_b, autojunk=False)
    opcodes = sm.get_opcodes()

    parts_a: list[str] = []
    parts_b: list[str] = []
    stats = {"equal": 0, "modified": 0, "deleted": 0, "inserted": 0}

    for tag, i1, i2, j1, j2 in opcodes:
        chunk_a = lines_a[i1:i2]
        chunk_b = lines_b[j1:j2]

        if tag == "equal":
            for la in chunk_a:
                parts_a.append(_line_html(la.rstrip("\n"), ""))
                parts_b.append(_line_html(la.rstrip("\n"), ""))
                stats["equal"] += 1

        elif tag == "replace":
            stats["modified"] += max(len(chunk_a), len(chunk_b))
            if mode == "words":
                for la, lb in zip_longest(chunk_a, chunk_b, fillvalue=""):
                    if la and lb:
                        ha, hb = _word_diff_html(la, lb)
                        parts_a.append(ha)
                        parts_b.append(hb)
                    elif la:
                        parts_a.append(_line_html(la.rstrip("\n"), _BG_DEL))
                        parts_b.append(_line_html("", _BG_EMPTY))
                    else:
                        parts_a.append(_line_html("", _BG_EMPTY))
                        parts_b.append(_line_html(lb.rstrip("\n"), _BG_INS))
            else:  # lines
                for la, lb in zip_longest(chunk_a, chunk_b, fillvalue=""):
                    if la and lb:
                        parts_a.append(_line_html(la.rstrip("\n"), _BG_MOD))
                        parts_b.append(_line_html(lb.rstrip("\n"), _BG_MOD))
                    elif la:
                        parts_a.append(_line_html(la.rstrip("\n"), _BG_DEL))
                        parts_b.append(_line_html("", _BG_EMPTY))
                    else:
                        parts_a.append(_line_html("", _BG_EMPTY))
                        parts_b.append(_line_html(lb.rstrip("\n"), _BG_INS))

        elif tag == "delete":
            stats["deleted"] += len(chunk_a)
            for la in chunk_a:
                parts_a.append(_line_html(la.rstrip("\n"), _BG_DEL))
                parts_b.append(_line_html("", _BG_EMPTY))

        elif tag == "insert":
            stats["inserted"] += len(chunk_b)
            for lb in chunk_b:
                parts_a.append(_line_html("", _BG_EMPTY))
                parts_b.append(_line_html(lb.rstrip("\n"), _BG_INS))

    pre_style = (
        f"margin:0;padding:4px;font-family:'{MONO.family()}',monospace;"
        f"font-size:{MONO.pointSize()}pt;color:{TEXT};"
        f"background-color:{BG_DEEP};line-height:1.4;"
    )
    html_a = f'<pre style="{pre_style}">{"".join(parts_a)}</pre>'
    html_b = f'<pre style="{pre_style}">{"".join(parts_b)}</pre>'
    return html_a, html_b, stats


class _DiffView(QTextEdit):
    def __init__(self, label: str):
        super().__init__()
        self.setFont(MONO)
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.NoWrap)
        self.setObjectName("terminalOutput")
        self._sync_target: _DiffView | None = None
        self._syncing = False
        self.verticalScrollBar().valueChanged.connect(self._on_scroll)

    def set_sync(self, other: "_DiffView") -> None:
        self._sync_target = other

    def _on_scroll(self, value: int) -> None:
        if self._syncing or self._sync_target is None:
            return
        self._sync_target._syncing = True
        self._sync_target.verticalScrollBar().setValue(value)
        self._sync_target._syncing = False


class ComparerTab(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def load_a(self, text: str) -> None:
        self._edit_a.setPlainText(text)
        self._lbl_a.setText("Texto A  ·  cargado")

    def load_b(self, text: str) -> None:
        self._edit_b.setPlainText(text)
        self._lbl_b.setText("Texto B  ·  cargado")

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        ctrl = QFrame()
        ctrl.setObjectName("controlBar")
        ctrl_lay = QHBoxLayout(ctrl)
        ctrl_lay.setContentsMargins(12, 8, 12, 8)
        ctrl_lay.setSpacing(10)

        ctrl_lay.addWidget(QLabel("Modo:"))
        self._mode_combo = QComboBox()
        self._mode_combo.addItems(["Palabras", "Líneas"])
        self._mode_combo.setToolTip(
            "Palabras: resalta diferencias a nivel de token dentro de cada línea\n"
            "Líneas: resalta líneas completas sin desglosar palabras")
        self._mode_combo.setFixedWidth(110)
        ctrl_lay.addWidget(self._mode_combo)

        cmp_btn = QPushButton("Comparar")
        cmp_btn.setObjectName("primaryButton")
        cmp_btn.setCursor(Qt.PointingHandCursor)
        cmp_btn.setToolTip("Muestra el diff entre Texto A y Texto B")
        cmp_btn.clicked.connect(self._compare)
        ctrl_lay.addWidget(cmp_btn)

        clr_btn = QPushButton("Limpiar todo")
        clr_btn.setCursor(Qt.PointingHandCursor)
        clr_btn.clicked.connect(self._clear_all)
        ctrl_lay.addWidget(clr_btn)

        ctrl_lay.addStretch()

        for hex_color, label in [("#ff6b6b", "Solo en A"), ("#5fd38a", "Solo en B"),
                                  ("#ffb454", "Modificado")]:
            dot = QLabel("  ●  ")
            dot.setStyleSheet(f"color: {hex_color};")
            ctrl_lay.addWidget(dot)
            ctrl_lay.addWidget(QLabel(label))

        self._stats_lbl = QLabel("")
        self._stats_lbl.setObjectName("paneCaption")
        ctrl_lay.addWidget(self._stats_lbl)

        root.addWidget(ctrl)

        input_split = QSplitter(Qt.Horizontal)
        input_split.setHandleWidth(8)

        for side in ("a", "b"):
            box = QWidget()
            bl = QVBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(4)

            hdr = QHBoxLayout()
            lbl = QLabel(f"Texto {'A' if side == 'a' else 'B'}")
            lbl.setObjectName("paneCaption")
            hdr.addWidget(lbl)
            hdr.addStretch()

            paste_btn = QPushButton("Pegar")
            paste_btn.setFixedHeight(22)
            paste_btn.setCursor(Qt.PointingHandCursor)
            paste_btn.setToolTip("Pega el contenido del portapapeles")

            clear_btn = QPushButton("Limpiar")
            clear_btn.setFixedHeight(22)
            clear_btn.setCursor(Qt.PointingHandCursor)

            hdr.addWidget(paste_btn)
            hdr.addWidget(clear_btn)
            bl.addLayout(hdr)

            edit = QPlainTextEdit()
            edit.setFont(MONO)
            edit.setPlaceholderText(
                "Pega aquí el texto a comparar, o usa\n"
                "«Enviar al Comparer» desde el HTTP History…")
            bl.addWidget(edit)
            input_split.addWidget(box)

            if side == "a":
                self._lbl_a = lbl
                self._edit_a = edit
                paste_btn.clicked.connect(
                    lambda: self._edit_a.setPlainText(QApplication.clipboard().text()))
                clear_btn.clicked.connect(self._edit_a.clear)
            else:
                self._lbl_b = lbl
                self._edit_b = edit
                paste_btn.clicked.connect(
                    lambda: self._edit_b.setPlainText(QApplication.clipboard().text()))
                clear_btn.clicked.connect(self._edit_b.clear)

        input_split.setSizes([500, 500])

        result_widget = QWidget()
        rl = QVBoxLayout(result_widget)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)

        res_hdr = QHBoxLayout()
        res_lbl = QLabel("Resultado")
        res_lbl.setObjectName("paneCaption")
        res_hdr.addWidget(res_lbl)
        res_hdr.addStretch()
        rl.addLayout(res_hdr)

        diff_split = QSplitter(Qt.Horizontal)
        diff_split.setHandleWidth(4)

        self._diff_a = _DiffView("A")
        self._diff_b = _DiffView("B")
        self._diff_a.set_sync(self._diff_b)
        self._diff_b.set_sync(self._diff_a)

        for view, title in [(self._diff_a, "A"), (self._diff_b, "B")]:
            wrap = QWidget()
            wl = QVBoxLayout(wrap)
            wl.setContentsMargins(0, 0, 0, 0)
            wl.setSpacing(2)
            cap = QLabel(title)
            cap.setObjectName("paneCaption")
            wl.addWidget(cap)
            wl.addWidget(view)
            diff_split.addWidget(wrap)

        diff_split.setSizes([500, 500])
        rl.addWidget(diff_split)

        vsplit = QSplitter(Qt.Vertical)
        vsplit.setHandleWidth(8)
        vsplit.addWidget(input_split)
        vsplit.addWidget(result_widget)
        vsplit.setSizes([280, 400])
        root.addWidget(vsplit, 1)

        self._show_placeholder()

    def _compare(self):
        text_a = self._edit_a.toPlainText()
        text_b = self._edit_b.toPlainText()

        if not text_a and not text_b:
            self._show_placeholder()
            return

        mode = "words" if self._mode_combo.currentText() == "Palabras" else "lines"
        html_a, html_b, stats = _build_diff_html(text_a, text_b, mode)

        self._diff_a.setHtml(html_a)
        self._diff_b.setHtml(html_b)

        parts = []
        if stats["equal"]:
            parts.append(f"{stats['equal']} iguales")
        if stats["modified"]:
            parts.append(f"{stats['modified']} modificadas")
        if stats["deleted"]:
            parts.append(f"{stats['deleted']} solo en A")
        if stats["inserted"]:
            parts.append(f"{stats['inserted']} solo en B")
        self._stats_lbl.setText("  ·  ".join(parts) if parts else "Sin diferencias")

    def _clear_all(self):
        self._edit_a.clear()
        self._edit_b.clear()
        self._lbl_a.setText("Texto A")
        self._lbl_b.setText("Texto B")
        self._show_placeholder()
        self._stats_lbl.setText("")

    def _show_placeholder(self):
        msg = (
            f'<p style="color:{TEXT_DIM};font-family:{MONO.family()},monospace;'
            f'font-size:{MONO.pointSize()}pt;padding:20px;">'
            "Pega texto en los paneles A y B y pulsa <b>Comparar</b>."
            "</p>"
        )
        self._diff_a.setHtml(msg)
        self._diff_b.setHtml(msg)
