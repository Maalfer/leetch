from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QDialog, QDialogButtonBox, QFormLayout, QLineEdit, QComboBox,
    QCheckBox, QMessageBox,
)

from ui.style import TEXT_DIM, ACCENT

_GREEN = "#5fd38a"
_AMBER = "#ffb454"

_SCOPE_REQUEST  = "Petición"
_SCOPE_RESPONSE = "Respuesta"
_SCOPE_BOTH     = "Ambos"


class Rule:
    _counter = 0

    def __init__(self, enabled: bool, scope: str, match_type: str,
                 match: str, replace: str):
        Rule._counter += 1
        self.id = Rule._counter
        self.enabled = enabled
        self.scope = scope
        self.match_type = match_type    # "Texto" | "Regex"
        self.match = match
        self.replace = replace


class RuleDialog(QDialog):
    def __init__(self, rule: Rule | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Regla Match & Replace")
        self.setMinimumWidth(520)

        form = QFormLayout(self)
        form.setSpacing(10)
        form.setContentsMargins(16, 16, 16, 16)

        self.scope_combo = QComboBox()
        self.scope_combo.addItems([_SCOPE_REQUEST, _SCOPE_RESPONSE, _SCOPE_BOTH])
        if rule:
            self.scope_combo.setCurrentText(rule.scope)
        form.addRow("Ámbito:", self.scope_combo)

        self.type_combo = QComboBox()
        self.type_combo.addItems(["Texto", "Regex"])
        if rule:
            self.type_combo.setCurrentText(rule.match_type)
        form.addRow("Tipo de búsqueda:", self.type_combo)

        self.match_edit = QLineEdit(rule.match if rule else "")
        self.match_edit.setPlaceholderText(
            "Texto o expresión regular a buscar en la petición/respuesta")
        form.addRow("Buscar:", self.match_edit)

        self.replace_edit = QLineEdit(rule.replace if rule else "")
        self.replace_edit.setPlaceholderText(
            "Texto de reemplazo  (vacío = eliminar la coincidencia)")
        form.addRow("Reemplazar por:", self.replace_edit)

        self.enabled_check = QCheckBox("Regla activa")
        self.enabled_check.setChecked(rule.enabled if rule else True)
        form.addRow("", self.enabled_check)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        form.addRow(btns)

    def _validate(self):
        if not self.match_edit.text().strip():
            QMessageBox.warning(self, "Campo vacío",
                                "El campo 'Buscar' no puede estar vacío.")
            return
        if self.type_combo.currentText() == "Regex":
            try:
                re.compile(self.match_edit.text().encode("utf-8", "replace"))
            except re.error as exc:
                QMessageBox.warning(self, "Regex inválido",
                                    f"Error en la expresión regular:\n{exc}")
                return
        self.accept()

    @property
    def rule_data(self) -> dict:
        return {
            "scope":      self.scope_combo.currentText(),
            "match_type": self.type_combo.currentText(),
            "match":      self.match_edit.text(),
            "replace":    self.replace_edit.text(),
            "enabled":    self.enabled_check.isChecked(),
        }


class MatchReplaceTab(QWidget):
    def __init__(self):
        super().__init__()
        self._rules: list[Rule] = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        desc = QLabel(
            "Las reglas se aplican automáticamente a toda petición/respuesta "
            "que pase por el proxy, en el orden de la tabla.")
        desc.setWordWrap(True)
        desc.setObjectName("paneCaption")
        root.addWidget(desc)

        btn_row = QHBoxLayout()

        add_btn = QPushButton("+ Nueva regla")
        add_btn.setObjectName("primaryButton")
        add_btn.setToolTip("Añadir una nueva regla")
        add_btn.clicked.connect(self._add_rule)
        btn_row.addWidget(add_btn)

        self.edit_btn = QPushButton("Editar")
        self.edit_btn.setEnabled(False)
        self.edit_btn.setToolTip("Editar la regla seleccionada (doble clic)")
        self.edit_btn.clicked.connect(self._edit_rule)
        btn_row.addWidget(self.edit_btn)

        self.del_btn = QPushButton("Eliminar")
        self.del_btn.setEnabled(False)
        self.del_btn.setToolTip("Eliminar la regla seleccionada")
        self.del_btn.clicked.connect(self._del_rule)
        btn_row.addWidget(self.del_btn)

        self.toggle_rule_btn = QPushButton("Activar / Desactivar")
        self.toggle_rule_btn.setEnabled(False)
        self.toggle_rule_btn.setToolTip("Activa o desactiva la regla seleccionada sin eliminarla")
        self.toggle_rule_btn.clicked.connect(self._toggle_rule)
        btn_row.addWidget(self.toggle_rule_btn)

        btn_row.addStretch()

        self._count_label = QLabel("0 reglas")
        self._count_label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        btn_row.addWidget(self._count_label)

        root.addLayout(btn_row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["", "Ámbito", "Tipo", "Buscar", "Reemplazar por"])
        self.table.setAccessibleName("Tabla de reglas Match & Replace")
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        hdr.setHighlightSections(False)
        self.table.setColumnWidth(0, 28)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(2, 80)
        self.table.itemDoubleClicked.connect(lambda _: self._edit_rule())
        self.table.itemSelectionChanged.connect(self._on_selection)
        root.addWidget(self.table, 1)

    def _on_selection(self):
        has = bool(self.table.selectedItems())
        self.edit_btn.setEnabled(has)
        self.del_btn.setEnabled(has)
        self.toggle_rule_btn.setEnabled(has)

    def _selected_row(self) -> int:
        return self.table.currentRow()

    def _add_rule(self):
        dlg = RuleDialog(parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        d = dlg.rule_data
        rule = Rule(enabled=d["enabled"], scope=d["scope"],
                    match_type=d["match_type"],
                    match=d["match"], replace=d["replace"])
        self._rules.append(rule)
        self._insert_row(rule)
        self._refresh_count()

    def _edit_rule(self):
        row = self._selected_row()
        if row < 0 or row >= len(self._rules):
            return
        rule = self._rules[row]
        dlg = RuleDialog(rule, parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        d = dlg.rule_data
        rule.enabled    = d["enabled"]
        rule.scope      = d["scope"]
        rule.match_type = d["match_type"]
        rule.match      = d["match"]
        rule.replace    = d["replace"]
        self._refresh_row(row, rule)

    def _del_rule(self):
        row = self._selected_row()
        if row < 0 or row >= len(self._rules):
            return
        self._rules.pop(row)
        self.table.removeRow(row)
        self._refresh_count()

    def _toggle_rule(self):
        row = self._selected_row()
        if row < 0 or row >= len(self._rules):
            return
        rule = self._rules[row]
        rule.enabled = not rule.enabled
        self._refresh_row(row, rule)

    def _insert_row(self, rule: Rule):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self._refresh_row(row, rule)

    def _refresh_row(self, row: int, rule: Rule):
        dot = QTableWidgetItem("●" if rule.enabled else "○")
        dot.setTextAlignment(Qt.AlignCenter)
        dot.setForeground(QColor(_GREEN) if rule.enabled else QColor(TEXT_DIM))
        self.table.setItem(row, 0, dot)
        self.table.setItem(row, 1, QTableWidgetItem(rule.scope))
        self.table.setItem(row, 2, QTableWidgetItem(rule.match_type))
        self.table.setItem(row, 3, QTableWidgetItem(rule.match))
        replace_display = rule.replace if rule.replace else "(vacío — eliminar)"
        item4 = QTableWidgetItem(replace_display)
        if not rule.replace:
            item4.setForeground(QColor(TEXT_DIM))
        self.table.setItem(row, 4, item4)

    def _refresh_count(self):
        n = len(self._rules)
        active = sum(1 for r in self._rules if r.enabled)
        self._count_label.setText(
            f"{n} regla{'s' if n != 1 else ''}  ({active} activa{'s' if active != 1 else ''})")

    def apply_to_request(self, raw: bytes) -> bytes:
        for rule in list(self._rules):
            if not rule.enabled or rule.scope not in (_SCOPE_REQUEST, _SCOPE_BOTH):
                continue
            raw = _apply_rule(raw, rule)
        return raw

    def apply_to_response(self, raw: bytes) -> bytes:
        for rule in list(self._rules):
            if not rule.enabled or rule.scope not in (_SCOPE_RESPONSE, _SCOPE_BOTH):
                continue
            raw = _apply_rule(raw, rule)
        return raw

    def open_new_rule_dialog(self):
        self._add_rule()


def _apply_rule(raw: bytes, rule: Rule) -> bytes:
    try:
        match_b   = rule.match.encode("utf-8", "replace")
        replace_b = rule.replace.encode("utf-8", "replace")
        if rule.match_type == "Regex":
            return re.sub(match_b, replace_b, raw)
        return raw.replace(match_b, replace_b)
    except Exception:
        return raw
