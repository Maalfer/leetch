from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QPushButton,
    QSplitter, QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from proxy.flow import Flow
from ui.style import ACCENT, TEXT_DIM, status_color


def _hk(host: str) -> str:
    return f"H|{host}"


def _pk(host: str, path: str) -> str:
    return f"P|{host}|{path}"


class SiteMapTab(QWidget):
    send_to_repeater = Signal(object)

    def __init__(self):
        super().__init__()
        self._node_flows: dict[str, list[Flow]] = {}
        self._tree_items: dict[str, QTreeWidgetItem] = {}
        self._flows_getter: Callable = lambda: []
        self._build_ui()

    def set_flows_getter(self, getter: Callable) -> None:
        self._flows_getter = getter

    def add_flow(self, flow: Flow) -> None:
        self._insert(flow)
        self._update_count()

    def clear(self) -> None:
        self.tree.clear()
        self._node_flows.clear()
        self._tree_items.clear()
        self.flow_table.setRowCount(0)
        self._count_lbl.setText("Sin datos")
        self._node_lbl.setText("Selecciona un nodo para ver sus peticiones")

    def full_refresh(self) -> None:
        flows = self._flows_getter()
        self.tree.clear()
        self._node_flows.clear()
        self._tree_items.clear()
        for flow in flows:
            self._insert(flow)
        self.tree.expandAll()
        self._update_count()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        toolbar = QHBoxLayout()
        refresh_btn = QPushButton("↻  Actualizar")
        refresh_btn.setObjectName("primaryButton")
        refresh_btn.clicked.connect(self.full_refresh)
        toolbar.addWidget(refresh_btn)

        expand_btn = QPushButton("Expandir todo")
        expand_btn.clicked.connect(lambda: self.tree.expandAll())
        toolbar.addWidget(expand_btn)

        collapse_btn = QPushButton("Contraer todo")
        collapse_btn.clicked.connect(lambda: self.tree.collapseAll())
        toolbar.addWidget(collapse_btn)

        toolbar.addStretch()
        self._count_lbl = QLabel("Sin datos")
        self._count_lbl.setObjectName("paneCaption")
        toolbar.addWidget(self._count_lbl)
        root.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(8)

        # Árbol
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Host / Ruta")
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.setAlternatingRowColors(True)
        self.tree.setMinimumWidth(240)
        self.tree.itemClicked.connect(self._on_node_clicked)
        splitter.addWidget(self.tree)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)

        self._node_lbl = QLabel("Selecciona un nodo para ver sus peticiones")
        self._node_lbl.setObjectName("paneCaption")
        rl.addWidget(self._node_lbl)

        self.flow_table = QTableWidget(0, 5)
        self.flow_table.setHorizontalHeaderLabels(
            ["#", "Método", "URL", "Estado", "Long."])
        self.flow_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.flow_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.flow_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.flow_table.setAlternatingRowColors(True)
        self.flow_table.setShowGrid(False)
        self.flow_table.verticalHeader().setVisible(False)
        self.flow_table.verticalHeader().setDefaultSectionSize(28)
        hdr = self.flow_table.horizontalHeader()
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setHighlightSections(False)
        self.flow_table.setColumnWidth(0, 50)
        self.flow_table.setColumnWidth(1, 80)
        self.flow_table.setColumnWidth(3, 80)
        self.flow_table.setColumnWidth(4, 80)
        self.flow_table.itemDoubleClicked.connect(self._on_flow_double_clicked)
        rl.addWidget(self.flow_table)

        splitter.addWidget(right)
        splitter.setSizes([300, 700])
        root.addWidget(splitter, 1)

    def _insert(self, flow: Flow) -> None:
        host = flow.host
        try:
            path = urlparse(flow.url).path or "/"
        except Exception:
            path = "/"

        hk = _hk(host)
        if hk not in self._tree_items:
            item = QTreeWidgetItem(self.tree, [host])
            item.setData(0, Qt.UserRole, hk)
            f = item.font(0)
            f.setBold(True)
            item.setFont(0, f)
            self._tree_items[hk] = item
            self._node_flows[hk] = []
        self._node_flows[hk].append(flow)
        self._refresh_item(hk)

        segments = [s for s in path.split("/") if s]
        parent_item = self._tree_items[hk]
        prefix = ""
        for seg in segments:
            prefix = f"{prefix}/{seg}"
            pk = _pk(host, prefix)
            if pk not in self._tree_items:
                item = QTreeWidgetItem(parent_item, [prefix])
                item.setData(0, Qt.UserRole, pk)
                self._tree_items[pk] = item
                self._node_flows[pk] = []
            self._node_flows[pk].append(flow)
            self._refresh_item(pk)
            parent_item = self._tree_items[pk]

    def _refresh_item(self, key: str) -> None:
        item = self._tree_items.get(key)
        if not item:
            return
        flows = self._node_flows.get(key, [])

        if key.startswith("H|"):
            short = key[2:]
        else:
            _, _, path = key.split("|", 2)
            segs = [s for s in path.split("/") if s]
            short = "/" + (segs[-1] if segs else "")

        methods = sorted(set(f.method for f in flows))
        text = f"{short}  [{'/'.join(methods)}]  ×{len(flows)}"
        item.setText(0, text)

        statuses = [f.status for f in flows if f.status]
        if any(s.startswith("5") for s in statuses):
            color = QColor("#ff6b6b")
        elif any(s.startswith("4") for s in statuses):
            color = QColor("#ffb454")
        elif any(s.startswith("3") for s in statuses):
            color = QColor("#4fc3d6")
        elif any(s.startswith("2") for s in statuses):
            color = QColor("#dfe3ea")
        else:
            color = QColor(TEXT_DIM)

        if key.startswith("H|"):
            color = QColor(ACCENT)
            f = item.font(0)
            f.setBold(True)
            item.setFont(0, f)

        item.setForeground(0, color)

    def _on_node_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        key = item.data(0, Qt.UserRole)
        flows = self._node_flows.get(key, [])

        if key.startswith("H|"):
            node_name = key[2:]
        else:
            _, host, path = key.split("|", 2)
            node_name = f"{host}{path}"
        self._node_lbl.setText(f"{node_name}  ·  {len(flows)} petición(es)")

        self.flow_table.setRowCount(0)
        for flow in flows:
            row = self.flow_table.rowCount()
            self.flow_table.insertRow(row)
            for col, val in enumerate([
                str(flow.id), flow.method, flow.url, flow.status, str(flow.length)
            ]):
                cell = QTableWidgetItem(val)
                cell.setData(Qt.UserRole, flow)
                if col == 1:
                    cell.setForeground(QColor("#7fb3ff"))
                elif col == 3:
                    c = status_color(flow.status)
                    if c:
                        cell.setForeground(c)
                        fnt = cell.font()
                        fnt.setBold(True)
                        cell.setFont(fnt)
                self.flow_table.setItem(row, col, cell)

    def _on_flow_double_clicked(self, item: QTableWidgetItem) -> None:
        flow = item.data(Qt.UserRole)
        if isinstance(flow, Flow):
            self.send_to_repeater.emit(flow)

    def _update_count(self) -> None:
        hosts = sum(1 for k in self._tree_items if k.startswith("H|"))
        paths = sum(1 for k in self._tree_items if k.startswith("P|"))
        self._count_lbl.setText(f"{hosts} host(s)  ·  {paths} ruta(s)")
