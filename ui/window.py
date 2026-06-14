"""Ventana principal de Leetch."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from datetime import datetime

from pathlib import Path

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QAction, QBrush, QColor, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QTabWidget, QTabBar, QTableWidget, QTableWidgetItem, QSplitter,
    QPlainTextEdit, QSpinBox, QHeaderView, QMenu, QMessageBox,
    QAbstractItemView, QFrame, QFileDialog, QDialog, QDialogButtonBox,
    QFormLayout, QCheckBox, QInputDialog, QStyledItemDelegate,
)

from proxy import ProxyServer, Flow, CA_CERT_FILE
from net import http_message as hm
from ui.style import STYLE, ACCENT, TEXT_DIM, MONO, decode, decode_http, status_color
from ui.highlighter import HTTPHighlighter
from ui.repeater import RepeaterTab, RepeaterWorker
from ui.fuzzer import FuzzerTab
from ui.intercept import InterceptBridge, InterceptTab
from ui.matchreplace import MatchReplaceTab
from ui.ai_shell import AIShellTab
from ui.decoder import DecoderTab
from ui.sitemap import SiteMapTab
from ui.comparer import ComparerTab
from ui.apikey import APIKeyTab
from ui.passive_scanner import PassiveScannerTab
from ui.collaborator import CollaboratorTab
import session

_ASSETS = Path(__file__).parent / "assets"
_LOGO   = str(_ASSETS / "logo.png")

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8080

# Colores de fondo para las etiquetas del History (tintes visibles sobre fondo oscuro)
_LABEL_BG: dict[str, str] = {
    "rojo":     "#6b1515",
    "naranja":  "#6b4010",
    "amarillo": "#6b5e10",
    "verde":    "#15602a",
    "azul":     "#10406b",
    "morado":   "#40106b",
}


class _SortItem(QTableWidgetItem):
    """QTableWidgetItem con sort_key numérico para ordenar correctamente."""
    def __init__(self, text: str, sort_key=None):
        super().__init__(text)
        self._sort_key = sort_key if sort_key is not None else text

    def __lt__(self, other):
        if isinstance(other, _SortItem):
            try:
                return self._sort_key < other._sort_key
            except TypeError:
                pass
        return super().__lt__(other)


class _BgDelegate(QStyledItemDelegate):
    """Delegado que pinta el BackgroundRole antes que el QSS global lo pise."""

    def paint(self, painter, option, index):
        bg = index.data(Qt.BackgroundRole)
        if bg is not None:
            color = bg.color() if isinstance(bg, QBrush) else QColor(bg)
            painter.fillRect(option.rect, color)
        super().paint(painter, option, index)

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        bg = index.data(Qt.BackgroundRole)
        if bg is not None:
            option.backgroundBrush = bg if isinstance(bg, QBrush) else QBrush(bg)
_LABEL_DISPLAY: dict[str, str] = {
    "rojo":     "Rojo",
    "naranja":  "Naranja",
    "amarillo": "Amarillo",
    "verde":    "Verde",
    "azul":     "Azul",
    "morado":   "Morado",
}


class FlowBridge(QObject):
    flow_received = Signal(object)


# ---------------------------------------------------------------------------
# Diálogo de ajustes del proxy
# ---------------------------------------------------------------------------
class SettingsDialog(QDialog):
    def __init__(self, host: str, port: int, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ajustes del proxy")
        self.setMinimumWidth(320)

        form = QFormLayout(self)
        form.setSpacing(10)
        form.setContentsMargins(16, 16, 16, 16)

        self.host_edit = QLineEdit(host)
        self.host_edit.setAccessibleName("Host de escucha del proxy")
        self.host_edit.setToolTip("Dirección en la que el proxy acepta conexiones")
        form.addRow("Host de escucha:", self.host_edit)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(port)
        self.port_spin.setAccessibleName("Puerto de escucha del proxy")
        self.port_spin.setToolTip("Puerto del proxy (1-65535)")
        form.addRow("Puerto:", self.port_spin)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    @property
    def host(self) -> str:
        return self.host_edit.text().strip() or _DEFAULT_HOST

    @property
    def port(self) -> int:
        return self.port_spin.value()


# ---------------------------------------------------------------------------
# Diálogo de scope / filtro de dominio
# ---------------------------------------------------------------------------
class ScopeDialog(QDialog):
    """Modal para definir el scope del HTTP History."""

    def __init__(self, entries: list[tuple[str, bool]], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scope / Filtro de dominio")
        self.setMinimumWidth(520)
        self.setMinimumHeight(400)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        desc = QLabel(
            "Solo se mostrarán las peticiones cuyo host o URL coincida con alguna entrada. "
            "Con el scope vacío se muestran todas las peticiones."
        )
        desc.setWordWrap(True)
        desc.setObjectName("paneCaption")
        layout.addWidget(desc)

        self._tbl = QTableWidget(0, 2)
        self._tbl.setHorizontalHeaderLabels(["Dominio / URL", "Incluir subdominios"])
        self._tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self._tbl.setColumnWidth(1, 140)
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self._tbl.setEditTriggers(
            QAbstractItemView.DoubleClicked | QAbstractItemView.SelectedClicked)
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.setShowGrid(False)
        self._tbl.setAlternatingRowColors(True)
        self._tbl.setAccessibleName("Entradas del scope")
        layout.addWidget(self._tbl)

        for pattern, include_sub in entries:
            self._add_row(pattern, include_sub)

        add_row = QHBoxLayout()
        self._new_pattern = QLineEdit()
        self._new_pattern.setPlaceholderText(
            "ejemplo.com  o  https://api.ejemplo.com/ruta")
        self._new_pattern.setAccessibleName("Nuevo dominio o URL para el scope")
        self._new_pattern.returnPressed.connect(self._add_entry)
        add_row.addWidget(self._new_pattern)

        self._new_sub = QCheckBox("Subdominios")
        self._new_sub.setChecked(True)
        self._new_sub.setAccessibleName("Incluir subdominios en la nueva entrada")
        add_row.addWidget(self._new_sub)

        add_btn = QPushButton("+ Agregar")
        add_btn.setAccessibleName("Agregar entrada al scope")
        add_btn.clicked.connect(self._add_entry)
        add_row.addWidget(add_btn)

        del_btn = QPushButton("− Eliminar")
        del_btn.setAccessibleName("Eliminar la entrada seleccionada")
        del_btn.clicked.connect(self._del_entry)
        add_row.addWidget(del_btn)
        layout.addLayout(add_row)

        btn_row = QHBoxLayout()
        clear_btn = QPushButton("Limpiar todo")
        clear_btn.setAccessibleName("Eliminar todas las entradas del scope")
        clear_btn.clicked.connect(lambda: self._tbl.setRowCount(0))
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        buttons.button(QDialogButtonBox.Ok).setText("Aplicar")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        btn_row.addWidget(buttons)
        layout.addLayout(btn_row)

    def _add_row(self, pattern: str, include_sub: bool):
        row = self._tbl.rowCount()
        self._tbl.insertRow(row)
        self._tbl.setItem(row, 0, QTableWidgetItem(pattern))
        check_item = QTableWidgetItem()
        check_item.setFlags(
            Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        check_item.setCheckState(Qt.Checked if include_sub else Qt.Unchecked)
        check_item.setTextAlignment(Qt.AlignCenter)
        self._tbl.setItem(row, 1, check_item)

    def _add_entry(self):
        pattern = self._new_pattern.text().strip()
        if not pattern:
            return
        self._add_row(pattern, self._new_sub.isChecked())
        self._new_pattern.clear()
        self._new_pattern.setFocus()

    def _del_entry(self):
        row = self._tbl.currentRow()
        if row >= 0:
            self._tbl.removeRow(row)

    @property
    def entries(self) -> list[tuple[str, bool]]:
        result = []
        for row in range(self._tbl.rowCount()):
            p_item = self._tbl.item(row, 0)
            c_item = self._tbl.item(row, 1)
            if p_item and c_item:
                pattern = p_item.text().strip()
                if pattern:
                    result.append((pattern, c_item.checkState() == Qt.Checked))
        return result


# ---------------------------------------------------------------------------
# Shims para compatibilidad con session.py
# ---------------------------------------------------------------------------
class _StrProxy:
    def __init__(self, window: "MainWindow"):
        self._w = window

    def text(self) -> str:
        return self._w._proxy_host

    def setText(self, v: str):
        self._w._proxy_host = v


class _IntProxy:
    def __init__(self, window: "MainWindow"):
        self._w = window

    def value(self) -> int:
        return self._w._proxy_port

    def setValue(self, v: int):
        self._w._proxy_port = v


# ---------------------------------------------------------------------------
# Ventana principal
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Leetch")
        self.setWindowIcon(QIcon(_LOGO))
        self.resize(1500, 950)

        self.flows: list[Flow] = []
        self._flow_by_id: dict[int, Flow] = {}
        self.proxy: ProxyServer | None = None
        self._proxy_host = _DEFAULT_HOST
        self._proxy_port = _DEFAULT_PORT
        self._scope_entries: list[tuple[str, bool]] = []

        self.bridge = FlowBridge()
        self.bridge.flow_received.connect(self.add_flow)

        self.intercept_bridge = InterceptBridge()
        self.intercept_bridge.pending_received.connect(self._on_intercept_pending)

        self.rep_worker = RepeaterWorker()
        self.rep_worker.finished.connect(
            lambda tab, resp, el: tab.on_response(resp, el))
        self.rep_worker.failed.connect(
            lambda tab, msg: tab.on_error(msg))

        self._build_menu()
        self._build_ui()
        # Conectar el toggle del intercept al proxy (después de crear la UI)
        self.intercept_tab.toggle_btn.toggled.connect(self._on_intercept_toggle)
        self._start_proxy()

    # Shims para session.py
    @property
    def listen_host(self) -> _StrProxy:
        return _StrProxy(self)

    @property
    def listen_port(self) -> _IntProxy:
        return _IntProxy(self)

    # ------------------------------------------------------------------ #
    # Menú
    # ------------------------------------------------------------------ #
    def _build_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&Archivo")

        save_action = QAction("Guardar sesión…", self)
        save_action.setShortcut("Ctrl+S")
        save_action.setToolTip("Exporta la sesión actual a un archivo .json")
        save_action.triggered.connect(self.save_session)
        file_menu.addAction(save_action)

        load_action = QAction("Cargar sesión…", self)
        load_action.setShortcut("Ctrl+O")
        load_action.setToolTip("Restaura una sesión previamente guardada")
        load_action.triggered.connect(self.load_session)
        file_menu.addAction(load_action)

        file_menu.addSeparator()

        quit_action = QAction("Salir", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        settings_menu = menubar.addMenu("&Ajustes")

        proxy_action = QAction("Configuración del proxy…", self)
        proxy_action.setToolTip(
            "Cambia el host y puerto de escucha (reinicia el proxy automáticamente)")
        proxy_action.triggered.connect(self.show_proxy_settings)
        settings_menu.addAction(proxy_action)

        settings_menu.addSeparator()

        ca_install_action = QAction("Instalar certificado CA…", self)
        ca_install_action.triggered.connect(self.install_ca)
        settings_menu.addAction(ca_install_action)

        ca_location_action = QAction("Ubicación de la CA…", self)
        ca_location_action.triggered.connect(self.show_ca_location)
        settings_menu.addAction(ca_location_action)

        tools_menu = menubar.addMenu("&Herramientas")

        browser_action = QAction("Abrir navegador", self)
        browser_action.setToolTip("Lanza Chrome/Chromium preconfigurado contra el proxy")
        browser_action.triggered.connect(self.launch_browser)
        tools_menu.addAction(browser_action)

        tools_menu.addSeparator()

        ca_install_tb_action = QAction("Instalar CA…", self)
        ca_install_tb_action.triggered.connect(self.install_ca)
        tools_menu.addAction(ca_install_tb_action)

        help_menu = menubar.addMenu("A&yuda")

        howto_action = QAction("Cómo usar Leetch", self)
        howto_action.triggered.connect(self.show_help)
        help_menu.addAction(howto_action)

        help_menu.addSeparator()

        about_action = QAction("Acerca de", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    # ------------------------------------------------------------------ #
    # Sesión
    # ------------------------------------------------------------------ #
    def save_session(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Guardar sesión", "sesion_leech.json",
            "Sesión Leetch (*.json);;Todos los archivos (*)",
        )
        if not path:
            return
        if not path.lower().endswith(".json"):
            path += ".json"
        try:
            session.save_session_to_file(self, path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Error al guardar",
                                 f"No se pudo guardar la sesión:\n{exc}")
            return
        QMessageBox.information(self, "Sesión guardada",
                                f"Sesión guardada en:\n{path}")

    def load_session(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Cargar sesión", "",
            "Sesión Leetch (*.json);;Todos los archivos (*)",
        )
        if not path:
            return
        try:
            session.load_session_from_file(self, path)
        except ValueError as exc:
            QMessageBox.warning(self, "Sesión no válida", str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Error al cargar",
                                 f"No se pudo cargar la sesión:\n{exc}")
            return
        QMessageBox.information(self, "Sesión cargada",
                                f"Sesión restaurada desde:\n{path}")

    # ------------------------------------------------------------------ #
    # Ajustes del proxy
    # ------------------------------------------------------------------ #
    def show_proxy_settings(self):
        dlg = SettingsDialog(self._proxy_host, self._proxy_port, self)
        if dlg.exec() != QDialog.Accepted:
            return
        new_host, new_port = dlg.host, dlg.port
        if new_host == self._proxy_host and new_port == self._proxy_port:
            return
        self._proxy_host = new_host
        self._proxy_port = new_port
        if self.proxy:
            self.proxy.stop()
            self.proxy = None
        self._start_proxy()

    def _start_proxy(self):
        self.proxy = ProxyServer(
            host=self._proxy_host,
            port=self._proxy_port,
            on_flow=self.bridge.flow_received.emit,
            on_intercept=self.intercept_bridge.pending_received.emit,
        )
        self.proxy.intercept_enabled  = self.intercept_tab.is_enabled
        self.proxy.transform_request  = self.mr_tab.apply_to_request
        self.proxy.transform_response = self.mr_tab.apply_to_response
        try:
            self.proxy.start()
            self.statusBar().showMessage(
                f"● Escuchando en {self._proxy_host}:{self._proxy_port}")
        except Exception as exc:  # noqa: BLE001
            self.proxy = None
            self.statusBar().showMessage("● Error al iniciar el proxy")
            QMessageBox.critical(
                self, "No se pudo iniciar el proxy",
                f"Puerto {self._proxy_port} no disponible:\n{exc}\n\n"
                "Cámbialo en Ajustes → Configuración del proxy.",
            )

    # ------------------------------------------------------------------ #
    # Intercept
    # ------------------------------------------------------------------ #
    def _on_intercept_toggle(self, checked: bool):
        if self.proxy:
            self.proxy.intercept_enabled = checked

    @Slot(object)
    def _on_intercept_pending(self, pending):
        self.tabs.setCurrentIndex(0)        # saltar a la pestaña Intercept
        self.intercept_tab.on_pending(pending)

    # ------------------------------------------------------------------ #
    # Ayuda / CA
    # ------------------------------------------------------------------ #
    def show_help(self):
        text = (
            "<h3>Cómo usar Leetch</h3>"
            "<p><b>1. Intercept.</b> Activa el toggle rojo para capturar peticiones "
            "en vuelo, edítalas y pulsa Forward o Drop.</p>"
            "<p><b>2. Proxy automático.</b> Leetch intercepta tráfico en "
            f"<code>{_DEFAULT_HOST}:{_DEFAULT_PORT}</code> nada más abrir. "
            "Cambia la dirección en <i>Ajustes → Configuración del proxy</i>.</p>"
            "<p><b>3. Enviar tráfico.</b> Configura tu navegador para usar ese proxy, "
            "o pulsa <i>Abrir navegador</i> para lanzar Chrome ya preconfigurado "
            "(incluye soporte de localhost).</p>"
            "<p><b>Capturar localhost en tu propio Chrome:</b> añade "
            f"<code>--proxy-server=http://{_DEFAULT_HOST}:{_DEFAULT_PORT} "
            "--proxy-bypass-list=&lt;-loopback&gt;</code> al acceso directo. "
            "En <b>Firefox</b>: Ajustes → Red → Proxy manual → borra "
            "<i>localhost, 127.0.0.1</i> del campo «Sin proxy para».</p>"
            "<p><b>4. HTTPS / CA.</b> Instala la CA desde "
            "<i>Ajustes → Instalar CA</i> y confía en <i>Leetch CA</i>.</p>"
            "<p><b>5. HTTP History.</b> Cada petición aparece en la tabla. "
            "Clic derecho para: Repeater, Tools, Matcher, Decoder, JWT Inspector, "
            "copiar curl, etiquetar con color, añadir comentario.</p>"
            "<p><b>6. Repeater.</b> Doble clic en History o botón Enviar. "
            "Edita y pulsa Enviar (Ctrl+Intro).</p>"
            "<p><b>7. Tools.</b> Fuzzing (marca §…§ + wordlist), Race Conditions y JWT Auditor.</p>"
            "<p><b>8. Matcher.</b> Reglas automáticas que modifican "
            "peticiones/respuestas en tiempo real (texto o regex).</p>"
            "<p><b>9. Decoder.</b> Encode/decode Base64, URL, HTML, Hex, hashes y "
            "JWT Inspector con detección de alg:none y re-firma HS256.</p>"
            "<p><b>10. Site Map.</b> Árbol de hosts y rutas. Doble clic en una fila "
            "para enviarla al Repeater.</p>"
            "<p><b>11. Sesiones.</b> Ctrl+S para guardar, Ctrl+O para cargar.</p>"
        )
        box = QMessageBox(self)
        box.setWindowTitle("Cómo usar Leetch")
        box.setTextFormat(Qt.RichText)
        box.setText(text)
        box.exec()

    def show_ca_location(self):
        exists = os.path.exists(CA_CERT_FILE)
        estado = ("La CA ya está generada." if exists
                  else "La CA se genera con la primera petición HTTPS.")
        box = QMessageBox(self)
        box.setWindowTitle("Ubicación de la CA")
        box.setTextFormat(Qt.RichText)
        box.setText(
            "<p>El certificado CA de Leetch se encuentra en:</p>"
            f"<p><code>{CA_CERT_FILE}</code></p>"
            f"<p>{estado}</p>"
        )
        box.exec()

    def show_about(self):
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Acerca de Leetch")
        dlg.setIconPixmap(QPixmap(_LOGO).scaled(72, 72, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        dlg.setText(
            "<h3>Leetch</h3>"
            "<p>Proxy de interceptación HTTP/HTTPS para pentesting web.<br>"
            "Intercept · History · Repeater · Tools · Site Map</p>"
        )
        dlg.exec()

    # ------------------------------------------------------------------ #
    # UI principal
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)

        #   0 → Intercept
        #   1 → HTTP History
        #   2 → Repeater
        #   3 → Tools  (FuzzerTab; Decoder, IA y Matcher son botones de la fila
        #               "Nueva sesión", junto a Fuzzing/Race/JWT Auditor)
        #   4 → Site Map
        self.intercept_tab = InterceptTab()
        self.tabs.addTab(self.intercept_tab, "Intercept")

        self.tabs.addTab(self._build_history_tab(), "HTTP History")
        self.tabs.addTab(self._build_repeater_container(), "Repeater")

        self.fuzzer_tab = FuzzerTab()

        # Herramientas singleton: botones en la fila "Nueva sesión" de FuzzerTab
        self.decoder_tab = DecoderTab()
        self.fuzzer_tab.register_tool("Decoder", self.decoder_tab, "Decoder")

        self.ai_tab = AIShellTab()
        self.ai_tab.set_flows_getter(lambda: self.flows)
        self.fuzzer_tab.register_tool("IA", self.ai_tab, "IA")

        self.mr_tab = MatchReplaceTab()
        self.fuzzer_tab.register_tool("Matcher", self.mr_tab, "Matcher")

        self.comparer_tab = ComparerTab()
        self.fuzzer_tab.register_tool("Comparer", self.comparer_tab, "Comparer")

        self.apikey_tab = APIKeyTab()
        self.apikey_tab.set_flows_getter(lambda: self.flows)
        self.fuzzer_tab.register_tool("API Key", self.apikey_tab, "API Key")

        self.passive_scanner = PassiveScannerTab()
        self.fuzzer_tab.register_tool("Scanner Pasivo", self.passive_scanner, "Scanner Pasivo")

        self.collaborator_tab = CollaboratorTab()
        self.fuzzer_tab.register_tool("Collaborator", self.collaborator_tab, "Collaborator")

        self.tabs.addTab(self.fuzzer_tab, "Tools")          # índice 3

        self.sitemap_tab = SiteMapTab()                     # índice 4
        self.sitemap_tab.set_flows_getter(lambda: self.flows)
        self.sitemap_tab.send_to_repeater.connect(self.send_to_repeater)
        self.tabs.addTab(self.sitemap_tab, "Site Map")

        # Botón de Scope en la esquina superior derecha, junto a las pestañas
        self.scope_btn = QPushButton("◎  Scope")
        self.scope_btn.setCheckable(True)
        self.scope_btn.setObjectName("scopeBtn")
        self.scope_btn.setCursor(Qt.PointingHandCursor)
        self.scope_btn.setAccessibleName("Configurar scope del historial")
        self.scope_btn.setToolTip(
            "Define el scope: solo se mostrarán peticiones que coincidan con "
            "los dominios o URLs configurados")
        self.scope_btn.clicked.connect(self._open_scope_dialog)
        corner = QWidget()
        corner_lay = QHBoxLayout(corner)
        corner_lay.setContentsMargins(0, 0, 4, 4)
        corner_lay.addWidget(self.scope_btn)
        self.tabs.setCornerWidget(corner, Qt.TopRightCorner)

        self.add_repeater_tab()  # pestaña inicial vacía en el Repeater

    def _attach_panel_search(self, layout: QVBoxLayout, title: str,
                              editor: QPlainTextEdit) -> QLineEdit:
        """Añade una fila [Título] ·· [Buscar…] [N/M] [↑][↓] al layout y devuelve el QLineEdit."""
        from PySide6.QtGui import QTextCharFormat, QColor
        from PySide6.QtWidgets import QTextEdit

        hdr = QHBoxLayout()
        hdr.setSpacing(4)
        caption = QLabel(title)
        caption.setObjectName("paneCaption")
        hdr.addWidget(caption)
        hdr.addStretch()

        entry = QLineEdit()
        entry.setPlaceholderText("Buscar…")
        entry.setFixedWidth(150)
        entry.setObjectName("panelSearch")
        entry.setToolTip("Buscar en el texto (Enter = siguiente, Shift+Enter = anterior)")
        hdr.addWidget(entry)

        count_lbl = QLabel("")
        count_lbl.setObjectName("searchCount")
        count_lbl.setFixedWidth(52)
        count_lbl.setAlignment(Qt.AlignCenter)
        hdr.addWidget(count_lbl)

        btn_prev = QPushButton("↑")
        btn_next = QPushButton("↓")
        for b in (btn_prev, btn_next):
            b.setFixedSize(22, 22)
            b.setObjectName("searchNavBtn")
            b.setCursor(Qt.PointingHandCursor)
        hdr.addWidget(btn_prev)
        hdr.addWidget(btn_next)
        layout.addLayout(hdr)

        _FMT_ALL = QTextCharFormat()
        _FMT_ALL.setBackground(QColor("#6b4010"))

        _FMT_CUR = QTextCharFormat()
        _FMT_CUR.setBackground(QColor(ACCENT))
        _FMT_CUR.setForeground(QColor("#000000"))

        state = {"matches": [], "idx": 0}

        def _apply():
            matches = state["matches"]
            idx = state["idx"]
            sels = []
            for i, cur in enumerate(matches):
                sel = QTextEdit.ExtraSelection()
                sel.cursor = cur
                sel.format = _FMT_CUR if i == idx else _FMT_ALL
                sels.append(sel)
            editor.setExtraSelections(sels)
            if matches:
                editor.setTextCursor(matches[idx])
                editor.ensureCursorVisible()
                count_lbl.setText(f"{idx + 1}/{len(matches)}")
            else:
                count_lbl.setText("0" if entry.text() else "")

        def _search(term: str):
            state["matches"].clear()
            state["idx"] = 0
            editor.setExtraSelections([])
            if not term:
                count_lbl.setText("")
                return
            doc = editor.document()
            cur = doc.find(term)
            while not cur.isNull():
                state["matches"].append(cur)
                cur = doc.find(term, cur)
            _apply()

        def _next():
            if not state["matches"]:
                return
            state["idx"] = (state["idx"] + 1) % len(state["matches"])
            _apply()

        def _prev():
            if not state["matches"]:
                return
            state["idx"] = (state["idx"] - 1) % len(state["matches"])
            _apply()

        entry.textChanged.connect(_search)
        entry.returnPressed.connect(_next)
        btn_next.clicked.connect(_next)
        btn_prev.clicked.connect(_prev)

        return entry

    def _build_history_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(
            ["#", "Hora", "Método", "Host", "URL", "Estado", "Long.", "Comentario"])
        self.table.setAccessibleName("Historial HTTP")
        self.table.setToolTip(
            "Peticiones interceptadas; clic derecho para más opciones")
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        hdr.setHighlightSections(False)
        hdr.setSectionsClickable(True)
        hdr.setSortIndicatorShown(False)
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 72)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 200)
        self.table.setColumnWidth(5, 80)
        self.table.setColumnWidth(6, 90)
        self.table.setColumnWidth(7, 160)
        self.table.itemSelectionChanged.connect(self.on_row_selected)
        self.table.itemDoubleClicked.connect(lambda _: self._send_selected_to_repeater())
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_history_menu)
        self.table.setItemDelegate(_BgDelegate(self.table))
        self._sort_col = -1
        self._sort_order = Qt.AscendingOrder
        hdr.sectionClicked.connect(self._on_history_header_clicked)

        action_row = QHBoxLayout()
        action_row.setSpacing(6)
        self.to_repeater_btn = QPushButton("→ Repeater")
        self.to_repeater_btn.setEnabled(False)
        self.to_repeater_btn.setObjectName("histActionBtn")
        self.to_repeater_btn.setCursor(Qt.PointingHandCursor)
        self.to_repeater_btn.setFixedSize(100, 26)
        self.to_repeater_btn.setAccessibleName("Enviar petición seleccionada al Repeater")
        self.to_repeater_btn.setToolTip(
            "Envía la petición seleccionada al Repeater (también con doble clic)")
        self.to_repeater_btn.clicked.connect(self._send_selected_to_repeater)
        action_row.addWidget(self.to_repeater_btn)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filtrar historial…")
        self.search_edit.setFixedWidth(230)
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setAccessibleName("Buscador del historial HTTP")
        self.search_edit.setToolTip(
            "Filtra por host, URL, método o código de estado (case insensitive)")
        self.search_edit.textChanged.connect(lambda _: self._apply_filters())
        action_row.addWidget(self.search_edit)
        action_row.addStretch()

        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(8)
        splitter.addWidget(self.table)

        detail = QSplitter(Qt.Horizontal)
        detail.setHandleWidth(8)

        req_box = QWidget()
        req_layout = QVBoxLayout(req_box)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(0)
        self.hist_request = QPlainTextEdit()
        self.hist_request.setFont(MONO)
        self.hist_request.setReadOnly(True)
        self.hist_request.setAccessibleName("Petición de la fila seleccionada")
        HTTPHighlighter(self.hist_request.document())
        req_layout.addWidget(self.hist_request)
        detail.addWidget(req_box)

        resp_box = QWidget()
        resp_layout = QVBoxLayout(resp_box)
        resp_layout.setContentsMargins(0, 0, 0, 0)
        resp_layout.setSpacing(0)
        self.hist_response = QPlainTextEdit()
        self.hist_response.setFont(MONO)
        self.hist_response.setReadOnly(True)
        self.hist_response.setAccessibleName("Respuesta de la fila seleccionada")
        HTTPHighlighter(self.hist_response.document())
        resp_layout.addWidget(self.hist_response)
        detail.addWidget(resp_box)

        detail.setSizes([600, 600])
        splitter.addWidget(detail)
        splitter.setSizes([300, 500])

        # Barra inferior: buscadores de texto para petición y respuesta
        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(0, 4, 0, 0)
        bottom_row.setSpacing(6)
        self._req_search = self._attach_panel_search(bottom_row, "Petición:", self.hist_request)
        sep_v = QFrame()
        sep_v.setFrameShape(QFrame.VLine)
        sep_v.setFixedWidth(1)
        bottom_row.addWidget(sep_v)
        self._resp_search = self._attach_panel_search(bottom_row, "Respuesta:", self.hist_response)

        layout.addLayout(action_row)
        layout.addWidget(splitter)
        layout.addLayout(bottom_row)
        return container

    def _build_repeater_container(self) -> QWidget:
        self.repeater_tabs = QTabWidget()

        add_tab_btn = QPushButton("+")
        add_tab_btn.setObjectName("addTabBtn")
        add_tab_btn.setFixedSize(28, 28)
        add_tab_btn.setCursor(Qt.PointingHandCursor)
        add_tab_btn.setAccessibleName("Nueva pestaña de Repeater")
        add_tab_btn.setToolTip("Abre una pestaña de Repeater vacía")
        add_tab_btn.clicked.connect(lambda: self.add_repeater_tab())
        self.repeater_tabs.setCornerWidget(add_tab_btn, Qt.TopRightCorner)

        container = QWidget()
        rep_layout = QVBoxLayout(container)
        rep_layout.setContentsMargins(8, 8, 8, 8)
        rep_layout.setSpacing(0)
        rep_layout.addWidget(self.repeater_tabs)
        return container

    # ------------------------------------------------------------------ #
    # Proxy → tabla
    # ------------------------------------------------------------------ #
    @Slot(object)
    def add_flow(self, flow: Flow):
        self.flows.append(flow)
        self._flow_by_id[flow.id] = flow
        row = self.table.rowCount()
        self.table.insertRow(row)
        hora_str = datetime.fromtimestamp(flow.timestamp).strftime("%H:%M:%S")
        texts = [str(flow.id), hora_str, flow.method, flow.host, flow.url,
                 flow.status, str(flow.length), flow.comment]
        sort_keys = [flow.id, flow.timestamp, None, None, None, None, flow.length, None]
        for col, (val, sk) in enumerate(zip(texts, sort_keys)):
            item = _SortItem(val, sk)
            item.setData(Qt.UserRole, flow.id)
            if col == 0:
                item.setForeground(QColor(TEXT_DIM))
            elif col == 1:
                item.setForeground(QColor(TEXT_DIM))
            elif col == 2:
                item.setForeground(QColor("#7fb3ff"))
            elif col == 5:
                color = status_color(flow.status)
                if color is not None:
                    item.setForeground(color)
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
            self.table.setItem(row, col, item)
        if flow.label:
            self._apply_row_color(row, flow.label)
        visible = self._flow_matches_scope(flow) and self._flow_matches_search(flow)
        self.table.setRowHidden(row, not visible)
        if visible and not self.table.selectedItems():
            self.table.selectRow(row)
        self.sitemap_tab.add_flow(flow)
        self.passive_scanner.analyze(flow)

    def _selected_flow(self) -> Flow | None:
        items = self.table.selectedItems()
        if not items:
            return None
        return self._flow_by_id.get(items[0].data(Qt.UserRole))

    def _send_selected_to_repeater(self):
        flow = self._selected_flow()
        if flow:
            self.send_to_repeater(flow)

    def on_row_selected(self):
        flow = self._selected_flow()
        has_flow = flow is not None
        self.to_repeater_btn.setEnabled(has_flow)
        if not has_flow:
            return
        self._req_search.clear()
        self._resp_search.clear()
        self.hist_request.setPlainText(decode(flow.raw_request))
        self.hist_response.setPlainText(decode_http(flow.raw_response))

    def show_history_menu(self, pos):
        flow = self._selected_flow()
        if not flow:
            return
        menu = QMenu(self)

        send_rep = QAction("Enviar al Repeater", self)
        send_rep.triggered.connect(lambda: self.send_to_repeater(flow))
        menu.addAction(send_rep)

        tools_menu = QMenu("Enviar a Tools ▶", self)
        for tool, label in [
            ("fuzzing", "Fuzzing"),
            ("race",    "Race Conditions"),
            ("jwt",     "JWT Auditor"),
            ("otp",     "OTP"),
            ("cors",    "CORS Tester"),
            ("sqli",     "Injection — SQLi"),
            ("xss",      "Injection — XSS"),
            ("lfi",      "Injection — LFI"),
            ("cmdi",     "Injection — CMDi"),
            ("ssti",     "Injection — SSTI"),
            ("redirect", "Injection — Open Redirect"),
            ("nosql",    "Injection — NoSQL"),
            ("crlf",     "Injection — CRLF"),
        ]:
            act = QAction(label, tools_menu)
            act.triggered.connect(
                lambda checked=False, t=tool: self._send_flow_to_tool(flow, t))
            tools_menu.addAction(act)
        menu.addMenu(tools_menu)

        send_dec = QAction("Enviar al Decoder", self)
        send_dec.setToolTip("Abre la petición en el Decoder para transformar y decodificar valores")
        send_dec.triggered.connect(lambda: self.send_to_decoder(flow))
        menu.addAction(send_dec)

        cmp_menu = QMenu("Enviar al Comparer ▶", self)
        cmp_a = QAction("Como Texto A", cmp_menu)
        cmp_a.triggered.connect(lambda checked=False, f=flow: self._send_to_comparer(f, "a"))
        cmp_menu.addAction(cmp_a)
        cmp_b = QAction("Como Texto B", cmp_menu)
        cmp_b.triggered.connect(lambda checked=False, f=flow: self._send_to_comparer(f, "b"))
        cmp_menu.addAction(cmp_b)
        menu.addMenu(cmp_menu)

        jwt_action = QAction("JWT Inspector", self)
        jwt_action.setToolTip("Extrae el JWT del header Authorization y lo analiza en el inspector")
        jwt_action.triggered.connect(lambda: self._send_flow_to_tool(flow, "jwt"))
        menu.addAction(jwt_action)

        menu.addSeparator()

        curl_action = QAction("Copiar como curl", self)
        curl_action.setToolTip("Genera el comando curl equivalente y lo copia al portapapeles")
        curl_action.triggered.connect(lambda: self._copy_as_curl(flow))
        menu.addAction(curl_action)

        menu.addSeparator()

        # Submenú de etiquetas de color
        label_menu = menu.addMenu("Etiquetar")
        clear_label = QAction("Sin etiqueta", self)
        clear_label.triggered.connect(lambda: self._set_flow_label(flow, ""))
        label_menu.addAction(clear_label)
        label_menu.addSeparator()
        for key, display in _LABEL_DISPLAY.items():
            act = QAction(display, self)
            act.triggered.connect(lambda _=False, k=key: self._set_flow_label(flow, k))
            label_menu.addAction(act)

        comment_action = QAction("Comentario…", self)
        comment_action.setToolTip("Añade o edita un comentario visible en el historial")
        comment_action.triggered.connect(lambda: self._edit_comment(flow))
        menu.addAction(comment_action)

        menu.addSeparator()
        clear_action = QAction("Limpiar historial", self)
        clear_action.setToolTip("Elimina todas las peticiones del historial")
        clear_action.triggered.connect(self._clear_history)
        menu.addAction(clear_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------ #
    # Scope / Filtros del historial
    # ------------------------------------------------------------------ #
    def _open_scope_dialog(self):
        dlg = ScopeDialog(self._scope_entries, self)
        if dlg.exec() == QDialog.Accepted:
            self._scope_entries = dlg.entries
        has_scope = bool(self._scope_entries)
        self.scope_btn.setChecked(has_scope)
        self._apply_filters()

    @staticmethod
    def _pattern_matches_flow(pattern: str, include_sub: bool, flow: Flow) -> bool:
        if "://" in pattern:
            flow_url = flow.url.lower()
            if flow_url.startswith(pattern):
                return True
            if include_sub:
                try:
                    scheme_end = pattern.index("://") + 3
                    p_host = pattern[scheme_end:].split("/")[0]
                    scheme = pattern[:scheme_end - 3]
                    if flow_url.startswith(scheme + "://"):
                        f_host = flow_url[len(scheme) + 3:].split("/")[0]
                        if f_host == p_host or f_host.endswith("." + p_host):
                            return True
                except Exception:
                    pass
        else:
            p_host = pattern.split(":")[0]
            f_host = flow.host.lower().split(":")[0]
            if f_host == p_host:
                return True
            if include_sub and f_host.endswith("." + p_host):
                return True
        return False

    def _flow_matches_scope(self, flow: Flow) -> bool:
        if not self._scope_entries:
            return True
        return any(
            self._pattern_matches_flow(p.strip().lower(), sub, flow)
            for p, sub in self._scope_entries
        )

    def _flow_matches_search(self, flow: Flow) -> bool:
        text = self.search_edit.text().strip().lower()
        if not text:
            return True
        meta = f"{flow.method} {flow.host} {flow.url} {flow.status} {flow.comment}".lower()
        if text in meta:
            return True
        needle = text.encode("utf-8", "replace")
        if needle in flow.raw_request.lower():
            return True
        if needle in flow.raw_response.lower():
            return True
        return False

    def _apply_filters(self):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if not item:
                self.table.setRowHidden(row, False)
                continue
            flow = self._flow_by_id.get(item.data(Qt.UserRole))
            if flow is None:
                self.table.setRowHidden(row, False)
                continue
            visible = self._flow_matches_scope(flow) and self._flow_matches_search(flow)
            self.table.setRowHidden(row, not visible)

    def _on_history_header_clicked(self, col: int):
        if self._sort_col == col:
            self._sort_order = (
                Qt.DescendingOrder if self._sort_order == Qt.AscendingOrder
                else Qt.AscendingOrder)
        else:
            self._sort_col = col
            self._sort_order = Qt.AscendingOrder
        self.table.sortItems(col, self._sort_order)
        hdr = self.table.horizontalHeader()
        hdr.setSortIndicator(col, self._sort_order)
        hdr.setSortIndicatorShown(True)

    # ------------------------------------------------------------------ #
    # Etiquetas y comentarios
    # ------------------------------------------------------------------ #
    def _row_for_flow_id(self, flow_id: int) -> int:
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.data(Qt.UserRole) == flow_id:
                return row
        return -1

    def _apply_row_color(self, row: int, label: str):
        bg = _LABEL_BG.get(label)
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                if bg:
                    item.setBackground(QColor(bg))
                else:
                    item.setBackground(QBrush())

    def _set_flow_label(self, flow: Flow, label: str):
        flow.label = label
        row = self._row_for_flow_id(flow.id)
        if row >= 0:
            self._apply_row_color(row, label)

    def _edit_comment(self, flow: Flow):
        text, ok = QInputDialog.getText(
            self, "Comentario",
            "Comentario para esta petición:",
            text=flow.comment,
        )
        if not ok:
            return
        flow.comment = text.strip()
        row = self._row_for_flow_id(flow.id)
        if row >= 0:
            item = self.table.item(row, 7)
            if item:
                item.setText(flow.comment)

    def _clear_history(self):
        self.flows.clear()
        self._flow_by_id.clear()
        self.table.setRowCount(0)
        self.hist_request.clear()
        self.hist_response.clear()
        if hasattr(self, "sitemap_tab"):
            self.sitemap_tab.clear()
        if hasattr(self, "passive_scanner"):
            self.passive_scanner.clear()

    # ------------------------------------------------------------------ #
    # Copiar como curl
    # ------------------------------------------------------------------ #
    def _copy_as_curl(self, flow: Flow):
        headers = hm.parse_headers(flow.raw_request)
        parts = ["curl", "-s"]
        if flow.method.upper() != "GET":
            parts += ["-X", flow.method.upper()]
        for name, val in headers.items():
            if name.lower() == "host":
                continue
            val_esc = val.replace('"', '\\"')
            parts.append(f'-H "{name}: {val_esc}"')
        body_sep = flow.raw_request.find(b"\r\n\r\n")
        if body_sep != -1:
            body = flow.raw_request[body_sep + 4:]
            if body.strip():
                body_str = body.decode("utf-8", "replace").replace('"', '\\"')
                parts += ["--data-raw", f'"{body_str}"']
        url_esc = flow.url.replace('"', '\\"')
        parts.append(f'"{url_esc}"')
        QApplication.clipboard().setText(" ".join(parts))
        self.statusBar().showMessage("Comando curl copiado al portapapeles", 3000)

    # ------------------------------------------------------------------ #
    # Repeater / Fuzzer / Match & Replace
    # ------------------------------------------------------------------ #
    def add_repeater_tab(self, flow: Flow | None = None) -> RepeaterTab:
        if flow:
            tab = RepeaterTab(
                self.rep_worker, host=flow.host, port=flow.port,
                use_tls=(flow.scheme == "https"), raw=flow.raw_request)
            title = f"{flow.method} {flow.host}"
        else:
            tab = RepeaterTab(self.rep_worker)
            title = "Nueva"
        index = self.repeater_tabs.addTab(tab, title[:25])

        close_btn = QPushButton("×")
        close_btn.setObjectName("tabCloseBtn")
        close_btn.setFixedSize(18, 18)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setToolTip("Cerrar pestaña")
        close_btn.clicked.connect(
            lambda checked=False, t=tab: self.repeater_tabs.removeTab(
                self.repeater_tabs.indexOf(t)))
        self.repeater_tabs.tabBar().setTabButton(index, QTabBar.RightSide, close_btn)

        self.repeater_tabs.setCurrentIndex(index)
        return tab

    def send_to_repeater(self, flow: Flow):
        self.add_repeater_tab(flow)
        self.tabs.setCurrentIndex(2)    # Repeater = índice 2

    def _go_tools(self, widget) -> None:
        """Navega a Tools y abre (o enfoca) la herramienta indicada."""
        self.tabs.setCurrentIndex(3)
        self.fuzzer_tab.open_tool(widget)

    def send_to_fuzzer(self, flow: Flow):
        self.fuzzer_tab.load_from_flow(
            raw=flow.raw_request,
            use_tls=(flow.scheme == "https"),
        )
        self.tabs.setCurrentIndex(3)    # Tools; load_from_flow ya activa el tab nuevo

    def send_to_match_replace(self, flow: Flow):
        self._go_tools(self.mr_tab)
        self.mr_tab.open_new_rule_dialog()

    def send_to_decoder(self, flow: Flow):
        self.decoder_tab.load_text(decode(flow.raw_request))
        self._go_tools(self.decoder_tab)

    def _send_to_comparer(self, flow: Flow, side: str):
        text = decode(flow.raw_request)
        if side == "a":
            self.comparer_tab.load_a(text)
        else:
            self.comparer_tab.load_b(text)
        self._go_tools(self.comparer_tab)

    def _send_flow_to_tool(self, flow: Flow, tool: str):
        if tool == "jwt":
            self.fuzzer_tab.add_jwt_tab(
                raw=flow.raw_request, use_tls=(flow.scheme == "https"))
            self.tabs.setCurrentIndex(3)
            return
        if tool == "otp":
            self.fuzzer_tab.add_otp_tab(
                raw=flow.raw_request, use_tls=(flow.scheme == "https"))
            self.tabs.setCurrentIndex(3)
            return
        if tool == "cors":
            self.fuzzer_tab.add_cors_tab(
                raw=flow.raw_request, use_tls=(flow.scheme == "https"))
            self.tabs.setCurrentIndex(3)
            return
        if tool in ("sqli", "xss", "lfi", "cmdi", "ssti", "redirect", "nosql", "crlf"):
            _type_map = {
                "sqli": "SQLi", "xss": "XSS", "lfi": "LFI", "cmdi": "CMDi",
                "ssti": "SSTI", "redirect": "Open Redirect",
                "nosql": "NoSQL", "crlf": "CRLF",
            }
            self.fuzzer_tab.add_injection_tab(
                raw=flow.raw_request,
                use_tls=(flow.scheme == "https"),
                vuln_type=_type_map[tool],
            )
            self.tabs.setCurrentIndex(3)
            return
        self.send_to_fuzzer(flow)

    # ------------------------------------------------------------------ #
    # Navegador / CA
    # ------------------------------------------------------------------ #
    _CA_INSTALLED_FLAG = os.path.join(
        os.path.expanduser("~"), ".leech", "ca_keychain_installed")

    def _find_browser(self) -> str | None:
        if sys.platform == "win32":
            candidates = [
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%LOCALAPPDATA%\Chromium\Application\chrome.exe"),
                shutil.which("chrome"),
                shutil.which("chromium"),
            ]
        elif sys.platform == "darwin":
            candidates = [
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                shutil.which("chromium"),
                shutil.which("google-chrome"),
            ]
        else:
            candidates = [
                shutil.which("chromium"),
                shutil.which("chromium-browser"),
                shutil.which("google-chrome"),
                shutil.which("google-chrome-stable"),
            ]
        return next((p for p in candidates if p and os.path.isfile(p)), None)

    def _ca_keychain_installed(self) -> bool:
        return os.path.exists(self._CA_INSTALLED_FLAG)

    def _install_ca_to_keychain(self) -> bool:
        if not os.path.exists(CA_CERT_FILE):
            return False
        try:
            if sys.platform == "darwin":
                result = subprocess.run([
                    "security", "add-trusted-cert",
                    "-d", "-r", "trustRoot",
                    "-k", os.path.expanduser("~/Library/Keychains/login.keychain-db"),
                    CA_CERT_FILE,
                ], capture_output=True, timeout=60)
                ok = result.returncode == 0
            elif sys.platform == "win32":
                result = subprocess.run(
                    ["certutil", "-addstore", "-user", "Root", CA_CERT_FILE],
                    capture_output=True, timeout=60,
                )
                ok = result.returncode == 0
            else:
                # Linux: instalar en NSS db de Chromium/Chrome
                nssdb = os.path.expanduser("~/.pki/nssdb")
                certutil_bin = shutil.which("certutil")
                if os.path.isdir(nssdb) and certutil_bin:
                    r = subprocess.run([
                        certutil_bin, "-d", f"sql:{nssdb}",
                        "-A", "-n", "Leetch CA", "-t", "CT,,", "-i", CA_CERT_FILE,
                    ], capture_output=True, timeout=30)
                    ok = r.returncode == 0
                else:
                    ok = False
            if ok:
                open(self._CA_INSTALLED_FLAG, "w").close()
            return ok
        except Exception:
            return False

    _BROWSER_PROFILE_DIR = os.path.join(os.path.expanduser("~"), ".leech", "browser_profile")

    def _ensure_ca_ready(self):
        from proxy.ca import ensure_ca
        if not os.path.exists(CA_CERT_FILE):
            t = threading.Thread(target=ensure_ca, daemon=True)
            t.start()
            t.join(timeout=15)

    def _ca_spki_hash(self) -> str | None:
        """SHA-256 SPKI hash de la CA para --ignore-certificate-errors-spki-list."""
        if not os.path.exists(CA_CERT_FILE):
            return None
        try:
            import hashlib, base64
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives import serialization as _ser
            with open(CA_CERT_FILE, "rb") as f:
                cert = _x509.load_pem_x509_certificate(f.read())
            pub_der = cert.public_key().public_bytes(
                _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo
            )
            return base64.b64encode(hashlib.sha256(pub_der).digest()).decode()
        except Exception:
            return None

    def _setup_browser_profile(self, profile_dir: str) -> None:
        """Siembra la CA en el perfil dedicado del navegador (silencioso, sin diálogos)."""
        flag = os.path.join(profile_dir, ".ca_trusted")
        if os.path.exists(flag):
            return
        if not os.path.exists(CA_CERT_FILE):
            return
        os.makedirs(profile_dir, exist_ok=True)
        try:
            if sys.platform == "linux":
                certutil_bin = shutil.which("certutil")
                if certutil_bin:
                    # Inicializar NSS db dentro del perfil si aún no existe
                    if not os.path.exists(os.path.join(profile_dir, "cert9.db")):
                        subprocess.run(
                            [certutil_bin, "-d", f"sql:{profile_dir}",
                             "-N", "--empty-password"],
                            capture_output=True, timeout=10,
                        )
                    r = subprocess.run([
                        certutil_bin, "-d", f"sql:{profile_dir}",
                        "-A", "-n", "Leetch CA", "-t", "CT,,", "-i", CA_CERT_FILE,
                    ], capture_output=True, timeout=10)
                    if r.returncode == 0:
                        open(flag, "w").close()
                    # También sembrar en ~/.pki/nssdb para que Firefox y Chrome del sistema confíen
                    nssdb = os.path.expanduser("~/.pki/nssdb")
                    if os.path.isdir(nssdb):
                        subprocess.run([
                            certutil_bin, "-d", f"sql:{nssdb}",
                            "-A", "-n", "Leetch CA", "-t", "CT,,", "-i", CA_CERT_FILE,
                        ], capture_output=True, timeout=10)
            elif sys.platform == "darwin":
                if not self._ca_keychain_installed():
                    if self._install_ca_to_keychain():
                        open(flag, "w").close()
            elif sys.platform == "win32":
                if not self._ca_keychain_installed():
                    if self._install_ca_to_keychain():
                        open(flag, "w").close()
        except Exception:
            pass

    def launch_browser(self):
        browser = self._find_browser()
        if not browser:
            QMessageBox.warning(
                self, "Navegador no encontrado",
                "No se encontró Chromium ni Google Chrome instalado.\n\n"
                "Instala Chromium (preferido) o Chrome y vuelve a intentarlo.",
            )
            return

        self._ensure_ca_ready()
        profile_dir = self._BROWSER_PROFILE_DIR
        self._setup_browser_profile(profile_dir)

        args = [
            browser,
            f"--proxy-server=http://{self._proxy_host}:{self._proxy_port}",
            # <-loopback> anula la regla hardcoded de Chrome que excluye
            # localhost/127.0.0.1 del proxy — necesario para capturar apps locales.
            "--proxy-bypass-list=<-loopback>",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
        ]
        spki = self._ca_spki_hash()
        if spki:
            args.append(f"--ignore-certificate-errors-spki-list={spki}")
        try:
            subprocess.Popen(args)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Error al lanzar el navegador", str(exc))

    def install_ca(self):
        if not os.path.exists(CA_CERT_FILE):
            QMessageBox.information(
                self, "CA no generada",
                "Espera a que llegue la primera petición HTTPS para que se genere la CA.",
            )
            return
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", CA_CERT_FILE])
                msg = (
                    f"Se ha abierto el certificado en Keychain Access.\n\n"
                    f"Haz doble clic en 'Leetch CA' → 'Confiar' → "
                    f"'Al usar este certificado: Confiar siempre'.\n\n"
                    f"Ruta: {CA_CERT_FILE}"
                )
            elif sys.platform == "win32":
                os.startfile(CA_CERT_FILE)
                msg = (
                    f"Se ha abierto el asistente de instalación de Windows.\n\n"
                    f"Selecciona 'Instalar certificado' → 'Equipo local' → "
                    f"'Entidades de certificación raíz de confianza'.\n\n"
                    f"Ruta: {CA_CERT_FILE}"
                )
            else:
                nssdb = os.path.expanduser("~/.pki/nssdb")
                certutil_bin = shutil.which("certutil")
                if os.path.isdir(nssdb) and certutil_bin:
                    r = subprocess.run([
                        certutil_bin, "-d", f"sql:{nssdb}",
                        "-A", "-n", "Leetch CA", "-t", "CT,,", "-i", CA_CERT_FILE,
                    ], capture_output=True, timeout=30)
                    if r.returncode == 0:
                        open(self._CA_INSTALLED_FLAG, "w").close()
                        msg = "CA instalada en Chromium/Chrome (NSS).\n\nReinicia el navegador para que surta efecto."
                    else:
                        msg = (
                            f"No se pudo instalar automáticamente.\n\n"
                            f"Ejecuta manualmente:\n"
                            f"  certutil -d sql:{nssdb} -A -n 'Leetch CA' -t 'CT,,' -i {CA_CERT_FILE}\n\n"
                            f"Ruta del certificado: {CA_CERT_FILE}"
                        )
                else:
                    msg = (
                        f"Ruta del certificado:\n{CA_CERT_FILE}\n\n"
                        f"Para Chrome/Chromium: instala 'libnss3-tools' y ejecuta:\n"
                        f"  certutil -d sql:~/.pki/nssdb -A -n 'Leetch CA' -t 'CT,,' -i {CA_CERT_FILE}\n\n"
                        f"Para Firefox: Preferencias → Privacidad → Ver certificados → Importar."
                    )
                    try:
                        subprocess.Popen(["xdg-open", os.path.dirname(CA_CERT_FILE)])
                    except Exception:
                        pass
            QMessageBox.information(self, "Instalar CA", msg)
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def closeEvent(self, event):
        if self.proxy:
            self.proxy.stop()
        super().closeEvent(event)


def main():
    # Delegar diálogos de archivo al entorno de escritorio nativo (COSMIC, GNOME, KDE…)
    if sys.platform.startswith("linux"):
        os.environ.setdefault("QT_QPA_PLATFORMTHEME", "xdgdesktopportal")
    app = QApplication(sys.argv)
    app.setApplicationName("Leetch")
    app.setApplicationDisplayName("Leetch")
    # Necesario para que GNOME/Cosmic emparejen la ventana con leetch.desktop
    app.setDesktopFileName("leetch")
    app.setWindowIcon(QIcon(str(_ASSETS / "logo.png")))
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
