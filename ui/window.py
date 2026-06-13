"""Ventana principal de Leech."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QAction, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QTabWidget, QTableWidget, QTableWidgetItem, QSplitter,
    QPlainTextEdit, QSpinBox, QHeaderView, QMenu, QMessageBox,
    QAbstractItemView, QFrame, QFileDialog, QDialog, QDialogButtonBox,
    QFormLayout, QCheckBox, QInputDialog,
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
import session

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8080

# Colores de fondo (tintes oscuros) para las etiquetas del History
_LABEL_BG: dict[str, str] = {
    "rojo":     "#3d1a1a",
    "naranja":  "#3d2a0f",
    "amarillo": "#3d3512",
    "verde":    "#133d1a",
    "azul":     "#0f2340",
    "morado":   "#251340",
}
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
        self.setWindowTitle("Leech")
        self.resize(1200, 800)

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

        howto_action = QAction("Cómo usar Leech", self)
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
            "Sesión Leech (*.json);;Todos los archivos (*)",
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
            "Sesión Leech (*.json);;Todos los archivos (*)",
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
            "<h3>Cómo usar Leech</h3>"
            "<p><b>1. Intercept.</b> Activa el toggle rojo para capturar peticiones "
            "en vuelo, edítalas y pulsa Forward o Drop.</p>"
            "<p><b>2. Proxy automático.</b> Leech intercepta tráfico en "
            f"<code>{_DEFAULT_HOST}:{_DEFAULT_PORT}</code> nada más abrir. "
            "Cambia la dirección en <i>Ajustes → Configuración del proxy</i>.</p>"
            "<p><b>3. Enviar tráfico.</b> Configura tu navegador para usar ese proxy, "
            "o pulsa <i>Abrir navegador</i> para lanzar Chrome ya preconfigurado.</p>"
            "<p><b>4. HTTPS / CA.</b> Instala la CA desde "
            "<i>Ajustes → Instalar CA</i> y confía en <i>Leech CA</i>.</p>"
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
        box.setWindowTitle("Cómo usar Leech")
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
            "<p>El certificado CA de Leech se encuentra en:</p>"
            f"<p><code>{CA_CERT_FILE}</code></p>"
            f"<p>{estado}</p>"
        )
        box.exec()

    def show_about(self):
        QMessageBox.about(
            self, "Acerca de Leech",
            "<h3>Leech</h3>"
            "<p>Mini proxy de interceptación HTTP/HTTPS con Intercept, History, "
            "Repeater, Tools, Matcher, Decoder y Site Map.</p>"
            "<p>Inspirado en Burp Suite, para aprendizaje y pruebas locales.</p>"
        )

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

        # Orden de pestañas:
        #   0 → Intercept        (nuevo, primero)
        #   1 → HTTP History
        #   2 → Repeater
        #   3 → Fuzzer
        #   4 → Match & Replace  (nuevo, último)
        self.intercept_tab = InterceptTab()
        self.tabs.addTab(self.intercept_tab, "Intercept")

        self.tabs.addTab(self._build_history_tab(), "HTTP History")
        self.tabs.addTab(self._build_repeater_container(), "Repeater")

        self.fuzzer_tab = FuzzerTab()
        self.tabs.addTab(self.fuzzer_tab, "Tools")

        self.ai_tab = AIShellTab()                          # índice 4
        self.ai_tab.set_flows_getter(lambda: self.flows)
        self.tabs.addTab(self.ai_tab, "IA")

        self.mr_tab = MatchReplaceTab()                     # índice 5
        self.tabs.addTab(self.mr_tab, "Matcher")

        self.decoder_tab = DecoderTab()                     # índice 6
        self.tabs.addTab(self.decoder_tab, "Decoder")

        self.sitemap_tab = SiteMapTab()                     # índice 7
        self.sitemap_tab.set_flows_getter(lambda: self.flows)
        self.sitemap_tab.send_to_repeater.connect(self.send_to_repeater)
        self.tabs.addTab(self.sitemap_tab, "Site Map")

        self.add_repeater_tab()  # pestaña inicial vacía en el Repeater

    def _build_history_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["#", "Método", "Host", "URL", "Estado", "Long.", "Comentario"])
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
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        hdr.setHighlightSections(False)
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 80)
        self.table.setColumnWidth(2, 200)
        self.table.setColumnWidth(4, 80)
        self.table.setColumnWidth(5, 90)
        self.table.setColumnWidth(6, 160)
        self.table.itemSelectionChanged.connect(self.on_row_selected)
        self.table.itemDoubleClicked.connect(lambda _: self._send_selected_to_repeater())
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_history_menu)

        action_row = QHBoxLayout()
        self.to_repeater_btn = QPushButton("Enviar al Repeater →")
        self.to_repeater_btn.setEnabled(False)
        self.to_repeater_btn.setAccessibleName("Enviar petición seleccionada al Repeater")
        self.to_repeater_btn.setToolTip(
            "Envía la petición seleccionada al Repeater (también con doble clic)")
        self.to_repeater_btn.clicked.connect(self._send_selected_to_repeater)
        action_row.addWidget(self.to_repeater_btn)

        self.scope_btn = QPushButton("▽  Scope")
        self.scope_btn.setCheckable(True)
        self.scope_btn.setObjectName("scopeBtn")
        self.scope_btn.setAccessibleName("Configurar scope del historial")
        self.scope_btn.setToolTip(
            "Define el scope: solo se mostrarán peticiones que coincidan con "
            "los dominios o URLs configurados")
        self.scope_btn.clicked.connect(self._open_scope_dialog)
        action_row.addWidget(self.scope_btn)

        action_row.addStretch()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Buscar en historial…")
        self.search_edit.setFixedWidth(260)
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setAccessibleName("Buscador del historial HTTP")
        self.search_edit.setToolTip(
            "Filtra por host, URL, método o código de estado (case insensitive)")
        self.search_edit.textChanged.connect(lambda _: self._apply_filters())
        action_row.addWidget(self.search_edit)

        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(8)
        splitter.addWidget(self.table)

        detail = QSplitter(Qt.Horizontal)
        detail.setHandleWidth(8)

        req_box = QWidget()
        req_layout = QVBoxLayout(req_box)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(6)
        req_caption = QLabel("Petición")
        req_caption.setObjectName("paneCaption")
        req_layout.addWidget(req_caption)
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
        resp_layout.setSpacing(6)
        resp_caption = QLabel("Respuesta")
        resp_caption.setObjectName("paneCaption")
        resp_layout.addWidget(resp_caption)
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

        layout.addLayout(action_row)
        layout.addWidget(splitter)
        return container

    def _build_repeater_container(self) -> QWidget:
        self.repeater_tabs = QTabWidget()
        self.repeater_tabs.setTabsClosable(True)
        self.repeater_tabs.tabCloseRequested.connect(
            lambda i: self.repeater_tabs.removeTab(i))

        add_tab_btn = QPushButton("+")
        add_tab_btn.setFixedSize(26, 26)
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
        values = [str(flow.id), flow.method, flow.host, flow.url,
                  flow.status, str(flow.length), flow.comment]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setData(Qt.UserRole, flow.id)
            if col == 0:
                item.setForeground(QColor(TEXT_DIM))
            elif col == 1:
                item.setForeground(QColor("#7fb3ff"))
            elif col == 4:
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
        for tool, label in [("fuzzing", "Fuzzing"), ("race", "Race Conditions"), ("jwt", "JWT Auditor")]:
            act = QAction(label, tools_menu)
            act.triggered.connect(
                lambda checked=False, t=tool: self._send_flow_to_tool(flow, t))
            tools_menu.addAction(act)
        menu.addMenu(tools_menu)

        send_mr = QAction("Enviar al Matcher", self)
        send_mr.triggered.connect(lambda: self.send_to_match_replace(flow))
        menu.addAction(send_mr)

        send_dec = QAction("Enviar al Decoder", self)
        send_dec.setToolTip("Abre la petición en el Decoder para transformar y decodificar valores")
        send_dec.triggered.connect(lambda: self.send_to_decoder(flow))
        menu.addAction(send_dec)

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
        haystack = f"{flow.method} {flow.host} {flow.url} {flow.status}".lower()
        return text in haystack

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
                    item.setData(Qt.BackgroundRole, None)

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
            item = self.table.item(row, 6)
            if item:
                item.setText(flow.comment)

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
        self.repeater_tabs.setCurrentIndex(index)
        return tab

    def send_to_repeater(self, flow: Flow):
        self.add_repeater_tab(flow)
        self.tabs.setCurrentIndex(2)    # Repeater = índice 2

    def send_to_fuzzer(self, flow: Flow):
        self.fuzzer_tab.load_from_flow(
            host=flow.host, port=flow.port,
            use_tls=(flow.scheme == "https"),
            raw=flow.raw_request,
        )
        self.tabs.setCurrentIndex(3)    # Fuzzer = índice 3

    def send_to_match_replace(self, flow: Flow):
        self.tabs.setCurrentIndex(5)    # Matcher = índice 5
        self.mr_tab.open_new_rule_dialog()

    def send_to_decoder(self, flow: Flow):
        self.decoder_tab.load_text(decode(flow.raw_request))
        self.tabs.setCurrentIndex(6)    # Decoder = índice 6

    def _send_flow_to_tool(self, flow: Flow, tool: str):
        if tool == "jwt":
            raw = flow.raw_request.decode("utf-8", "replace")
            jwt_token = ""
            for line in raw.split("\r\n"):
                if line.lower().startswith("authorization: bearer "):
                    jwt_token = line.split(" ", 2)[-1].strip()
                    break
            if jwt_token:
                self.decoder_tab.load_jwt(jwt_token)
                self.tabs.setCurrentIndex(6)
                return
        self.send_to_fuzzer(flow)

    # ------------------------------------------------------------------ #
    # Navegador / CA
    # ------------------------------------------------------------------ #
    _CA_INSTALLED_FLAG = os.path.join(
        os.path.expanduser("~"), ".leech", "ca_keychain_installed")

    def _find_browser(self) -> str | None:
        candidates = [
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
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
            result = subprocess.run([
                "security", "add-trusted-cert",
                "-d", "-r", "trustRoot",
                "-k", os.path.expanduser("~/Library/Keychains/login.keychain-db"),
                CA_CERT_FILE,
            ], capture_output=True, timeout=60)
            if result.returncode == 0:
                open(self._CA_INSTALLED_FLAG, "w").close()
                return True
            return False
        except Exception:
            return False

    def _ensure_ca_ready(self):
        from proxy.ca import ensure_ca
        if not os.path.exists(CA_CERT_FILE):
            t = threading.Thread(target=ensure_ca, daemon=True)
            t.start()
            t.join(timeout=15)

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

        if not self._ca_keychain_installed():
            reply = QMessageBox.question(
                self, "Instalar certificado CA",
                "Para interceptar tráfico HTTPS, Leech necesita que confíes "
                "en su autoridad certificadora.\n\n"
                "macOS te pedirá tu contraseña de usuario (igual que Burp Suite). "
                "¿Instalar ahora?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                ok = self._install_ca_to_keychain()
                if not ok:
                    QMessageBox.warning(
                        self, "CA no instalada",
                        "No se pudo instalar la CA automáticamente.\n"
                        "Ve a Ajustes → Instalar CA para hacerlo manualmente\n"
                        "o abre el navegador igualmente (verás avisos de certificado).",
                    )

        profile_dir = os.path.join(tempfile.gettempdir(), "leech_browser_profile")
        args = [
            browser,
            f"--proxy-server=http://{self._proxy_host}:{self._proxy_port}",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--ignore-certificate-errors",
            "--ignore-ssl-errors",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
        ]
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
            subprocess.Popen(["open", CA_CERT_FILE])
            QMessageBox.information(
                self, "Instalar CA",
                f"Se ha abierto el certificado en Keychain Access.\n\n"
                f"Haz doble clic en 'Leech CA' → 'Confiar' → "
                f"'Al usar este certificado: Confiar siempre'.\n\n"
                f"Ruta: {CA_CERT_FILE}",
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Error", str(exc))

    def closeEvent(self, event):
        if self.proxy:
            self.proxy.stop()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
