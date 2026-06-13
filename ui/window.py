"""Ventana principal de MiniBurp."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QAction, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QLabel, QTabWidget, QTableWidget, QTableWidgetItem, QSplitter,
    QPlainTextEdit, QSpinBox, QHeaderView, QMenu, QMessageBox,
    QAbstractItemView, QFrame, QFileDialog, QDialog, QDialogButtonBox,
    QFormLayout,
)

from proxy import ProxyServer, Flow, CA_CERT_FILE
from net import http_message as hm
from ui.style import STYLE, ACCENT, TEXT_DIM, MONO, decode, status_color
from ui.repeater import RepeaterTab, RepeaterWorker
from ui.fuzzer import FuzzerTab
import session

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8080


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
# Shims para compatibilidad con session.py
# ---------------------------------------------------------------------------
class _StrProxy:
    """Hace que session.py pueda leer/escribir el host como un QLineEdit."""
    def __init__(self, window: "MainWindow"):
        self._w = window

    def text(self) -> str:
        return self._w._proxy_host

    def setText(self, v: str):
        self._w._proxy_host = v


class _IntProxy:
    """Hace que session.py pueda leer/escribir el puerto como un QSpinBox."""
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
        self.setWindowTitle("MiniBurp")
        self.resize(1200, 800)

        self.flows: list[Flow] = []
        self._flow_by_id: dict[int, Flow] = {}
        self.proxy: ProxyServer | None = None
        self._proxy_host = _DEFAULT_HOST
        self._proxy_port = _DEFAULT_PORT

        self.bridge = FlowBridge()
        self.bridge.flow_received.connect(self.add_flow)

        self.rep_worker = RepeaterWorker()
        self.rep_worker.finished.connect(
            lambda tab, resp, el: tab.on_response(resp, el))
        self.rep_worker.failed.connect(
            lambda tab, msg: tab.on_error(msg))

        self._build_menu()
        self._build_ui()
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

        help_menu = menubar.addMenu("A&yuda")

        howto_action = QAction("Cómo usar MiniBurp", self)
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
            self, "Guardar sesión", "sesion_miniburp.json",
            "Sesión MiniBurp (*.json);;Todos los archivos (*)",
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
            "Sesión MiniBurp (*.json);;Todos los archivos (*)",
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
        )
        try:
            self.proxy.start()
            self.status_label.setText(
                f"● Escuchando en {self._proxy_host}:{self._proxy_port}")
            self.status_label.setProperty("state", "running")
        except Exception as exc:  # noqa: BLE001
            self.proxy = None
            self.status_label.setText("● Error al iniciar")
            self.status_label.setProperty("state", "stopped")
            QMessageBox.critical(
                self, "No se pudo iniciar el proxy",
                f"Puerto {self._proxy_port} no disponible:\n{exc}\n\n"
                "Cámbialo en Ajustes → Configuración del proxy.",
            )
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ #
    # Ayuda / CA
    # ------------------------------------------------------------------ #
    def show_help(self):
        text = (
            "<h3>Cómo usar MiniBurp</h3>"
            "<p><b>1. Proxy automático.</b> MiniBurp intercepta tráfico en "
            f"<code>{_DEFAULT_HOST}:{_DEFAULT_PORT}</code> nada más abrir. "
            "Cambia la dirección en <i>Ajustes → Configuración del proxy</i>.</p>"
            "<p><b>2. Enviar tráfico.</b> Configura tu navegador para usar ese proxy, "
            "o pulsa <i>Abrir navegador</i> para lanzar Chrome ya preconfigurado.</p>"
            "<p><b>3. HTTPS / CA.</b> Instala la CA desde "
            "<i>Ajustes → Instalar CA</i> y confía en <i>MiniBurp CA</i>.</p>"
            "<p><b>4. HTTP History.</b> Cada petición aparece en la tabla. "
            "Selecciona una fila para ver petición y respuesta.</p>"
            "<p><b>5. Repeater.</b> Doble clic o botón <i>Enviar al Repeater</i>. "
            "Edita la petición y pulsa <i>Enviar</i> (Ctrl+Intro).</p>"
            "<p><b>6. Fuzzer.</b> Clic derecho → <i>Enviar al Fuzzer</i>, marca la "
            "zona con §…§, carga una wordlist y pulsa <i>▶ Iniciar</i>.</p>"
            "<p><b>7. Sesiones.</b> Ctrl+S para guardar, Ctrl+O para cargar.</p>"
        )
        box = QMessageBox(self)
        box.setWindowTitle("Cómo usar MiniBurp")
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
            "<p>El certificado CA de MiniBurp se encuentra en:</p>"
            f"<p><code>{CA_CERT_FILE}</code></p>"
            f"<p>{estado}</p>"
        )
        box.exec()

    def show_about(self):
        QMessageBox.about(
            self, "Acerca de MiniBurp",
            "<h3>MiniBurp</h3>"
            "<p>Mini proxy de interceptación HTTP/HTTPS con History, Repeater y Fuzzer.</p>"
            "<p>Inspirado en Burp Suite, para aprendizaje y pruebas locales.</p>"
        )

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        # Encabezado
        header = QHBoxLayout()
        header.setSpacing(8)
        brand = QLabel("Mini<span style='color:%s'>Burp</span>" % ACCENT)
        brand.setObjectName("brand")
        brand.setTextFormat(Qt.RichText)
        header.addWidget(brand)
        tagline = QLabel("Proxy de interceptación  ·  HTTP History  ·  Repeater  ·  Fuzzer")
        tagline.setObjectName("tagline")
        header.addWidget(tagline)
        header.addStretch()
        outer.addLayout(header)

        # Barra de estado (sin botón de toggle — el proxy siempre está activo)
        control_bar = QFrame()
        control_bar.setObjectName("controlBar")
        control = QHBoxLayout(control_bar)
        control.setContentsMargins(10, 8, 10, 8)
        control.setSpacing(8)
        self.status_label = QLabel("● Iniciando…")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setProperty("state", "stopped")
        self.status_label.setAccessibleName("Estado del proxy")
        control.addWidget(self.status_label)
        control.addStretch()
        self.browser_btn = QPushButton("Abrir navegador")
        self.browser_btn.setAccessibleName("Abrir navegador integrado")
        self.browser_btn.setToolTip("Lanza Chrome/Chromium preconfigurado contra el proxy")
        self.browser_btn.clicked.connect(self.launch_browser)
        control.addWidget(self.browser_btn)
        self.ca_btn = QPushButton("Instalar CA")
        self.ca_btn.setAccessibleName("Instalar certificado CA")
        self.ca_btn.setToolTip("Abre el certificado CA para instalarlo en el sistema")
        self.ca_btn.clicked.connect(self.install_ca)
        control.addWidget(self.ca_btn)
        outer.addWidget(control_bar)

        # Pestañas principales
        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)

        self.tabs.addTab(self._build_history_tab(), "HTTP History")
        self.tabs.addTab(self._build_repeater_container(), "Repeater")
        self.fuzzer_tab = FuzzerTab()
        self.tabs.addTab(self.fuzzer_tab, "Fuzzer")

        self.add_repeater_tab()  # pestaña inicial vacía

    def _build_history_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["#", "Método", "Host", "URL", "Estado", "Long."])
        self.table.setAccessibleName("Historial HTTP")
        self.table.setToolTip("Peticiones interceptadas; doble clic o clic derecho para más opciones")
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
        action_row.addStretch()

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

        # "+" integrado en la barra de pestañas del Repeater
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
                  flow.status, str(flow.length)]
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
        if self.table.rowCount() == 1:
            self.table.selectRow(0)

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
        self.hist_response.setPlainText(decode(flow.raw_response))

    def show_history_menu(self, pos):
        flow = self._selected_flow()
        if not flow:
            return
        menu = QMenu(self)
        send_rep = QAction("Enviar al Repeater", self)
        send_rep.triggered.connect(lambda: self.send_to_repeater(flow))
        menu.addAction(send_rep)
        send_fuzz = QAction("Enviar al Fuzzer", self)
        send_fuzz.triggered.connect(lambda: self.send_to_fuzzer(flow))
        menu.addAction(send_fuzz)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------ #
    # Repeater / Fuzzer
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
        self.tabs.setCurrentIndex(1)

    def send_to_fuzzer(self, flow: Flow):
        self.fuzzer_tab.load_from_flow(
            host=flow.host, port=flow.port,
            use_tls=(flow.scheme == "https"),
            raw=flow.raw_request,
        )
        self.tabs.setCurrentIndex(2)

    # ------------------------------------------------------------------ #
    # Navegador / CA
    # ------------------------------------------------------------------ #
    def _find_browser(self) -> str | None:
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            shutil.which("chromium"),
            shutil.which("chromium-browser"),
            shutil.which("google-chrome"),
            shutil.which("google-chrome-stable"),
        ]
        return next((p for p in candidates if p and os.path.isfile(p)), None)

    def launch_browser(self):
        browser = self._find_browser()
        if not browser:
            QMessageBox.warning(
                self, "Navegador no encontrado",
                "No se encontró Google Chrome ni Chromium instalado.\n"
                "Instala Chrome o Chromium y vuelve a intentarlo.",
            )
            return
        profile_dir = os.path.join(tempfile.gettempdir(), "miniburp_browser_profile")
        args = [
            browser,
            f"--proxy-server={self._proxy_host}:{self._proxy_port}",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--ignore-certificate-errors",
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
                f"Haz doble clic en 'MiniBurp CA' → 'Confiar' → "
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
