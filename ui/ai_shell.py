"""Pestaña IA para Leetch.

Abre, al mostrarse, una shell real del sistema embebida (pseudo-TTY) lista para
lanzar `claude` (Claude Code) o cualquier otra IA de terminal.  Antes de
arrancar genera un directorio de contexto con:

  - CLAUDE.md          → descripción de Leetch, sus herramientas y el objetivo
                         de auditoría, más un índice del HTTP History.
  - http_history/      → un fichero por petición con la request y la response
                         completas (descomprimidas), para que la IA tenga
                         acceso total al tráfico interceptado.

La shell arranca en ese directorio, así que `claude` lee CLAUDE.md
automáticamente y puede inspeccionar http_history/ a voluntad.

El render del terminal usa **pyte** (emulador VT100 en Python puro): mantiene
la matriz de pantalla real (posicionamiento de cursor, pantalla alternativa,
colores…) y se vuelca a HTML, por lo que las TUIs como claude se ven bien.
"""
from __future__ import annotations

import html as _html
import os
import signal
import struct
import subprocess
import tempfile
import threading
from datetime import datetime
from typing import Callable

try:                       # POSIX: terminal embebido real
    import pty
    import select
    import termios
    import fcntl
    _PTY_OK = True
except ImportError:        # Windows: solo terminal del sistema externo
    _PTY_OK = False

try:
    import pyte
    _PYTE_OK = True
except ImportError:
    _PYTE_OK = False

from PySide6.QtCore import Qt, Signal, Slot, QTimer
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QApplication, QMenu,
)

from ui.style import MONO, BG_DEEP, TEXT, decode, decode_http

# Paleta para los 8 colores ANSI nombrados (tono acorde al tema oscuro).
_PALETTE = {
    "black":   "#3a3f4a",
    "red":     "#ff6b6b",
    "green":   "#5fd38a",
    "brown":   "#e5c07b",   # amarillo
    "blue":    "#61afef",
    "magenta": "#c678dd",
    "cyan":    "#56b6c2",
    "white":   "#dfe3ea",
}


def _css_color(value: str, default: str) -> str:
    if not value or value == "default":
        return default
    if value in _PALETTE:
        return _PALETTE[value]
    if len(value) == 6:            # hex de 256-color / truecolor
        try:
            int(value, 16)
            return "#" + value
        except ValueError:
            pass
    return default


# Teclas especiales → bytes que espera un PTY (xterm).
_SPECIAL_KEYS = {
    Qt.Key_Up: b'\x1b[A', Qt.Key_Down: b'\x1b[B',
    Qt.Key_Right: b'\x1b[C', Qt.Key_Left: b'\x1b[D',
    Qt.Key_Home: b'\x1b[H', Qt.Key_End: b'\x1b[F',
    Qt.Key_PageUp: b'\x1b[5~', Qt.Key_PageDown: b'\x1b[6~',
    Qt.Key_Delete: b'\x1b[3~', Qt.Key_Insert: b'\x1b[2~',
    Qt.Key_Backspace: b'\x7f', Qt.Key_Tab: b'\t',
    Qt.Key_Return: b'\r', Qt.Key_Enter: b'\r', Qt.Key_Escape: b'\x1b',
}


# ---------------------------------------------------------------------------
# Vista de terminal: reenvía pulsaciones crudas al PTY; el contenido se pinta
# por HTML desde AIShellTab (matriz de pyte).
# ---------------------------------------------------------------------------
class _TerminalView(QTextEdit):
    key_bytes = Signal(bytes)

    def __init__(self):
        super().__init__()
        self.setFont(MONO)
        self.setObjectName("terminalOutput")
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.NoWrap)
        self.setUndoRedoEnabled(False)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def keyPressEvent(self, e):
        mods = e.modifiers()
        key = e.key()

        if (mods & Qt.ControlModifier) and (mods & Qt.ShiftModifier):
            if key == Qt.Key_C:
                self.copy()
                return
            if key == Qt.Key_V:
                self._paste()
                return

        if mods & Qt.ControlModifier and Qt.Key_A <= key <= Qt.Key_Z:
            self.key_bytes.emit(bytes([key - Qt.Key_A + 1]))
            return

        if key in _SPECIAL_KEYS:
            self.key_bytes.emit(_SPECIAL_KEYS[key])
            return

        text = e.text()
        if text:
            self.key_bytes.emit(text.encode('utf-8'))

    def _paste(self):
        text = QApplication.clipboard().text()
        if text:
            self.key_bytes.emit(text.encode('utf-8'))

    def _menu(self, pos):
        menu = QMenu(self)
        cp = menu.addAction("Copiar")
        cp.setEnabled(self.textCursor().hasSelection())
        cp.triggered.connect(self.copy)
        menu.addAction("Pegar").triggered.connect(self._paste)
        menu.exec(self.viewport().mapToGlobal(pos))


# ---------------------------------------------------------------------------
# Pestaña principal
# ---------------------------------------------------------------------------
class AIShellTab(QWidget):
    """Terminal del sistema embebida con contexto del HTTP History para la IA."""

    _output_sig = Signal(bytes)

    def __init__(self):
        super().__init__()
        self._master_fd: int | None = None
        self._process: subprocess.Popen | None = None
        self._tmpdir: str | None = None
        self._flows_getter: Callable | None = None
        self._started = False
        self._last_count = -1

        self._screen = pyte.Screen(100, 30) if _PYTE_OK else None
        self._stream = pyte.ByteStream(self._screen) if _PYTE_OK else None
        self._dirty = False

        self._output_sig.connect(self._on_output)
        self._build_ui()

        self._render_timer = QTimer(self)
        self._render_timer.setInterval(30)
        self._render_timer.timeout.connect(self._render_if_dirty)

        self._ctx_timer = QTimer(self)
        self._ctx_timer.setInterval(4000)
        self._ctx_timer.timeout.connect(self._auto_refresh)

    # ------------------------------------------------------------------ #
    def set_flows_getter(self, getter: Callable) -> None:
        self._flows_getter = getter

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(8)

        self.refresh_btn = QPushButton("↻  Actualizar contexto")
        self.refresh_btn.setToolTip(
            "Regenera CLAUDE.md y http_history/ con el tráfico más reciente")
        self.refresh_btn.clicked.connect(self._manual_refresh)
        top.addWidget(self.refresh_btn)

        self.systerm_btn = QPushButton("⊞  Terminal del sistema")
        self.systerm_btn.setToolTip(
            "Abre el directorio de contexto en la terminal nativa del sistema")
        self.systerm_btn.clicked.connect(self._open_system_terminal)
        top.addWidget(self.systerm_btn)

        self.restart_btn = QPushButton("Reiniciar shell")
        self.restart_btn.setToolTip("Cierra la shell actual y abre una nueva")
        self.restart_btn.clicked.connect(self._restart)
        top.addWidget(self.restart_btn)

        top.addStretch()

        self.status_label = QLabel("Iniciando terminal…")
        self.status_label.setObjectName("paneCaption")
        top.addWidget(self.status_label)

        root.addLayout(top)

        self.term = _TerminalView()
        self.term.key_bytes.connect(self._write_pty)
        root.addWidget(self.term, 1)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._started:
            self._started = True
            if _PTY_OK and _PYTE_OK:
                QTimer.singleShot(0, self.launch)
            else:
                missing = "pyte" if not _PYTE_OK else "pty"
                self.term.setPlainText(
                    f"[Terminal embebida no disponible: falta {missing}]\n"
                    "Usa «Terminal del sistema» para abrir claude con el contexto.")
                self.status_label.setText("Terminal embebida no disponible")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_winsize()

    # ------------------------------------------------------------------ #
    # Generación de contexto
    # ------------------------------------------------------------------ #
    def _flows(self):
        return self._flows_getter() if self._flows_getter else []

    def _build_claude_md(self, flows) -> str:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = [
            "# Leetch — Contexto de auditoría de seguridad web",
            f"_Generado: {ts}_",
            "",
            "Estás dentro de **Leetch**, un proxy de interceptación HTTP/HTTPS "
            "(estilo Burp/Caido) para pentesting web. Tienes acceso completo al "
            "tráfico interceptado y debes actuar como experto en seguridad ofensiva.",
            "",
            "## Herramientas de Leetch disponibles para el usuario",
            "- **Intercept** — pausa, edita y reenvía peticiones en vuelo.",
            "- **HTTP History** — registro completo del tráfico (búsqueda, etiquetas, notas).",
            "- **Repeater** — reenvío y edición manual de peticiones HTTP.",
            "- **Tools → Fuzzing** — fuzzing con wordlists y marcadores `§…§` en la petición.",
            "- **Tools → Race Conditions** — N peticiones simultáneas para condiciones de carrera.",
            "- **Tools → JWT Auditor** — decodifica JWT y bruteforce de secreto HS256/384/512.",
            "- **Tools → Decoder** — transformaciones encadenadas (base64, url, hex, hashes) + JWT.",
            "- **Tools → Matcher** — reglas Match & Replace sobre petición/respuesta.",
            "",
            "## Acceso al tráfico interceptado",
            "El tráfico completo está en la carpeta **`http_history/`** de este "
            "directorio: un fichero `flow_NNNN.http` por petición, con la request "
            "y la response completas (ya descomprimidas). Léelos para analizar a fondo.",
            "",
        ]

        if not flows:
            lines += [
                "_Aún no hay peticiones interceptadas. Pide al usuario que navegue "
                "con el navegador integrado (Ajustes → Abrir navegador) y luego pulsa "
                "«Actualizar contexto»._",
                "",
            ]
        else:
            lines += [
                f"### Índice — {len(flows)} peticiones",
                "",
                "| # | Método | URL | Estado | Bytes | Fichero |",
                "|---|--------|-----|--------|-------|---------|",
            ]
            for f in flows:
                url = f.url[:90] + "…" if len(f.url) > 90 else f.url
                lines.append(
                    f"| {f.id} | `{f.method}` | {url} | {f.status} | {f.length} "
                    f"| `http_history/flow_{f.id:04d}.http` |")
            lines.append("")

        lines += [
            "## Objetivo",
            "Analiza el tráfico y, como pentester, identifica y explica:",
            "",
            "- Vulnerabilidades: SQLi, XSS, IDOR, SSRF, SSTI, open redirect, "
            "auth bypass, CSRF, deserialización, etc.",
            "- Tokens, credenciales, claves o datos sensibles expuestos.",
            "- Cabeceras de seguridad ausentes o mal configuradas.",
            "- Endpoints y parámetros interesantes para profundizar.",
            "",
            "Para cada hallazgo propón **payloads concretos** y di con qué "
            "herramienta de Leetch probarlos (Repeater, Fuzzing, Matcher…).",
        ]
        return "\n".join(lines)

    def _write_history_files(self, flows):
        hist_dir = os.path.join(self._tmpdir, 'http_history')
        if os.path.isdir(hist_dir):
            for fn in os.listdir(hist_dir):
                try:
                    os.remove(os.path.join(hist_dir, fn))
                except OSError:
                    pass
        else:
            os.makedirs(hist_dir, exist_ok=True)

        for fl in flows:
            path = os.path.join(hist_dir, f'flow_{fl.id:04d}.http')
            head = f"# Flow #{fl.id}  {fl.method} {fl.url}\n# Estado: {fl.status}  ·  Bytes: {fl.length}"
            if fl.label:
                head += f"  ·  Etiqueta: {fl.label}"
            if fl.comment:
                head += f"  ·  Nota: {fl.comment}"
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(head + "\n\n")
                    f.write("===== REQUEST =====\n")
                    f.write(decode(fl.raw_request))
                    f.write("\n\n===== RESPONSE =====\n")
                    f.write(decode_http(fl.raw_response))
            except OSError:
                pass

    def _write_context(self) -> str:
        if not self._tmpdir or not os.path.isdir(self._tmpdir):
            self._tmpdir = tempfile.mkdtemp(prefix='leetch_ai_')

        flows = self._flows()
        with open(os.path.join(self._tmpdir, 'CLAUDE.md'), 'w', encoding='utf-8') as f:
            f.write(self._build_claude_md(flows))
        self._write_history_files(flows)
        self._last_count = len(flows)
        return self._tmpdir

    def _manual_refresh(self):
        self._write_context()
        self._notify(
            f"[Leetch] Contexto actualizado — {self._last_count} peticiones en http_history/")

    def _auto_refresh(self):
        if not self._tmpdir:
            return
        if len(self._flows()) != self._last_count:
            self._write_context()

    def _notify(self, msg: str):
        """Inyecta un aviso de Leetch en el flujo del terminal."""
        if self._stream is not None:
            self._stream.feed(f"\r\n\x1b[38;5;208m{msg}\x1b[0m\r\n".encode())
            self._dirty = True

    # ------------------------------------------------------------------ #
    # Terminal del sistema (externa)
    # ------------------------------------------------------------------ #
    def _open_system_terminal(self):
        import platform
        import shutil
        cwd = self._write_context()
        sysname = platform.system()
        try:
            if sysname == 'Darwin':
                subprocess.Popen(['open', '-a', 'Terminal', cwd])
            elif sysname == 'Windows':
                subprocess.Popen('start cmd', cwd=cwd, shell=True)
            else:
                launched = False
                for term in ('x-terminal-emulator', 'gnome-terminal', 'konsole',
                             'xfce4-terminal', 'alacritty', 'kitty', 'xterm'):
                    if shutil.which(term):
                        if term == 'gnome-terminal':
                            subprocess.Popen([term, '--working-directory', cwd])
                        elif term == 'konsole':
                            subprocess.Popen([term, '--workdir', cwd])
                        else:
                            subprocess.Popen([term], cwd=cwd)
                        launched = True
                        break
                if not launched:
                    self._notify("[No se encontró un emulador de terminal]")
                    return
        except Exception as exc:  # noqa: BLE001
            self._notify(f"[No se pudo abrir la terminal del sistema: {exc}]")
            return
        self._notify(f"[Leetch] Terminal del sistema abierta en: {cwd}")

    # ------------------------------------------------------------------ #
    # Gestión del proceso / PTY
    # ------------------------------------------------------------------ #
    def launch(self):
        if not (_PTY_OK and _PYTE_OK):
            return
        if self._process and self._process.poll() is None:
            self._kill_process()
        cwd = self._write_context()
        self._screen.reset()
        self.term.clear()
        self._start_shell(cwd)

    def _start_shell(self, cwd: str):
        try:
            master, slave = pty.openpty()
        except Exception as exc:  # noqa: BLE001
            self.term.setPlainText(f"[Error al crear PTY: {exc}]")
            return

        env = os.environ.copy()
        env['TERM'] = 'xterm-256color'
        env['COLORTERM'] = 'truecolor'

        shell = os.environ.get('SHELL', '/bin/bash')
        banner = (
            'printf "\\033[1;38;5;208m  Leetch AI\\033[0m  ·  shell del sistema '
            'con contexto del HTTP History\\n" && '
            'printf "  Directorio: ' + cwd + '\\n" && '
            'printf "  Ejecuta: \\033[1mclaude\\033[0m  '
            '(lee CLAUDE.md y http_history/ automáticamente)\\n\\n"'
        )
        init = f'cd {cwd!r} && {banner} && exec {shell} -i'

        try:
            self._process = subprocess.Popen(
                [shell, '-c', init],
                stdin=slave, stdout=slave, stderr=slave,
                cwd=cwd, env=env, close_fds=True,
                preexec_fn=os.setsid,
            )
        except Exception as exc:  # noqa: BLE001
            os.close(master)
            os.close(slave)
            self.term.setPlainText(f"[Error al lanzar shell: {exc}]")
            return

        os.close(slave)
        self._master_fd = master
        self._update_winsize()

        self.status_label.setText(f"Shell activa  ·  PID {self._process.pid}")
        self.term.setFocus()
        self._render_timer.start()
        self._ctx_timer.start()
        threading.Thread(target=self._read_loop, daemon=True).start()

    def _update_winsize(self):
        if self._master_fd is None or not (_PTY_OK and _PYTE_OK):
            return
        fm = QFontMetrics(self.term.font())
        cw = max(1, fm.horizontalAdvance('M'))
        ch = max(1, fm.height())
        cols = max(20, (self.term.viewport().width() - 4) // cw)
        rows = max(5, (self.term.viewport().height() - 4) // ch)
        if cols == self._screen.columns and rows == self._screen.lines:
            return
        self._screen.resize(rows, cols)
        self._dirty = True
        try:
            fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ,
                        struct.pack('HHHH', rows, cols, 0, 0))
        except OSError:
            pass

    def _read_loop(self):
        fd = self._master_fd
        while True:
            try:
                r, _, _ = select.select([fd], [], [], 0.05)
                if r:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    self._output_sig.emit(chunk)
                elif self._process and self._process.poll() is not None:
                    break
            except OSError:
                break
        self._output_sig.emit(b'\r\n[Shell terminada]\r\n')
        try:
            os.close(fd)
        except OSError:
            pass
        if self._master_fd == fd:
            self._master_fd = None

    @Slot(bytes)
    def _on_output(self, data: bytes):
        if self._stream is not None:
            try:
                self._stream.feed(data)
            except Exception:  # noqa: BLE001
                pass
            self._dirty = True

    def _write_pty(self, data: bytes):
        if self._master_fd is not None:
            try:
                os.write(self._master_fd, data)
            except OSError:
                pass

    def _restart(self):
        self._kill_process()
        if _PTY_OK and _PYTE_OK:
            self.launch()

    def _kill_process(self):
        self._render_timer.stop()
        self._ctx_timer.stop()
        if self._process:
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                try:
                    self._process.kill()
                except OSError:
                    pass
            self._process = None
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None

    # ------------------------------------------------------------------ #
    # Render de la matriz de pyte → HTML
    # ------------------------------------------------------------------ #
    def _render_if_dirty(self):
        if self._dirty:
            self._dirty = False
            self._render()

    def _render(self):
        screen = self._screen
        if screen is None:
            return
        cx, cy = screen.cursor.x, screen.cursor.y
        cursor_on = not screen.cursor.hidden
        rows_html = []
        for y in range(screen.lines):
            row = screen.buffer[y]
            parts = []
            run = ""
            run_style = None
            for x in range(screen.columns):
                cell = row[x]
                data = cell.data or " "
                fg = _css_color(cell.fg, TEXT)
                bg = _css_color(cell.bg, "")
                bold = cell.bold
                if cell.reverse:
                    fg, bg = (bg or BG_DEEP), (fg or TEXT)
                if cursor_on and x == cx and y == cy:
                    fg, bg = BG_DEEP, "#ff8c1a"
                style = (fg, bg, bold)
                if style != run_style:
                    if run:
                        parts.append(self._span(run_style, run))
                    run = ""
                    run_style = style
                run += data
            if run:
                parts.append(self._span(run_style, run))
            rows_html.append("".join(parts))

        body = "\n".join(rows_html)
        html = (
            f'<pre style="margin:0;font-family:\'{MONO.family()}\',monospace;'
            f'font-size:{MONO.pointSize()}pt;color:{TEXT};line-height:100%;">'
            f'{body}</pre>'
        )
        self.term.setHtml(html)

    @staticmethod
    def _span(style, text):
        fg, bg, bold = style
        css = f"color:{fg};"
        if bg:
            css += f"background-color:{bg};"
        if bold:
            css += "font-weight:bold;"
        return f'<span style="{css}">{_html.escape(text, quote=False)}</span>'

    # ------------------------------------------------------------------ #
    def closeEvent(self, event):
        self._kill_process()
        super().closeEvent(event)
