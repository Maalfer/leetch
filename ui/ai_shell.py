"""Pestaña IA para Leetch.

Abre una terminal embebida (pseudo-TTY) con un shell del sistema.
Al lanzar, escribe CLAUDE.md con el historial HTTP completo y una guía
de análisis ofensivo, de modo que `claude` arranque con todo el contexto.
"""
from __future__ import annotations

import os
import pty
import re
import select
import signal
import subprocess
import tempfile
import threading
from datetime import datetime
from typing import Callable

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QColor, QFont, QTextCursor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QPlainTextEdit, QLineEdit,
)

from ui.style import MONO, TEXT_DIM

# Regex para filtrar secuencias de escape ANSI (colores, cursor, etc.)
_ANSI_RE = re.compile(
    r'\x1b(?:'
    r'[@-Z\\-_]'                      # secuencias de 2 chars
    r'|\[[\x20-\x3f]*[\x40-\x7e]'    # CSI sequences  (ESC [ ... letra)
    r'|\].*?(?:\x07|\x1b\\)'          # OSC sequences  (ESC ] ... BEL/ST)
    r'|[\x20-\x2f]*[\x30-\x7e]'      # secuencias Fs/Fp/Fe
    r')',
    re.DOTALL,
)


def _strip_ansi(text: str) -> str:
    cleaned = _ANSI_RE.sub('', text)
    # Normalizar saltos de línea del terminal
    cleaned = cleaned.replace('\r\n', '\n').replace('\r', '\n')
    return cleaned


# ---------------------------------------------------------------------------
# Pestaña principal
# ---------------------------------------------------------------------------
class AIShellTab(QWidget):
    """Terminal embebida con shell del sistema y contexto del HTTP History."""

    _output_sig = Signal(str)   # thread-safe: emitido desde hilo lector

    def __init__(self):
        super().__init__()
        self._master_fd: int | None = None
        self._process: subprocess.Popen | None = None
        self._tmpdir: str | None = None
        self._flows_getter: Callable | None = None

        self._output_sig.connect(self._append_output)
        self._build_ui()

    # ------------------------------------------------------------------ #
    # API pública
    # ------------------------------------------------------------------ #
    def set_flows_getter(self, getter: Callable) -> None:
        """Recibe una función () → list[Flow] para leer el HTTP History."""
        self._flows_getter = getter

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Barra superior
        top = QHBoxLayout()
        top.setSpacing(8)

        self.launch_btn = QPushButton("Lanzar Claude con contexto")
        self.launch_btn.setObjectName("primaryButton")
        self.launch_btn.setToolTip(
            "Genera CLAUDE.md con el HTTP History y abre una shell con claude listo para usar")
        self.launch_btn.clicked.connect(self.launch)
        top.addWidget(self.launch_btn)

        self.refresh_btn = QPushButton("Actualizar contexto")
        self.refresh_btn.setToolTip(
            "Regenera CLAUDE.md con las peticiones más recientes del historial")
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.clicked.connect(self._refresh_context)
        top.addWidget(self.refresh_btn)

        self.ctrlc_btn = QPushButton("Ctrl+C")
        self.ctrlc_btn.setToolTip("Envía SIGINT al proceso activo (interrumpir)")
        self.ctrlc_btn.setEnabled(False)
        self.ctrlc_btn.clicked.connect(self._send_ctrl_c)
        top.addWidget(self.ctrlc_btn)

        self.restart_btn = QPushButton("Reiniciar shell")
        self.restart_btn.setToolTip("Cierra el proceso actual y abre una nueva shell")
        self.restart_btn.setEnabled(False)
        self.restart_btn.clicked.connect(self._restart)
        top.addWidget(self.restart_btn)

        top.addStretch()

        self.status_label = QLabel("Terminal inactiva — pulsa «Lanzar Claude con contexto»")
        self.status_label.setObjectName("paneCaption")
        top.addWidget(self.status_label)

        root.addLayout(top)

        # Salida del terminal
        self.output = QPlainTextEdit()
        self.output.setFont(MONO)
        self.output.setReadOnly(True)
        self.output.setObjectName("terminalOutput")
        root.addWidget(self.output, 1)

        # Entrada
        input_row = QHBoxLayout()
        input_row.setSpacing(6)

        self.input_edit = QLineEdit()
        self.input_edit.setFont(MONO)
        self.input_edit.setPlaceholderText(
            "Escribe aquí y pulsa Enter para enviar al shell…")
        self.input_edit.returnPressed.connect(self._send_input)
        self.input_edit.setEnabled(False)
        self.input_edit.installEventFilter(self)
        input_row.addWidget(self.input_edit)

        self.send_btn = QPushButton("Enviar")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self._send_input)
        input_row.addWidget(self.send_btn)

        root.addLayout(input_row)

    def eventFilter(self, obj, event):
        """Intercepta Ctrl+C / Ctrl+D en el input para enviarlos al PTY."""
        from PySide6.QtCore import QEvent
        from PySide6.QtGui import QKeyEvent
        if obj is self.input_edit and event.type() == QEvent.KeyPress:
            key_event: QKeyEvent = event
            if key_event.modifiers() == Qt.ControlModifier:
                if key_event.key() == Qt.Key_C:
                    self._send_ctrl_c()
                    return True
                if key_event.key() == Qt.Key_D:
                    self._write_pty(b'\x04')
                    return True
        return super().eventFilter(obj, event)

    # ------------------------------------------------------------------ #
    # Generación de contexto
    # ------------------------------------------------------------------ #
    def _build_context(self) -> str:
        flows = self._flows_getter() if self._flows_getter else []
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        lines = [
            "# Leetch — Contexto para análisis de seguridad",
            f"_Generado automáticamente: {ts}_",
            "",
            "## Herramienta",
            "**Leetch** es un proxy MITM HTTP/HTTPS para pruebas de seguridad.",
            "Módulos disponibles: Intercept, HTTP History, Repeater, Fuzzer, Match & Replace.",
            "",
        ]

        if not flows:
            lines += [
                "## HTTP History",
                "_Sin peticiones interceptadas todavía._",
                "",
                "Navega con el navegador integrado (Herramientas → Abrir navegador)",
                "para capturar tráfico y luego actualiza el contexto.",
            ]
        else:
            lines += [
                f"## HTTP History — {len(flows)} peticiones interceptadas",
                "",
                "| # | Método | URL | Estado | Bytes |",
                "|---|--------|-----|--------|-------|",
            ]
            for f in flows:
                url_short = f.url[:100] + "…" if len(f.url) > 100 else f.url
                lines.append(
                    f"| {f.id} | `{f.method}` | {url_short} | **{f.status}** | {f.length} |"
                )

            # Detalle de las últimas 15 peticiones
            recent = flows[-15:]
            lines += [
                "",
                f"## Detalle de las últimas {len(recent)} peticiones",
                "",
            ]
            for f in recent:
                req_body = f.raw_request.decode('utf-8', 'replace')
                resp_body = f.raw_response.decode('utf-8', 'replace')
                # Truncar si son muy largas
                if len(req_body) > 4000:
                    req_body = req_body[:4000] + "\n… [truncado]"
                if len(resp_body) > 4000:
                    resp_body = resp_body[:4000] + "\n… [truncado]"
                lines += [
                    f"### Request #{f.id} — {f.method} {f.url}",
                    f"**Estado:** {f.status}  ·  **Bytes:** {f.length}"
                    + (f"  ·  **Etiqueta:** {f.label}" if f.label else "")
                    + (f"  ·  **Nota:** {f.comment}" if f.comment else ""),
                    "",
                    "**Petición HTTP:**",
                    "```http",
                    req_body,
                    "```",
                    "",
                    "**Respuesta HTTP:**",
                    "```http",
                    resp_body,
                    "```",
                    "",
                ]

        lines += [
            "## Objetivo del análisis",
            "Como experto en seguridad ofensiva y pentesting web, analiza el tráfico",
            "HTTP interceptado y:",
            "",
            "- Identifica vulnerabilidades: SQLi, XSS, IDOR, SSRF, SSTI, open redirect, etc.",
            "- Detecta tokens, credenciales o datos sensibles expuestos.",
            "- Señala cabeceras de seguridad ausentes o mal configuradas.",
            "- Sugiere payloads concretos para probar en el **Repeater** o el **Fuzzer**.",
            "- Propone reglas de **Match & Replace** útiles para las pruebas.",
            "",
            "## Comandos de referencia (Leetch)",
            "- Repeater: reenvío manual de peticiones HTTP",
            "- Fuzzer: fuzzing con wordlists, marcadores §…§ en la petición",
            "- Match & Replace: sustitución automática en petición/respuesta",
            "- Intercept: pausa y modificación de peticiones en vuelo",
        ]

        return "\n".join(lines)

    def _write_context(self) -> str:
        """Escribe CLAUDE.md y el script de análisis. Devuelve el path del directorio."""
        if not self._tmpdir or not os.path.isdir(self._tmpdir):
            self._tmpdir = tempfile.mkdtemp(prefix='leech_ai_')

        # Contexto principal
        ctx_path = os.path.join(self._tmpdir, 'CLAUDE.md')
        with open(ctx_path, 'w', encoding='utf-8') as f:
            f.write(self._build_context())

        # Script de análisis rápido
        script_path = os.path.join(self._tmpdir, 'analizar.sh')
        prompt = (
            "Eres un experto en pentesting web. "
            "Lee el archivo CLAUDE.md y analiza el tráfico HTTP interceptado "
            "buscando vulnerabilidades, credenciales expuestas, endpoints críticos "
            "y sugiere ataques concretos con payloads."
        )
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(f'#!/bin/bash\nclaude -p "{prompt}"\n')
        os.chmod(script_path, 0o755)

        return self._tmpdir

    def _refresh_context(self):
        if self._tmpdir:
            self._write_context()
            self._append_output(
                "\n\033[0m[Leetch] Contexto actualizado en CLAUDE.md\n")

    # ------------------------------------------------------------------ #
    # Gestión del proceso / PTY
    # ------------------------------------------------------------------ #
    def launch(self):
        """Lanza (o reinicia) la shell con el contexto del HTTP History."""
        if self._process and self._process.poll() is None:
            self._kill_process()

        cwd = self._write_context()
        self.output.clear()
        self._start_shell(cwd)

    def _start_shell(self, cwd: str):
        try:
            master, slave = pty.openpty()
        except Exception as exc:
            self._append_output(f"[Error al crear PTY: {exc}]\n")
            return

        env = os.environ.copy()
        env['TERM'] = 'xterm-256color'
        env['COLUMNS'] = '120'
        env['LINES'] = '40'

        shell = os.environ.get('SHELL', '/bin/zsh')

        # Comando inicial: muestra banner y lanza un shell interactivo
        banner = (
            'echo "┌─────────────────────────────────────────────────┐" && '
            'echo "│  Leetch AI  —  contexto del HTTP History OK  │" && '
            'echo "└─────────────────────────────────────────────────┘" && '
            'echo "" && '
            f'echo "  Directorio: {cwd}" && '
            'echo "" && '
            'echo "  Comandos disponibles:" && '
            'echo "    claude             → chat interactivo con contexto del historial" && '
            'echo "    bash analizar.sh   → análisis automático del tráfico HTTP" && '
            'echo "    cat CLAUDE.md      → ver el contexto generado" && '
            'echo ""'
        )
        init = f'cd {cwd!r} && {banner} && exec {shell} --login'

        try:
            self._process = subprocess.Popen(
                [shell, '-c', init],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                cwd=cwd,
                env=env,
                close_fds=True,
                preexec_fn=os.setsid,
            )
        except Exception as exc:
            os.close(master)
            os.close(slave)
            self._append_output(f"[Error al lanzar shell: {exc}]\n")
            return

        os.close(slave)
        self._master_fd = master

        self.launch_btn.setText("Reiniciar shell")
        self.refresh_btn.setEnabled(True)
        self.ctrlc_btn.setEnabled(True)
        self.restart_btn.setEnabled(True)
        self.input_edit.setEnabled(True)
        self.send_btn.setEnabled(True)
        self.input_edit.setFocus()
        self.status_label.setText(
            f"Shell activa  ·  PID {self._process.pid}  ·  {cwd}")

        threading.Thread(target=self._read_loop, daemon=True).start()

    def _read_loop(self):
        """Hilo de lectura del PTY — envía datos al slot _append_output via signal."""
        buf = b""
        while True:
            try:
                r, _, _ = select.select([self._master_fd], [], [], 0.05)
                if r:
                    chunk = os.read(self._master_fd, 4096)
                    if not chunk:
                        break
                    buf += chunk
                    # Emitir cuando tengamos datos completos (línea o sin datos pendientes)
                    text = buf.decode('utf-8', 'replace')
                    text = _strip_ansi(text)
                    self._output_sig.emit(text)
                    buf = b""
                elif self._process and self._process.poll() is not None:
                    if buf:
                        self._output_sig.emit(buf.decode('utf-8', 'replace'))
                    self._output_sig.emit('\n[Shell terminada]\n')
                    break
            except OSError:
                break

        try:
            os.close(self._master_fd)
        except OSError:
            pass
        self._master_fd = None

    def _write_pty(self, data: bytes):
        if self._master_fd is not None:
            try:
                os.write(self._master_fd, data)
            except OSError:
                pass

    def _send_input(self):
        text = self.input_edit.text()
        self.input_edit.clear()
        self._write_pty((text + '\n').encode('utf-8'))

    def _send_ctrl_c(self):
        self._write_pty(b'\x03')

    def _restart(self):
        self._kill_process()
        if self._tmpdir:
            self.launch()

    def _kill_process(self):
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
    # Slot de escritura en la terminal
    # ------------------------------------------------------------------ #
    @Slot(str)
    def _append_output(self, text: str):
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()

    def closeEvent(self, event):
        self._kill_process()
        super().closeEvent(event)
