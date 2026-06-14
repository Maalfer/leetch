# MiniBurp — Guía de desarrollo para Claude Code

Proxy MITM HTTP/HTTPS de escritorio escrito en Python + PySide6.
Inspirado en Burp Suite y Caido. Herramienta de pentesting web personal.

## Arrancar la aplicación

```bash
python3 main.py
```

Requiere: `PySide6`, `cryptography`. Opcional: `brotli`, `zstandard`.

---

## Arquitectura de módulos

```
main.py              → entrypoint (llama a ui.window.main)
session.py           → serialización/restauración de sesión (JSON + base64)

proxy/
  __init__.py        → re-exporta ProxyServer, Flow, PendingRequest, CA_CERT_FILE
  flow.py            → dataclass Flow + clase PendingRequest (Intercept)
  server.py          → ProxyServer: hilo TCP, MITM HTTPS, hooks intercept/M&R
  ca.py              → genera CA raíz y certificados por host (cryptography)

net/
  http_client.py     → cliente HTTP/HTTPS directo (usado por Repeater y Fuzzer)
  http_message.py    → parse de headers HTTP raw

ui/
  window.py          → MainWindow: orquesta pestañas, proxy, sesión
  style.py           → STYLE (QSS), paleta, MONO font, decode(), decode_http(), status_color()
  highlighter.py     → HTTPHighlighter, JSONHighlighter (QSyntaxHighlighter)
  repeater.py        → RepeaterTab, RepeaterWorker
  fuzzer.py          → FuzzerTab (§markers§ + wordlist + filtros)
  intercept.py       → InterceptTab + InterceptBridge (Signal/Slot cross-thread)
  matchreplace.py    → MatchReplaceTab (reglas texto/regex sobre req/resp)
  ai_shell.py        → AIShellTab (pseudo-TTY + CLAUDE.md con contexto HTTP History)
  decoder.py         → DecoderTab: Transformar (encadenado) + JWT Inspector
  sitemap.py         → SiteMapTab: árbol de hosts/rutas, tabla de flows por nodo
```

---

## Orden de pestañas (window.py `_build_ui`)

| Índice | Nombre        | Widget          |
|--------|---------------|-----------------|
| 0      | Intercept     | InterceptTab    |
| 1      | HTTP History  | (inline)        |
| 2      | Repeater      | RepeaterTab×N   |
| 3      | Tools         | FuzzerTab       |
| 4      | Site Map      | SiteMapTab      |

**Tools (FuzzerTab)** agrupa todas las herramientas. La fila "Nueva sesión:"
tiene botones que abren pestañas internas en `fuzzer_tab._tabs`:

- **Fuzzing / Race Conditions / JWT Auditor** → tabs nuevos cerrables (`add_fuzzing_tab`, etc.)
- **Decoder / IA / Matcher** → herramientas singleton registradas con
  `fuzzer_tab.register_tool(texto, widget, nombre)`; el botón abre o enfoca su
  tab con `fuzzer_tab.open_tool(widget)`. Los widgets (`decoder_tab`, `ai_tab`,
  `mr_tab`) viven en `MainWindow` y se conservan entre cierres/reaperturas.

Para navegar a una herramienta: `self.tabs.setCurrentIndex(3); self.fuzzer_tab.open_tool(self.decoder_tab)`
(o usa el helper `self._go_tools(widget)`).

---

## Modelo de datos principal: `Flow`

```python
@dataclass
class Flow:
    id: int
    method: str        # "GET", "POST", ...
    host: str          # "target.com" (sin puerto si es estándar)
    port: int
    scheme: str        # "http" | "https"
    path: str          # "/api/users?q=1"
    raw_request: bytes
    raw_response: bytes
    status: str        # "200", "404", ""
    use_tls: bool
    timestamp: float
    label: str         # "" | "rojo" | "naranja" | "amarillo" | "verde" | "azul" | "morado"
    comment: str

    @property url: str       # "https://host:port/path"
    @property length: int    # len(raw_response)
```

`window.flows: list[Flow]` — lista maestra, nunca borrar sin limpiar también `_flow_by_id`.

---

## Intercept: cómo funciona el bloqueo

`PendingRequest` usa `threading.Event`. El hilo del proxy llama a `pending.wait(300)` y queda bloqueado. La UI emite `InterceptBridge.pending_received` (Signal) → el slot en el hilo principal llama a `intercept_tab.on_pending(pending)`. El usuario pulsa Forward → `pending.forward(modified_raw)` → `_event.set()` → el proxy continúa.

**Nunca llames a métodos de Qt desde hilos del proxy.** Usa siempre Signal/Slot.

---

## Match & Replace (Matcher): thread safety

`MatchReplaceTab.apply_to_request(raw)` y `apply_to_response(raw)` toman un snapshot de la lista de reglas al inicio (`list(self._rules)`) para evitar race conditions con el hilo de la UI editando las reglas mientras el proxy las aplica.

---

## Añadir una pestaña nueva

1. Crear `ui/mi_tab.py` con una clase `MiTab(QWidget)`.
2. En `window.py`:
   - Importar: `from ui.mi_tab import MiTab`
   - En `_build_ui()`: `self.mi_tab = MiTab(); self.tabs.addTab(self.mi_tab, "Nombre")`
   - **Actualizar** la tabla de índices de arriba y cualquier `setCurrentIndex(N)` existente.
3. Si necesita acceso a los flows: `self.mi_tab.set_flows_getter(lambda: self.flows)`.
4. Si emite señales hacia el Repeater: `self.mi_tab.send_to_repeater.connect(self.send_to_repeater)`.

---

## Cómo añadir una opción al menú contextual del HTTP History

En `MainWindow.show_history_menu()` (window.py):

```python
mi_action = QAction("Texto del menú", self)
mi_action.triggered.connect(lambda: self.mi_metodo(flow))
menu.addAction(mi_action)
```

`flow` es el `Flow` de la fila seleccionada en ese momento.

---

## Decode de respuestas HTTP

`ui/style.py` tiene `decode_http(raw: bytes) -> str` que:
1. Desencadena `Transfer-Encoding: chunked`
2. Descomprime `Content-Encoding: gzip/deflate/br/zstd`
3. Devuelve texto UTF-8 (fallback latin-1)

Úsala siempre para mostrar respuestas. Para peticiones basta con `decode(raw)`.

---

## Sesión (session.py)

- `save_session_to_file(window, path)` → JSON con flows (base64) + repeater tabs
- `load_session_from_file(window, path)` → llama a `window.add_flow()` por cada flow restaurado
- Al restaurar, `sitemap_tab.clear()` se llama antes del bucle para limpiar el árbol
- `Flow.label` y `Flow.comment` se serializan en la sesión

---

## Paleta de colores (ui/style.py)

```python
ACCENT        = "#ff8c1a"   # naranja — botones primarios, host en site map
BG_DEEP       = "#1b1d22"   # fondo más oscuro (inputs, tabla)
BG_BASE       = "#23262d"   # fondo principal
BG_PANEL      = "#2b2f37"   # paneles, cabeceras de tabla
TEXT          = "#dfe3ea"   # texto principal
TEXT_DIM      = "#9aa1ad"   # texto secundario, captions
# Status colors:
# 2xx → #5fd38a (verde)
# 3xx → #4fc3d6 (cian)
# 4xx → #ffb454 (ámbar)
# 5xx → #ff6b6b (rojo)
```

Todos los widgets usan la stylesheet global `STYLE` aplicada en `main()`.
Para estilos específicos de un widget usa `setObjectName("nombre")` y añade CSS en `STYLE`.

---

## Decoder (ui/decoder.py)

**Sub-pestaña Transformar:** pasos encadenables con `_StepRow`. Los hash ops (MD5, SHA-*) desactivan el combo "Decodificar" automáticamente.

**Sub-pestaña JWT Inspector:**
- `_JWT_RE` valida formato `header.payload.signature`
- `_b64url_dec(s)` / `_b64url_enc(data)` — base64url sin padding
- Detecta `alg: none` comparando el campo en el header decoded
- "Re-firmar HS256" usa `hmac.new(secret, header.payload, sha256).digest()`
- "Ataque alg:none" genera `header_enc.payload_enc.` (punto final, firma vacía)

Llamada desde window.py: `decoder_tab.load_text(str)` o `decoder_tab.load_jwt(token)`.

---

## Site Map (ui/sitemap.py)

**Claves de nodo:**
- Host: `"H|target.com"`
- Ruta: `"P|target.com|/api/users"`

`_node_flows[key]` acumula **todos** los flows para ese nodo y sus descendientes.
Así, al clicar `/api` se muestran todos los flows bajo `/api/**`.

`add_flow(flow)` se llama desde `MainWindow.add_flow()` → actualización incremental en tiempo real.

`full_refresh()` reconstruye desde cero usando `_flows_getter()`.

Doble clic en una fila emite `send_to_repeater(flow)`, conectado a `MainWindow.send_to_repeater`.

---

## IA Shell (ui/ai_shell.py)

Terminal del sistema embebida que **auto-arranca** al mostrarse la pestaña
(`showEvent` → `launch()` una sola vez). Pensada para lanzar `claude` (Claude
Code) con todo el contexto de Leetch y del tráfico interceptado.

- `_TerminalView(QPlainTextEdit)` es un terminal interactivo real: en
  `keyPressEvent` traduce las teclas a bytes (flechas, Tab, Ctrl+letra, etc.)
  y las emite por `key_bytes` hacia el PTY (no edita localmente). Copiar/pegar
  con `Ctrl+Shift+C` / `Ctrl+Shift+V`. `feed()` pinta la salida manejando
  `\r` (overwrite de línea), `\b` y `\n`; ANSI se elimina con `_ANSI_RE`.
- `pty.openpty()` + `subprocess.Popen` (POSIX). El import de `pty/termios/...`
  está guardado en `_PTY_OK`; en Windows solo se ofrece el terminal externo.
- `_write_context()` genera un directorio temporal con:
  - `CLAUDE.md` → descripción de Leetch, sus herramientas, objetivo de
    auditoría e índice del HTTP History.
  - `http_history/flow_NNNN.http` → un fichero por flow con request + response
    (response descomprimida con `decode_http`). Da acceso **total** al tráfico.
- `_ctx_timer` (QTimer 4 s) refresca el contexto si cambia el nº de flows.
- `_update_winsize()` ajusta `TIOCSWINSZ` según el tamaño del widget para que
  las TUIs (claude) se rendericen al ancho correcto.
- Botón **«Terminal del sistema»**: abre el directorio de contexto en el
  emulador nativo (gnome-terminal/konsole/xterm/Terminal.app/cmd) para usar
  claude a pantalla completa con render perfecto.

---

## Convenciones de código

- Sin comentarios obvios. Solo comentar el **por qué** si no es evidente.
- Señales cross-thread: siempre `Signal(object)` + `@Slot` en el receptor del hilo principal.
- Prefijo `_` para métodos/atributos privados.
- Los `lambda` en `triggered.connect` capturan variables con argumentos por defecto cuando es necesario evitar closures tardías: `lambda checked=False, f=flow: ...`
- `QPlainTextEdit` para HTTP raw (monospace), no `QTextEdit`.
- Siempre `setFont(MONO)` en editores de texto.
