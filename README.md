<p align="center">
  <img src="ui/assets/logo.png" width="120" alt="Leetch logo" />
</p>

<h1 align="center">Leetch</h1>
<p align="center">Proxy de interceptación HTTP/HTTPS para pentesting web</p>

---

## Características

| Módulo | Descripción |
|---|---|
| **Intercept** | Bloquea peticiones en tiempo real · editar y reenviar |
| **HTTP History** | Log completo con búsqueda, etiquetas y menú contextual |
| **Repeater** | Edita y reenvía peticiones · búsqueda por panel |
| **Tools** | Fuzzer, Race Conditions, JWT Auditor, Decoder, Matcher, IA shell |
| **Site Map** | Árbol de hosts y rutas con flows asociados |

## Requisitos

```
Python 3.10+
PySide6
cryptography
```

Opcionales (descompresión de respuestas):

```
brotli
zstandard
```

## Instalación

```bash
pip install PySide6 cryptography
# opcionales
pip install brotli zstandard
```

## Uso

```bash
python3 main.py
```

El proxy escucha en `127.0.0.1:8080` por defecto.  
Configúralo en tu navegador o usa el navegador integrado (menú **Ajustes → Abrir navegador**).

### CA raíz

Al arrancar la primera vez, Leetch genera una CA propia en `~/.leeth/`.  
Para HTTPS: **Ajustes → Instalar CA** o confía en `leeth-ca.crt` manualmente.

## Estructura

```
main.py        entrypoint
proxy/         servidor MITM (CA, flows, intercept)
net/           cliente HTTP y parser de mensajes
ui/            interfaz (PySide6)
session.py     guardado/restauración de sesión
```

