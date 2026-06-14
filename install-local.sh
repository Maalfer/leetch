#!/usr/bin/env bash
# Instala el .desktop y el icono de Leetch en el entorno local del usuario.
# Solo necesitas ejecutar esto una vez para que el dock/taskbar muestre el icono.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
DESKTOP_DIR="$HOME/.local/share/applications"

mkdir -p "$ICON_DIR" "$DESKTOP_DIR"

# Instalar icono
cp "$SCRIPT_DIR/ui/assets/logo.png" "$ICON_DIR/leetch.png"

# Instalar .desktop
cat > "$DESKTOP_DIR/leetch.desktop" << EOF
[Desktop Entry]
Name=Leetch
GenericName=Web Proxy
Comment=Proxy MITM HTTP/HTTPS para pentesting web
Exec=python3 $SCRIPT_DIR/main.py
Icon=leetch
Terminal=false
Type=Application
Categories=Network;Security;
Keywords=proxy;mitm;pentest;http;burp;
StartupWMClass=Leetch
EOF

# Actualizar caché
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

echo "✓ Instalado en $DESKTOP_DIR/leetch.desktop"
echo "✓ Icono en $ICON_DIR/leetch.png"
echo ""
echo "Si el icono no aparece de inmediato, cierra y vuelve a abrir la app."
