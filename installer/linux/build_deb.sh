#!/usr/bin/env bash
set -e

VERSION="${1:-1.0.0}"
ARCH="amd64"
PKG="leetch"
DEB_DIR="deb_build/${PKG}_${VERSION}_${ARCH}"

# --- estructura de directorios ---
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/opt/leetch"
mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/usr/share/applications"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/256x256/apps"

# --- binario + dependencias (onedir) ---
cp -r dist/Leetch/* "${DEB_DIR}/opt/leetch/"
chmod 755 "${DEB_DIR}/opt/leetch/Leetch"

# --- wrapper en /usr/bin ---
cat > "${DEB_DIR}/usr/bin/leetch" << 'LAUNCHER'
#!/usr/bin/env bash
exec /opt/leetch/Leetch "$@"
LAUNCHER
chmod 755 "${DEB_DIR}/usr/bin/leetch"

# --- icono ---
cp "ui/assets/logo.png" "${DEB_DIR}/usr/share/icons/hicolor/256x256/apps/leetch.png"

# --- .desktop ---
cat > "${DEB_DIR}/usr/share/applications/leetch.desktop" << EOF
[Desktop Entry]
Version=1.0
Name=Leetch
GenericName=Web Proxy
Comment=Proxy MITM HTTP/HTTPS para pentesting web
Exec=/usr/bin/leetch
Icon=leetch
Terminal=false
Type=Application
Categories=Network;Security;
Keywords=proxy;mitm;pentest;http;burp;
EOF

# --- control ---
cat > "${DEB_DIR}/DEBIAN/control" << EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: maalfer <maalfer59@gmail.com>
Depends: libgl1, libglib2.0-0, libxkbcommon0, libxkbcommon-x11-0, libxcb-xinerama0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, libxcb-render-util0, libdbus-1-3, libfontconfig1
Section: net
Priority: optional
Homepage: https://github.com/maalfer/leether
Description: Leetch — Proxy MITM HTTP/HTTPS para pentesting
 Herramienta de pentesting web de escritorio inspirada en Burp Suite y Caido.
 Incluye: Intercept, HTTP History, Repeater, Fuzzer (Sniper/Pitchfork/Cluster Bomb),
 Decoder, JWT Inspector, Site Map, Match & Replace e IA Shell.
EOF

# --- postinst: actualizar caché de iconos ---
cat > "${DEB_DIR}/DEBIAN/postinst" << 'POSTINST'
#!/usr/bin/env bash
update-desktop-database -q /usr/share/applications 2>/dev/null || true
gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
POSTINST
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

# --- construir .deb ---
mkdir -p dist
dpkg-deb --build "${DEB_DIR}" "dist/${PKG}_${VERSION}_${ARCH}.deb"
echo "✓ dist/${PKG}_${VERSION}_${ARCH}.deb"
