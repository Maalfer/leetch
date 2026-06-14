import os
import sys

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('ui/assets/logo.png', 'ui/assets'),
    ],
    hiddenimports=[
        'cryptography.hazmat.backends.openssl',
        'cryptography.hazmat.bindings._rust',
        'cryptography.hazmat.primitives.serialization.pkcs12',
        'cryptography.hazmat.primitives.asymmetric.padding',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.asymmetric.ec',
        'cryptography.x509',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

_icon = None
if sys.platform == 'win32' and os.path.exists('ui/assets/logo.ico'):
    _icon = 'ui/assets/logo.ico'
elif sys.platform != 'win32' and os.path.exists('ui/assets/logo.png'):
    _icon = 'ui/assets/logo.png'

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Leetch',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_icon,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Leetch',
)

if sys.platform == 'darwin':
    _icns = 'ui/assets/logo.icns' if os.path.exists('ui/assets/logo.icns') else None
    app = BUNDLE(
        coll,
        name='Leetch.app',
        icon=_icns,
        bundle_identifier='com.leetch.proxy',
        info_plist={
            'NSPrincipalClass': 'NSApplication',
            'NSAppleScriptEnabled': False,
            'LSMinimumSystemVersion': '10.14.0',
            'CFBundleShortVersionString': os.environ.get('LEETCH_VERSION', '1.0.0'),
        },
    )
