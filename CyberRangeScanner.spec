# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['c:\\Users\\MostafaBrakat\\CyberRangeScanner\\cyberrange_scanner.py'],
    pathex=[],
    binaries=[],
    datas=[('c:\\Users\\MostafaBrakat\\CyberRangeScanner\\icons', 'icons')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CyberRangeScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['c:\\Users\\MostafaBrakat\\CyberRangeScanner\\icon.ico'],
)
