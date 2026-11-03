# -*- mode: python ; coding: utf-8 -*-
import os

from PyInstaller.utils.hooks import collect_all


release_root = SPECPATH
project_root = os.path.abspath(os.path.join(release_root, os.pardir))
assets_root = os.path.join(release_root, "assets")
diagnostic_build = os.environ.get("SHAHEEN_CONSOLE", "").strip() == "1"
executable_name = "SHAHEEN-Diagnostic" if diagnostic_build else "SHAHEEN"

datas = [
    (os.path.join(project_root, "LICENSE"), "."),
    (os.path.join(project_root, ".env.example"), "config"),
]
binaries = []
hiddenimports = []

for package in ("customtkinter", "scapy", "reportlab"):
    package_datas, package_binaries, package_hiddenimports = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hiddenimports

a = Analysis(
    [os.path.join(project_root, "main.py")],
    pathex=[project_root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name=executable_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=diagnostic_build,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(assets_root, "SHAHEEN.ico"),
    version=os.path.join(release_root, "version_info.txt"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=executable_name,
)
