# SHAHEEN Windows Release Build

Build on 64-bit Windows with Python 3.12 or newer, the Visual C++ runtime
available to PyInstaller, and Inno Setup 6.7 or newer. The included Inno Setup
script uses only SHAHEEN files; it does not redistribute Npcap.

Run these commands from the repository root in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r .\SHAHEEN_RELEASE\requirements.txt
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean `
  --distpath .\SHAHEEN_RELEASE\dist `
  --workpath .\SHAHEEN_RELEASE\build `
  .\SHAHEEN_RELEASE\SHAHEEN.spec
```

Find the Inno Setup compiler through its registered install location, then
compile the installer:

```powershell
$inno = Get-ItemProperty `
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
  -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -like 'Inno Setup version *' } |
  Select-Object -First 1
$iscc = Join-Path $inno.InstallLocation 'ISCC.exe'
if (-not (Test-Path -LiteralPath $iscc)) { throw 'Inno Setup 6 ISCC.exe was not found.' }
& $iscc .\SHAHEEN_RELEASE\installer\SHAHEEN_Setup.iss
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }
```

The GUI executable is produced at
`SHAHEEN_RELEASE\dist\SHAHEEN\SHAHEEN.exe`; the installer is produced at
`SHAHEEN_RELEASE\installer\SHAHEEN_Setup_v1.0.0.exe`.

For a separate console-enabled diagnostic build, set the environment variable
and use a distinct work and distribution directory:

```powershell
$env:SHAHEEN_CONSOLE = '1'
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean `
  --distpath .\SHAHEEN_RELEASE\dist `
  --workpath .\SHAHEEN_RELEASE\build\diagnostic `
  .\SHAHEEN_RELEASE\SHAHEEN.spec
Remove-Item Env:\SHAHEEN_CONSOLE
```

This mode produces `SHAHEEN-Diagnostic\SHAHEEN-Diagnostic.exe`. Build the
release installer only from the default, windowed build.

## Release checks

1. Launch the packaged app from a working directory outside the repository.
2. Confirm database, configuration, captures, reports, logs, and backups are
   created under `%LOCALAPPDATA%\Shaheen`.
3. Exercise navigation, PCAP/PCAPNG import, CSV export, PDF report generation,
   application restart, and settings persistence.
4. Install and uninstall in a disposable Windows account/VM to verify
   shortcuts, upgrade behavior, and the user-data preservation prompt.
5. Test live capture only on a machine with Npcap installed and authorized
   interface permissions. The build process does not install or bundle drivers.

Windows edition, Npcap driver availability, signing, SmartScreen reputation,
and permissions affect clean-machine deployment and must be validated on the
target release environment.
