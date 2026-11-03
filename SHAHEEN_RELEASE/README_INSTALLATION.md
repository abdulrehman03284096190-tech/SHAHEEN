# SHAHEEN Windows Installation

SHAHEEN is installed as a standalone 64-bit Windows desktop application. The
installer includes the Python runtime, application dependencies, CustomTkinter
resources, and the SHAHEEN application files. A separate Python installation
is not required.

## Install

1. Run `SHAHEEN_Setup_v1.0.0.exe` and approve the Windows administrator prompt.
2. Accept the included MIT license, select an installation folder if desired,
   and optionally choose a desktop shortcut.
3. Use the Start Menu shortcut to launch SHAHEEN.

The default installation folder is `%ProgramFiles%\SHAHEEN`. The installer
registers SHAHEEN with Windows and supports upgrades and uninstall.

## User data and upgrades

The application stores its SQLite database, settings, `.env` configuration,
reports, captures, logs, and backup directory under
`%LOCALAPPDATA%\Shaheen`. Settings already stored in the database are retained
when the application is upgraded. The installer does not install over this
directory, and normal upgrades do not remove user data.

During uninstall, SHAHEEN asks whether to remove this user-data directory. The
default selection is **No**. Choose **Yes** only if you intend to permanently
delete the database and all user reports, captures, settings, logs, and backups.
Data stored at paths explicitly configured outside this directory is not deleted.

For environment-based configuration, copy the installed
`config\shaheen.env.example` template to
`%LOCALAPPDATA%\Shaheen\config\.env` and edit the copy. Existing process
environment variables take precedence over values in this file.

## Live packet capture

Offline PCAP/PCAPNG analysis does not require Npcap. Live Windows capture
requires Npcap with WinPcap API-compatible mode. Npcap is not bundled because
its driver and installer are third-party software with separate redistribution
terms. If Npcap is not detected, the installer offers to open the official
[Npcap download page](https://npcap.com/#download). Install Npcap separately,
restart SHAHEEN, and follow Npcap's interface/permission guidance. SHAHEEN does
not elevate itself; capture access denied errors include troubleshooting
guidance in the application.

## Troubleshooting

- If Windows SmartScreen warns about the installer, verify its origin and
  digital signature before proceeding. This build is not code-signed.
- If an upgrade reports that files are in use, close SHAHEEN and retry.
- Application logs are stored in `%LOCALAPPDATA%\Shaheen\logs`.
- The application creates or migrates its SQLite database on startup and leaves
  user data in place when an upgrade is installed.
