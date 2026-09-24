# JJS KODI Toolbox

Windows toolbox for managing Kodi on **Android / NVIDIA Shield (ADB)** and **LibreELEC (SSH)**.

Current version: **1.14**

## What it does

- **Backup Kodi profiles**
  - Complete profile backup to a local TAR file
  - Optional automatic safety backup before restore/uninstall

- **Restore and transfer profiles**
  - Restore a backup to another Kodi installation
  - Direct transfer from Source A to Target B
  - Same-platform restore: complete profile
  - Cross-platform restore: keeps the target `Addons*.db`, restores portable add-ons/settings, skips platform-dependent binary add-ons

- **Install / update Kodi**
  - Android: install or update a local APK with `adb install -r`
  - Android: detect multiple Kodi installations and uninstall a selected one
  - Fresh Android installs: configure microphone and "All files" access where supported
  - LibreELEC: upload a local update TAR to `/storage/.update/` and optionally reboot

- **Back up / restore Kodi databases**
  - MusicDB and VideoDB independently
  - MariaDB and local SQLite
  - Uses the existing JJS Music Library Manager ZIP backup format (version 2)
  - Either read MariaDB credentials automatically from Source A's `advancedsettings.xml` or connect directly to a MariaDB server
  - Direct MariaDB mode stores server/port/user/prefixes, but never the password
  - Backup filename: `DBname-IP-YYMMDD-HHMM.zip` (SQLite uses the Kodi device IP; MariaDB uses the DB server host/IP)
  - Verifies backup checksums and schema version before restore
  - SQLite is stopped, rebuilt and verified before replacing the active DB

- **Take Kodi screenshots**
  - Android: capture directly over ADB; no screenshot file is left on the device
  - LibreELEC: temporary screenshot is downloaded and removed immediately
  - Saves directly to a selectable Windows folder
  - Removes narrow black / near-black outer borders automatically
  - Filename: `Device (IP)-YYDDMM-HHMM.png`

- **Shared device state**
  - Screenshot tab mirrors **Source A**
  - Install / Update tab mirrors **Target B**
  - Device type, IP, port, Kodi selection and status stay synchronized

- **Progress display**
  - Determinate 0–100% progress instead of an animated activity bar
  - Real byte progress where available; phase progress where the underlying tool exposes no usable percentage

## Supported systems

- **Android / NVIDIA Shield**
  - Developer options enabled
  - Network ADB enabled
  - PC and device reachable over the network
  - If ADB is missing, the toolbox can download the official Android Platform Tools

- **LibreELEC**
  - SSH enabled
  - SSH password is entered at runtime and is **not stored**

## Download

Get the current Windows build from:

**Releases → JJS KODI Toolbox 1.14**

Files:

- `JJS-KODI-Toolbox.exe`
- `SHA256SUMS.txt`

The Windows EXE is built automatically with GitHub Actions and PyInstaller.

## Local data

Stored under:

`%LOCALAPPDATA%\JJSKodiToolbox\`

Contains configuration, SSH host keys and logs. SSH passwords are never stored.

## Important

Restore, transfer, update and uninstall operations can change or remove Kodi data.

**Keep an independent backup of important Kodi profiles.**

## Disclaimer

- Independent, unofficial community project
- Not affiliated with or endorsed by Team Kodi, the Kodi Foundation or LibreELEC
- Provided **as is**, without warranty or support commitment
- Use at your own risk

## License

MIT License. See [LICENSE](LICENSE).

Kodi, LibreELEC, Android and third-party project names belong to their respective owners.
