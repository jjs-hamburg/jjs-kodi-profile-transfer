# JJS KODI Profile Backup/Restore, Transfer & Install

A Windows tool for managing Kodi installations and profiles on:

- Android / NVIDIA Shield via ADB
- LibreELEC via SSH

Current version: **1.12**

The application has two separate areas:

- **Profile Backup / Restore / Transfer**
- **Kodi Install / Update**

Both tabs show the same target device. Connection type, IP address, port, SSH credentials, and the detected Kodi installations are synchronized so the target does not need to be entered twice.

All Kodi installation and update files are selected locally. The tool does not download Kodi builds.

## Profile Backup / Restore / Transfer

The profile tools can create a complete Kodi profile backup, restore a backup to another Kodi installation, or transfer a profile directly from one device to another.

Backups are stored as uncompressed TAR archives and include transfer metadata used to decide which parts of a profile are safe to restore on the target system.

### Restore policy

#### Same platform

A full profile restore is performed.

#### Cross-platform

The target Kodi add-on database (`Addons*.db`) is preserved.

Portable source add-ons and their settings are restored. Platform-dependent or binary add-ons are skipped automatically so that an Android profile can, for example, be transferred to LibreELEC without replacing the target system's architecture-specific add-on state.

Keymaps, library nodes, and the normal Kodi userdata profile are restored.

An optional safety backup of the existing target profile can be created automatically before restore.

## Kodi Install / Update

The second application tab installs or updates Kodi from a **local file**.

Connection settings are intentionally similar to the profile tools. Options that are irrelevant to the selected platform are hidden automatically.

### Android / NVIDIA Shield

Select a local `.apk` file and an Android device connected through ADB.

The tool uses Android's normal package installation mechanism:

- If the APK package is not installed yet, it is installed as a new application.
- If the same package is already installed and the APK signature is compatible, the existing application is updated with `adb install -r`.
- Existing application data and the Kodi profile are retained during a normal update.
- If the APK signature does not match the installed application, Android rejects the update. **The tool never automatically uninstalls the existing application to work around a signature mismatch.**

The package ID embedded in the APK determines which application Android installs or updates. This allows multiple Kodi variants to coexist, for example:

- `org.xbmc.kodi` — Kodi
- `org.jjs.kodi` — Kodi JJS

The tool detects installed Kodi packages on the device. If more than one Kodi installation is present, a specific installation can be selected from the list for uninstalling. Package IDs do not need to be typed manually.

#### Android uninstall

A selected Kodi installation can be uninstalled explicitly.

Before uninstalling, the tool can create a complete profile backup using the same proven backup mechanism as the profile tab. This option is enabled by default.

Android uninstall removes the selected application and its application data. The tool therefore requires explicit confirmation and never performs an uninstall automatically as part of an update.

### LibreELEC

Select a local LibreELEC `.tar` update file and connect to an existing LibreELEC system through SSH.

The tool:

1. verifies that the SSH target identifies itself as LibreELEC,
2. uploads the TAR to `/storage/.update/`,
3. verifies the uploaded file size,
4. places the completed upload in the update directory,
5. asks whether LibreELEC should be restarted immediately.

If you choose not to restart, the update remains staged and can be installed by rebooting LibreELEC later.

This function updates an **existing LibreELEC installation**. It does not install LibreELEC onto a blank device.

## Supported connections

### Android / NVIDIA Shield

Android devices are accessed through **ADB (Android Debug Bridge)**.

Requirements:

- Developer options must be enabled on the Android device / NVIDIA Shield.
- Network debugging / ADB over network must be enabled on the device.
- The Windows PC and the Android device must be able to reach each other over the network.

A manual ADB installation is **not required**. The application first looks for `adb.exe` in the configured ADB folder and in the Windows `PATH`. If ADB is not found, it offers to download and install the official Android Platform Tools directly from Google. The default installation folder is `C:\\ADB`.

The exact name of the debugging option can differ between Android versions and devices. On NVIDIA Shield it is available under the developer options as network debugging.

### LibreELEC

LibreELEC is accessed through SSH.

SSH host keys are verified and stored locally after first confirmation. SSH passwords are entered at runtime and are not written to the application's configuration file.

## Windows build

The Windows executable is built automatically with GitHub Actions and PyInstaller.

Download the current executable from:

**Releases → JJS KODI Profile Backup/Restore, Transfer & Install 1.12**

Release files:

- `JJS-KODI-Profile-Backup-Restore-Transfer.exe`
- `SHA256SUMS.txt`

The executable filename is retained for continuity with earlier releases.

The source used for the build is:

`installer/jjs_kodi_profile_transfer.py`

The repository source is the authoritative project state.

## Important warning

Restore, transfer, install, update, and uninstall operations can change or remove Kodi data or software.

Although the tool contains platform checks, cross-platform filtering, optional safety backups, explicit confirmations, and conservative update behavior, a failed transfer, incompatible build, unusual Kodi configuration, network interruption, device problem, or software bug can still damage or overwrite data.

**Keep an independent backup of any Kodi profile that matters before using restore, transfer, update, or uninstall functions.**

## Disclaimer

This project was originally created for my own personal use. I am making the source code and prebuilt Windows binaries available for anyone who may find them useful.

This is an independent, unofficial community project. It is **not an official Kodi project** and is not affiliated with or endorsed by Team Kodi, the Kodi Foundation, or LibreELEC.

The software is provided **as is**, without warranty of any kind. Use it at your own risk. I do not guarantee compatibility with any particular Kodi version, device, operating system, add-on, network environment, APK, LibreELEC image, or configuration.

There is **no commitment or obligation to provide support, bug fixes, future updates, maintenance, compatibility updates, or future releases**.

To the maximum extent permitted by applicable law, the author shall not be liable for loss of data, configuration, functionality, availability, or other damages arising from the use of, or inability to use, this software.

## License

The JJS KODI Profile Backup/Restore, Transfer & Install source code in this repository is released under the **MIT License**. See [LICENSE](LICENSE).

The Windows executable is built with third-party open-source components and uses external tools such as Android ADB. Those projects remain subject to their own licenses and terms.

Kodi, LibreELEC, Android, and the names of third-party projects belong to their respective owners.
