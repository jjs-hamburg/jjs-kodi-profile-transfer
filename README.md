# JJS KODI Profile Backup/Restore & Transfer

A Windows tool for backing up, restoring, and transferring complete Kodi profiles between:

- Android / NVIDIA Shield via ADB
- LibreELEC via SSH

Current version: **1.10**

## What it does

The tool can create a complete Kodi profile backup, restore a backup to another Kodi installation, or transfer a profile directly from one device to another.

Backups are stored as uncompressed TAR archives and include transfer metadata used to decide which parts of a profile are safe to restore on the target system.

## Restore policy

### Same platform and architecture

A full profile restore is performed.

### Cross-platform or cross-architecture

The target Kodi add-on database (`Addons*.db`) is preserved.

Portable source add-ons and their settings are restored. Platform-dependent or binary add-ons are skipped automatically so that an Android profile can, for example, be transferred to LibreELEC without replacing the target system's architecture-specific add-on state.

Keymaps, library nodes, and the normal Kodi userdata profile are restored.

An optional safety backup of the existing target profile can be created automatically before restore.

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

**Releases → JJS KODI Profile Backup/Restore & Transfer 1.10**

Release files:

- `JJS-KODI-Profile-Backup-Restore-Transfer.exe`
- `SHA256SUMS.txt`

The source used for the build is:

`installer/jjs_kodi_profile_transfer.py`

The repository source is the authoritative project state.

## Important warning

Restore and transfer operations replace parts of a Kodi profile. Although the tool contains platform checks, cross-platform filtering, and an optional safety backup, a failed transfer, incompatible add-on, unusual Kodi configuration, network interruption, device problem, or software bug can still damage or overwrite profile data.

**Keep an independent backup of any Kodi profile that matters before using restore or transfer functions.**

## Disclaimer

This project was originally created for my own personal use. I am making the source code and prebuilt Windows binaries available for anyone who may find them useful.

This is an independent, unofficial community project. It is **not an official Kodi project** and is not affiliated with or endorsed by Team Kodi or the Kodi Foundation.

The software is provided **as is**, without warranty of any kind. Use it at your own risk. I do not guarantee compatibility with any particular Kodi version, device, operating system, add-on, network environment, or configuration.

There is **no commitment or obligation to provide support, bug fixes, future updates, maintenance, compatibility updates, or future releases**.

To the maximum extent permitted by applicable law, the author shall not be liable for loss of data, configuration, functionality, availability, or other damages arising from the use of, or inability to use, this software.

## License

The JJS KODI Profile Backup/Restore & Transfer source code in this repository is released under the **MIT License**. See [LICENSE](LICENSE).

The Windows executable is built with third-party open-source components and uses external tools such as Android ADB. Those projects remain subject to their own licenses and terms.

Kodi and the names of third-party projects belong to their respective owners.
