# dotnet-troubleshooter

A PowerShell script that diagnoses, and optionally fixes, machine-level problems that break
.NET apps on Windows. It covers both **.NET Framework 4.x** and **.NET 5+** (including the Windows
Desktop Runtime used by WinForms and WPF apps).

> [!WARNING]
> **This is experimental.** It was written quickly to investigate a specific problem, not as a
> polished or supported tool. Most of the diagnostics have only been run on a handful of machines,
> and several of the fix and repair paths have never been run on a real system (see
> [Testing status](#testing-status)). Run it in the default report-only mode first, read what it
> says, and treat its suggestions as leads to investigate, not conclusions.

## Background

The script was originally created to understand some .NET issues that appeared after the
**November 2026 Patch Tuesday** updates. At first the focus was on "out of memory" errors on
machines with plenty of free RAM. It has since grown into a general check of the things that
commonly break .NET apps after updates or configuration changes: handle leaks, broken runtime
installs, corrupt native images, injected profilers, failed .NET updates, and so on.

It doesn't identify or explain any particular update as the cause. It collects the state of the
machine so you can work that out.

## Requirements

- Windows 10 or 11 (Windows Server should work but hasn't been tested)
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator rights for `-Fix`, `-Repair` and `-ResetNativeImages`. Diagnosis works without
  them, but some checks see less (the output says which).

## Quick start

```powershell
# Report only. Changes nothing. Run this while the failing app is open and in use.
.\Invoke-DotNetTroubleshooter.ps1

# Run elevated for complete results, and watch for handle growth over 2 minutes
.\Invoke-DotNetTroubleshooter.ps1 -HandleSampleSeconds 120

# Preview what -Fix would change, without changing anything
.\Invoke-DotNetTroubleshooter.ps1 -Fix -WhatIf
```

The script isn't signed. If PowerShell refuses to run it, either use
`powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DotNetTroubleshooter.ps1`, or run
`Unblock-File .\Invoke-DotNetTroubleshooter.ps1` if you downloaded it.

## What it checks

The output starts with a **System information** block (computer, user, elevation, session, OS
version and build, hardware, CPU, RAM, PowerShell host, locale, time zone), then runs these checks:

| # | Check | What it looks for |
|---|---|---|
| 1 | Memory, commit limit, pagefile | Commit charge nearly exhausted; pagefile disabled or too small |
| 2 | CLR environment variables | `COMPlus_`/`DOTNET_` GC overrides; CLR profilers (`COR_*`, `CORECLR_*`) injected into every app |
| 3 | CLR registry and runtimes | GC/profiler values under the `.NETFramework` keys; installed .NET Framework release; installed .NET 5+ `NETCore.App` and `WindowsDesktop.App` runtimes (x64 and x86); `DOTNET_ROOT` |
| 4 | Exploit protection | System-wide Mandatory ASLR, which is known to cause problems for older .NET Framework apps |
| 5 | Desktop heap | Interactive desktop heap set too small; desktop heap failure events |
| 6 | Handles | GDI/USER handle quotas; processes near their GDI/USER limit; session-wide GDI total; processes holding very large numbers of kernel handles; optional handle growth between two samples |
| 7 | .NET Framework config files | Missing or corrupt `machine.config` / `web.config` |
| 8 | Running .NET processes | 32-bit .NET apps near the ~2 GB address-space limit; runtime and version of each .NET process; for self-contained apps (which carry their own .NET and aren't patched by Windows Update), the exact version, where it's loaded from and how many patches it is behind your installed runtime; which Visual C++ runtimes each one has loaded; `System.GC.HeapHardLimit*` in .NET 5+ apps' `runtimeconfig.json` |
| 9 | DLL injection | `AppInit_DLLs` loaded into every GUI process |
| 10 | Allocation test | Starts 64-bit and 32-bit Windows PowerShell (.NET Framework) and PowerShell 7 (.NET), and allocates memory in each to confirm the runtime can allocate at all |
| 11 | Event log | Recent .NET app crashes (`.NET Runtime` events 1022–1026, `Application Error` 1000 inside the runtime), grouped by app with a likely-cause hint; out-of-memory errors from other sources |
| 12 | NGen native images | .NET Framework native image cache size, NGen service state, optimization-service errors |
| 13 | Windows Update | Failed .NET updates (Windows Update history and Setup log) with hints for common error codes; pending reboot; whether .NET 5+ is updated through Microsoft Update; optionally, .NET updates not yet installed |
| 14 | Visual C++ Redistributables | Installed versions (x86/x64); **orphaned registrations that stop VC++ from being upgraded** (cached installer or MSI missing, Programs and Features entries Windows Installer doesn't know about and the reverse, stale dependency records, duplicate v14 entries); whether the v14 installer, runtime packages, registry and DLL versions agree; missing x86 runtime while 32-bit .NET apps run; failed `VC_redist` installs (installer logs and Windows Installer events); crashes inside the C++ runtime DLLs |
| 15 | Application control | Smart App Control state; enforced WDAC policies (admin); Code Integrity, AppLocker and Defender Attack Surface Reduction blocks that hit .NET apps or the runtime; Defender detections in `.exe`/`.dll` files (a quarantined DLL looks like a missing file) |
| 16 | TLS and cryptography | `SchUseStrongCrypto` / `SystemDefaultTlsVersions` for .NET Framework 4.x (and 2.0/3.5 if installed); TLS versions turned off in SCHANNEL; FIPS mode; Schannel credential errors |
| 17 | .NET 5+ host resolution | Causes of "You must install or update .NET" when .NET is installed: missing `hostfxr.dll`, a wrong registered install location, the 32-bit `dotnet.exe` first on PATH, `DOTNET_ROOT*` pointing nowhere or at the wrong bitness, roll-forward overrides; apps that logged ".NET not found" start failures |
| 18 | Component store and .NET 3.5 | .NET Framework 3.5 feature state (including half-installed); `DISM /CheckHealth` (admin); a `pending.xml` stuck since before the last boot; servicing errors and corruption in `CBS.log` |
| 19 | Temp folders and disk space | `TMP`/`TEMP` pointing at a missing folder; temp folders close to the 65,535 `tmp*.tmp` limit where `Path.GetTempFileName()` fails; a live `GetTempFileName()` test; low free space on the system and temp drives |
| 20 | Injected DLLs | Third-party DLLs (security, overlay, hardware and shell-extension software) loaded into two or more running .NET apps from outside their folders, flagged when apps have crashed inside them |

Each finding is tagged:

```
  [ OK ] Nothing wrong found
  [INFO] Context, no action needed
  [WARN] Worth a look
  [FAIL] Likely cause of problems
         -> Suggested next step
```

A summary of all `WARN` and `FAIL` findings is printed at the end. Each run also saves two files
in the script's folder (or the folder given with `-OutputDirectory`):

- `DotNetTroubleshooter-console-<timestamp>.log`: everything printed to the console
- `DotNetTroubleshooter-report-<timestamp>.csv`: every finding, one row each

If the folder can't be written to, both go to `%TEMP%` instead. The repo's `.gitignore` excludes
them.

## Parameters

| Parameter | What it does |
|---|---|
| *(none)* | Report only. Changes nothing. |
| `-Fix` | Applies the fixes marked `Fix:` in the output (see below). Needs admin. Supports `-WhatIf`. |
| `-Repair` | Also runs `DISM /RestoreHealth` and `sfc /scannow`. Needs admin. Slow. |
| `-ResetNativeImages` | Deletes and rebuilds the .NET Framework native image (NGen) cache. Needs admin. Supports `-WhatIf`. Takes 10–30+ minutes. Close .NET Framework apps first, and preferably run it from PowerShell 7, because Windows PowerShell locks some of the files it needs to delete. |
| `-HandleSampleSeconds <n>` | Takes a second handle sample after `n` seconds (1–3600) and reports processes whose handle counts grew. |
| `-CheckAvailableUpdates` | Searches Windows Update online for applicable .NET updates that aren't installed. Can take a few minutes. |
| `-SkipAllocationTest` | Skips check 10. |
| `-OutputDirectory <path>` | Where to save the console log and CSV report. Default: the script's folder. |
| `-BackupRoot <path>` | Where `-Fix` saves backups. Default: `%USERPROFILE%\DotNetTroubleshooter-Backups`. |

### `-Fix` vs `-Repair`

They do different jobs and can be combined (`-Fix -Repair`). Both need admin.

| | `-Fix` | `-Repair` |
|---|---|---|
| What it does | Undoes specific settings the diagnosis flagged (listed below) | Repairs Windows system files: `DISM /Online /Cleanup-Image /RestoreHealth`, then `sfc /scannow` |
| When it acts | Only on findings marked `Fix:`. On a healthy machine it changes nothing | Always runs, whatever the diagnosis found |
| Safety net | Restore point and registry backups first; supports `-WhatIf` | No backup or `-WhatIf` (it only replaces damaged files with clean copies from Microsoft) |
| Time | Seconds; some changes need a reboot | Usually 15–45 minutes |
| Doesn't cover | Anything marked `Manual:` | .NET 5+ runtimes and Visual C++ Redistributables (reinstall those instead) |

Use `-Repair` when the report shows component store corruption (check 18), failed .NET Framework
updates (check 13), or a missing or broken .NET Framework install (check 3). Use `-Fix` for the
settings findings. If DISM can't download repair files (0x800f081f / 0x800f0906, common with
WSUS), the check 18 finding explains how to repair from a Windows ISO instead.

### What `-Fix` changes

Before its first change, `-Fix` tries to create a System Restore point and saves backups of
registry keys and settings to `<BackupRoot>\<timestamp>`. It only changes what the diagnosis flagged:

- Switches a disabled or undersized pagefile to system-managed *(reboot)*
- Removes GC override environment variables and `.NETFramework` registry values
- Turns system-wide Mandatory ASLR back off *(reboot)*
- Restores the interactive desktop heap to 20480 KB *(reboot)*
- Restores lowered GDI/USER handle quotas to 10000 *(reboot)*
- Restores a corrupt `machine.config`/`web.config` from its `.default` copy, if one exists
- Runs `ngen executeQueuedItems` and `ngen update` for 32-bit and 64-bit (these do nothing when the cache is healthy)
- Sets `SchUseStrongCrypto=1` and `SystemDefaultTlsVersions=1` under the .NET Framework keys when
  they are missing or 0 (Microsoft's recommended setting; restart the apps afterwards)

Profilers, `AppInit_DLLs`, 32-bit apps, failed Windows updates, `runtimeconfig.json` settings,
Visual C++ Redistributable problems (including orphaned entries), application control policies,
SCHANNEL/FIPS settings, .NET 5+ install locations, temp folders and injected DLLs are reported
only. Each orphan finding names the exact registry path involved. Those belong to other products,
to whoever manages the machine, or need a human decision.

## Testing status

The report-only diagnosis has been run on Windows 11 under both Windows PowerShell 5.1 and
PowerShell 7. The crash-event parsing was checked against a deliberately crashed test app. The
Visual C++ orphan checks and installer-log parsing were checked against simulated orphaned entries
and fake failed installer logs, not against a real broken machine. Check 17 was checked with fake
`DOTNET_ROOT` variables, and check 20 with a third-party DLL loaded into two .NET processes.

**Never run on a real system:**

- `-Fix` and `-Repair`, beyond the admin check
- `-ResetNativeImages`
- Most `FAIL` paths, because the test machines didn't have those problems: a process near its
  handle limit, kernel handle leaks, handle growth, a `HeapHardLimit` setting, a currently failing
  .NET update, Setup log install failures
- Checks 15–20 against real blocks or failures: Code Integrity/AppLocker/ASR blocks, disabled TLS
  1.2, FIPS mode, a missing `hostfxr.dll`, component store corruption, a full temp folder, and
  crashes inside an injected DLL

If you use it and something is wrong, the CSV report and the console output are the most useful
things to share.

## Known limitations

- **Snapshot only.** Handle and process checks see the machine at the moment the script runs. Run
  it while the failing app is open and in use.
- **Single-file .NET apps** can bundle the runtime into the exe, so check 8 may not detect them,
  and their embedded `runtimeconfig.json` can't be read.
- **Per-app environment variables** set by a launcher or shortcut aren't visible. Only
  machine-wide and user-wide variables are checked.
- **The session GDI total** only covers your own session, not other users or services.
- **Managed update environments** (WSUS, Intune, offline patching) may leave little in the local
  Windows Update history for check 13 to use.
- **Thresholds** (for example 20,000 kernel handles, 80% of a quota) are rules of thumb, not hard limits.

## Privacy

The console output, console log and CSV report include the computer name, user name, installed software
and process names. Review them before posting them publicly.

## Disclaimer

Provided as-is, with no warranty. `-Fix`, `-Repair` and `-ResetNativeImages` change system
settings. Have a backup, and run with `-WhatIf` first.
