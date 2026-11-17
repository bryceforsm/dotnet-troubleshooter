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
| 8 | Running .NET processes | 32-bit .NET apps near the ~2 GB address-space limit; runtime and version of each .NET process; `System.GC.HeapHardLimit*` in .NET 5+ apps' `runtimeconfig.json` |
| 9 | DLL injection | `AppInit_DLLs` loaded into every GUI process |
| 10 | Allocation test | Starts 64-bit and 32-bit Windows PowerShell (.NET Framework) and PowerShell 7 (.NET), and allocates memory in each to confirm the runtime can allocate at all |
| 11 | Event log | Recent .NET app crashes (`.NET Runtime` events 1022–1026, `Application Error` 1000 inside the runtime), grouped by app with a likely-cause hint; out-of-memory errors from other sources |
| 12 | NGen native images | .NET Framework native image cache size, NGen service state, optimization-service errors |
| 13 | Windows Update | Failed .NET updates (Windows Update history and Setup log) with hints for common error codes; pending reboot; whether .NET 5+ is updated through Microsoft Update; optionally, .NET updates not yet installed |

Each finding is tagged:

```
  [ OK ] Nothing wrong found
  [INFO] Context, no action needed
  [WARN] Worth a look
  [FAIL] Likely cause of problems
         -> Suggested next step
```

A summary of all `WARN` and `FAIL` findings is printed at the end, and every finding is saved to
`%TEMP%\DotNetTroubleshooter-report-<timestamp>.csv`.

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
| `-BackupRoot <path>` | Where `-Fix` saves backups. Default: `%USERPROFILE%\DotNetTroubleshooter-Backups`. |

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

Profilers, `AppInit_DLLs`, 32-bit apps, failed Windows updates and `runtimeconfig.json` settings
are reported only. Those belong to other products or need a human decision.

## Testing status

The report-only diagnosis has been run on Windows 11 under both Windows PowerShell 5.1 and
PowerShell 7. The crash-event parsing was checked against a deliberately crashed test app.

**Never run on a real system:**

- `-Fix` and `-Repair`, beyond the admin check
- `-ResetNativeImages`
- Most `FAIL` paths, because the test machines didn't have those problems: a process near its
  handle limit, kernel handle leaks, handle growth, a `HeapHardLimit` setting, a currently failing
  .NET update, Setup log install failures

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

The console output and the CSV report include the computer name, user name, installed software
and process names. Review them before posting them publicly.

## Disclaimer

Provided as-is, with no warranty. `-Fix`, `-Repair` and `-ResetNativeImages` change system
settings. Have a backup, and run with `-WhatIf` first.
