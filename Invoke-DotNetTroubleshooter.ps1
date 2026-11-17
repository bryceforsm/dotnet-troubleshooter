<#
.SYNOPSIS
    Diagnoses (and optionally fixes) machine-level problems that break .NET Framework and
    .NET 5+ (desktop runtime: WinForms/WPF) apps: out-of-memory errors with free RAM, handle
    leaks, broken runtime installs or config, injected profilers/DLLs and corrupt native images.

.DESCRIPTION
    Checks the usual non-obvious causes:
      1. Commit limit / pagefile        - pagefile disabled or capped, commit charge exhausted
      2. CLR GC overrides                - COMPlus_/DOTNET_ GC env vars, .NETFramework registry values,
                                           and System.GC.* settings in running .NET apps' runtimeconfig.json
      3. CLR profilers                   - COR_* (Framework) / CORECLR_* (.NET 5+) profilers injected
                                           into every app; also lists installed .NET desktop runtimes
      4. Exploit protection              - system-wide Mandatory ASLR (breaks/fragments older .NET apps)
      5. Desktop heap                    - SharedSection too small (WinForms/WPF "out of memory")
      6. Handle quotas and usage         - lowered GDI/USER quotas, a process near its GDI/USER quota,
                                           session-wide GDI total, kernel handle leaks, and (with
                                           -HandleSampleSeconds) handle growth between two samples
      7. machine.config integrity        - corrupt config makes every .NET Framework app fail (Framework only)
      8. 32-bit address-space limits     - running 32-bit .NET Framework or .NET 5+ processes approaching ~2 GB
      9. AppInit_DLLs injection          - DLLs loaded into every GUI process
     10. Live allocation test            - spins up 64-bit and 32-bit Windows PowerShell (.NET Framework),
                                           plus PowerShell 7 (CoreCLR) if installed, and allocates memory
                                           to prove whether the runtime can allocate
     11. Event log                      - recent .NET app crashes (.NET Runtime 1022-1026, Application Error
                                           1000 in the CLR), grouped per app with a likely-cause hint,
                                           plus out-of-memory errors logged by other sources
     12. NGen native images             - .NET Framework native image cache, NGen service state and
                                           optimization-service errors (corrupt images crash Framework apps)
     13. Windows Update                 - failed .NET updates (WU history + Setup log) with error-code hints,
                                           pending reboot, whether .NET 5+ is updated via Microsoft Update,
                                           and (with -CheckAvailableUpdates) .NET updates not yet installed
     14. Visual C++ Redistributables    - installed versions; orphaned registrations that block upgrades
                                           (missing cached installers/MSIs, stale Programs and Features or
                                           dependency entries, duplicate v14 entries); v14 version consistency;
                                           failed VC_redist installs; crashes inside the C++ runtime DLLs
     15. Application control            - Smart App Control, WDAC (Code Integrity), AppLocker and Defender ASR
                                           blocks or detections hitting .NET apps and their DLLs
     16. TLS and cryptography           - SchUseStrongCrypto / SystemDefaultTlsVersions, TLS protocols turned
                                           off in SCHANNEL, FIPS mode, Schannel credential errors
     17. .NET 5+ host resolution        - missing hostfxr, bad registered install location, 32-bit dotnet.exe
                                           first on PATH, broken DOTNET_ROOT, ".NET not found" start failures
     18. Component store / .NET 3.5     - .NET 3.5 feature state, DISM /CheckHealth (admin), stuck pending.xml,
                                           servicing errors in CBS.log
     19. Temp folders and disk space    - missing or full temp folders (GetTempFileName fails at 65,535 files),
                                           live GetTempFileName test, low disk space
     20. Injected DLLs                  - third-party DLLs loaded into several .NET apps (security, overlay,
                                           hook tools), flagged when apps crash inside them

    Default is report-only. Use -Fix to apply safe fixes (backups + restore point first).
    Use -Repair to also run DISM /RestoreHealth and SFC to repair .NET Framework system files.
    -Fix also runs "ngen executeQueuedItems" and "ngen update" (no-ops when the cache is healthy),
    and sets SchUseStrongCrypto / SystemDefaultTlsVersions = 1 when they are missing or 0.
    Use -ResetNativeImages to delete and rebuild the .NET Framework native image cache (slow:
    10-30+ minutes; close .NET Framework apps first, ideally run from PowerShell 7).
    Supports -WhatIf with -Fix and -ResetNativeImages.

.EXAMPLE
    .\Invoke-DotNetTroubleshooter.ps1                 # diagnose only
.EXAMPLE
    .\Invoke-DotNetTroubleshooter.ps1 -Fix -WhatIf    # show what would be changed
.EXAMPLE
    .\Invoke-DotNetTroubleshooter.ps1 -Fix -Repair    # fix + repair system files (run as admin)
.EXAMPLE
    .\Invoke-DotNetTroubleshooter.ps1 -HandleSampleSeconds 60   # also watch for handle growth over 60 s
.EXAMPLE
    pwsh -File .\Invoke-DotNetTroubleshooter.ps1 -ResetNativeImages -SkipAllocationTest   # rebuild NGen cache (admin)
.EXAMPLE
    .\Invoke-DotNetTroubleshooter.ps1 -CheckAvailableUpdates   # also search online for .NET updates not yet installed
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Fix,
    [switch]$Repair,
    [string]$BackupRoot = (Join-Path $env:USERPROFILE 'DotNetTroubleshooter-Backups'),
    [string]$OutputDirectory = '',   # console log + CSV report; default: the script's own folder
    [switch]$SkipAllocationTest,
    [ValidateRange(0, 3600)]
    [int]$HandleSampleSeconds = 0,
    [switch]$ResetNativeImages,
    [switch]$CheckAvailableUpdates
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------- helpers
$script:Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([ValidateSet('OK','Info','Warn','Problem')]$Severity, $Area, $Detail, $Action = '')
    $script:Findings.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Detail = $Detail; Action = $Action })
    $tag   = @{ OK = '[ OK ]'; Info = '[INFO]'; Warn = '[WARN]'; Problem = '[FAIL]' }[$Severity]
    $color = @{ OK = 'Green'; Warn = 'Yellow'; Problem = 'Red' }[$Severity]
    if ($color) { Write-Host "  $tag " -ForegroundColor $color -NoNewline } else { Write-Host "  $tag " -NoNewline }
    Write-Host $Detail
    if ($Action) { Write-Host "         -> $Action" -ForegroundColor Cyan }
}
function Write-Section($t) { Write-Host "`n=== $t ===" -ForegroundColor White }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (($Fix -or $Repair -or $ResetNativeImages) -and -not $isAdmin) {
    Write-Warning 'Fixes and repairs need an elevated (Run as administrator) PowerShell. Re-run elevated.'
    return
}

$stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$BackupDir  = Join-Path $BackupRoot $stamp
$script:BackupReady = $false
$script:NeedsReboot = $false

# ---------------------------------------------------------------- output files (console log + CSV report)
# Written even under -WhatIf: they are the script's own output, not system changes.
if (-not $OutputDirectory) { $OutputDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }
try {
    if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force -WhatIf:$false -ErrorAction Stop | Out-Null }
    $probe = Join-Path $OutputDirectory ".write-test-$stamp"
    [IO.File]::WriteAllText($probe, '')
    Remove-Item $probe -Force -WhatIf:$false
} catch {
    Write-Warning "Cannot write to $OutputDirectory ($($_.Exception.Message)). Saving the console log and report to $env:TEMP instead."
    $OutputDirectory = $env:TEMP
}
$LogPath = Join-Path $OutputDirectory "DotNetTroubleshooter-console-$stamp.log"
$script:Transcribing = $false
try {
    Start-Transcript -Path $LogPath -WhatIf:$false -ErrorAction Stop | Out-Null
    $script:Transcribing = $true
} catch { Write-Warning "Console log will not be saved: $($_.Exception.Message)" }
# Stop the transcript if the script dies, so it doesn't keep recording the user's session.
trap { if ($script:Transcribing) { try { Stop-Transcript | Out-Null } catch { } }; break }

function Initialize-Backup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if ($script:BackupReady) { return }
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    Write-Host "`nBackups -> $BackupDir" -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess('System', 'Create restore point')) {
        try {
            Invoke-CimMethod -Namespace root/default -ClassName SystemRestore -MethodName CreateRestorePoint `
                -Arguments @{ Description = "Before .NET troubleshooter fix $stamp"; RestorePointType = [uint32]12; EventType = [uint32]100 } `
                -ErrorAction Stop | Out-Null
            Write-Host 'Restore point created.' -ForegroundColor Green
        } catch { Write-Warning "Could not create restore point (System Protection may be off): $($_.Exception.Message)" }
    }
    $script:BackupReady = $true
}
function Backup-RegKey([string]$NativePath) {
    Initialize-Backup
    $file = Join-Path $BackupDir (($NativePath -replace '[\\: ]', '_') + '.reg')
    & reg.exe export $NativePath $file /y 2>&1 | Out-Null
}

Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class OomNative {
    [DllImport("user32.dll")] public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64);
}
'@
# Separate type so a session that already loaded an older OomNative still gets these.
Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class DntNative {
    [DllImport("psapi.dll", SetLastError=true)]
    static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
    // All modules (32- and 64-bit). Process.Modules in a 64-bit .NET Framework host only sees the WOW64 stubs of a 32-bit process.
    public static string[] GetModulePaths(IntPtr hProcess) {
        IntPtr[] mods = new IntPtr[2048];
        int needed;
        if (!EnumProcessModulesEx(hProcess, mods, IntPtr.Size * mods.Length, out needed, 3)) return new string[0];
        int n = Math.Min(needed / IntPtr.Size, mods.Length);
        List<string> list = new List<string>();
        StringBuilder sb = new StringBuilder(1024);
        for (int i = 0; i < n; i++) {
            sb.Length = 0;
            if (GetModuleFileNameEx(hProcess, mods[i], sb, sb.Capacity) > 0) list.Add(sb.ToString());
        }
        return list.ToArray();
    }
}
'@

Write-Host ".NET troubleshooter (Framework + .NET 5+)  ($(Get-Date))" -ForegroundColor White
$modeParts = @('DIAGNOSE')
if ($Fix)               { $modeParts += 'FIX' }
if ($Repair)            { $modeParts += 'REPAIR' }
if ($ResetNativeImages) { $modeParts += 'RESET NATIVE IMAGES' }
if ($WhatIfPreference)  { $modeParts += '(WhatIf)' }
$modeText = $modeParts -join ' + '
if ($modeParts.Count -eq 1) { $modeText += ' ONLY (use -Fix to apply fixes)' }
Write-Host "Mode: $modeText"

# ---------------------------------------------------------------- system information
Write-Section 'System information'
function Get-RegValue($Path, $Name) {
    $item = Get-ItemProperty $Path -ErrorAction SilentlyContinue
    if ($item -and $item.PSObject.Properties[$Name]) { $item.$Name } else { $null }
}
$sysInfo = [ordered]@{}
try {
    $sOs  = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $sCs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction Stop
    $sCpu = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue)
    $sBios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $cv   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $displayVer = Get-RegValue $cv 'DisplayVersion'
    if (-not $displayVer) { $displayVer = Get-RegValue $cv 'ReleaseId' }
    $build = '{0}.{1}' -f (Get-RegValue $cv 'CurrentBuild'), (Get-RegValue $cv 'UBR')
    $uptime = (Get-Date) - $sOs.LastBootUpTime

    $sysInfo['Computer']     = $env:COMPUTERNAME
    $sysInfo['Domain']       = if ($sCs.PartOfDomain) { "$($sCs.Domain) (domain-joined)" } else { "$($sCs.Workgroup) (workgroup)" }
    $sysInfo['User']         = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $sysInfo['Elevated']     = if ($isAdmin) { 'Yes' } else { 'No' }
    $sysInfo['Session']      = '{0} (id {1})' -f $(if ($env:SESSIONNAME) { $env:SESSIONNAME } else { 'n/a' }), (Get-Process -Id $PID).SessionId
    $sysInfo['OS']           = '{0} {1} ({2}-bit)' -f $sOs.Caption.Trim(), $displayVer, $(if ([Environment]::Is64BitOperatingSystem) { 64 } else { 32 })
    $sysInfo['OS build']     = $build
    $sysInfo['Installed']    = '{0:d}' -f $sOs.InstallDate
    $sysInfo['Last boot']    = '{0:g} (up {1}d {2}h {3}m)' -f $sOs.LastBootUpTime, $uptime.Days, $uptime.Hours, $uptime.Minutes
    $sysInfo['Hardware']     = ('{0} {1}' -f $sCs.Manufacturer, $sCs.Model).Trim()
    if ("$($sCs.Model)" -match 'System Product Name|To Be Filled|Default string|^\s*$') {
        # Custom-built PC: the OEM model is a placeholder, so show the motherboard instead.
        $board = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
        if ($board) { $sysInfo['Hardware'] = ('{0} {1} (motherboard)' -f $board.Manufacturer, $board.Product).Trim() }
    }
    if ($sBios) { $sysInfo['BIOS'] = "$($sBios.SMBIOSBIOSVersion)" }
    if ($sCpu.Count) {
        $sysInfo['CPU'] = '{0} ({1} cores / {2} threads{3})' -f $sCpu[0].Name.Trim(),
            ($sCpu | Measure-Object NumberOfCores -Sum).Sum, ($sCpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum,
            $(if ($sCpu.Count -gt 1) { ", $($sCpu.Count) sockets" } else { '' })
    }
    $sysInfo['RAM']          = '{0:N1} GB' -f ($sCs.TotalPhysicalMemory / 1GB)
    $sysInfo['PowerShell']   = '{0} {1} ({2}-bit host, CLR {3})' -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, $(if ([Environment]::Is64BitProcess) { 64 } else { 32 }), [Environment]::Version
    $sysInfo['Locale']       = '{0} (UI {1})' -f (Get-Culture).Name, (Get-UICulture).Name
    $sysInfo['Time zone']    = [TimeZoneInfo]::Local.DisplayName
} catch {
    $sysInfo['Error'] = "Could not read system information: $($_.Exception.Message)"
}
foreach ($k in $sysInfo.Keys) {
    Write-Host ("  {0,-11} {1}" -f $k, $sysInfo[$k])
    $script:Findings.Add([pscustomobject]@{ Severity = 'Info'; Area = 'System'; Detail = "${k}: $($sysInfo[$k])"; Action = '' })
}
if (-not $isAdmin) { Write-Host '  Not elevated: some checks will be partial.' -ForegroundColor Yellow }

# ---------------------------------------------------------------- 1. memory / commit / pagefile
Write-Section '1. Physical memory, commit limit and pagefile'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$ramGB       = $os.TotalVisibleMemorySize / 1MB
$freeRamGB   = $os.FreePhysicalMemory / 1MB
$commitGB    = $os.TotalVirtualMemorySize / 1MB
$freeCommitGB= $os.FreeVirtualMemory / 1MB
Add-Finding Info 'Memory' ("RAM {0:N1} GB ({1:N1} free); commit limit {2:N1} GB ({3:N1} free)" -f $ramGB, $freeRamGB, $commitGB, $freeCommitGB)

$pfUsage = @(Get-CimInstance Win32_PageFileUsage)
$pfTotalGB = ($pfUsage | Measure-Object AllocatedBaseSize -Sum).Sum / 1KB
if ($freeCommitGB -lt ($commitGB * 0.10)) {
    Add-Finding Problem 'Commit' ("Commit charge nearly exhausted ({0:N1} GB free). Allocations fail even with free RAM." -f $freeCommitGB) 'Close the top consumers below and/or enlarge the pagefile'
    Get-Process | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First 8 Name, Id,
        @{n = 'Private_GB'; e = { [math]::Round($_.PrivateMemorySize64 / 1GB, 2) } } | Format-Table -AutoSize | Out-Host
} else { Add-Finding OK 'Commit' 'Commit headroom is fine.' }

if (-not $cs.AutomaticManagedPagefile) {
    $pfSettings = @(Get-CimInstance Win32_PageFileSetting)
    $tooSmall = ($pfSettings.Count -eq 0) -or ($pfTotalGB -lt 4)
    if ($tooSmall) {
        Add-Finding Problem 'Pagefile' ("Pagefile is manual and {0}. .NET reserves/commits large GC segments, so a missing pagefile causes OOM despite free RAM." -f $(if ($pfSettings.Count -eq 0) { 'DISABLED' } else { "only {0:N1} GB" -f $pfTotalGB })) 'Fix: switch to system-managed pagefile (reboot required)'
        if ($Fix -and $PSCmdlet.ShouldProcess('Pagefile', 'Enable automatic (system-managed) pagefile')) {
            Initialize-Backup
            $pfSettings | Select-Object Name, InitialSize, MaximumSize | ConvertTo-Json | Set-Content (Join-Path $BackupDir 'pagefile-settings.json')
            Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $true }
            Add-Finding OK 'Pagefile' 'Pagefile set to system-managed.'
            $script:NeedsReboot = $true
        }
    } else { Add-Finding Info 'Pagefile' ("Manual pagefile, {0:N1} GB allocated." -f $pfTotalGB) }
} else { Add-Finding OK 'Pagefile' ("System-managed pagefile ({0:N1} GB currently allocated)." -f $pfTotalGB) }

# ---------------------------------------------------------------- 2/3. CLR env vars
Write-Section '2. CLR / GC environment variables'
$gcPattern       = '^(COMPlus|DOTNET)_(GC\w*|gcServer|gcConcurrent|gcTrace)$'
$profilerPattern = '^(COR|CORECLR)_(ENABLE_PROFILING|PROFILER|PROFILER_PATH(_32|_64)?)$|^(COMPlus|DOTNET)_EnableEventPipe$'
$anyEnv = $false
foreach ($scope in 'Machine', 'User') {
    $vars = [Environment]::GetEnvironmentVariables($scope)
    foreach ($name in @($vars.Keys)) {
        $val = $vars[$name]
        if ($name -match $gcPattern) {
            $anyEnv = $true
            Add-Finding Problem 'CLR env' "$scope env var $name=$val overrides GC heap behaviour for every .NET app" 'Fix: remove variable'
            if ($Fix -and $PSCmdlet.ShouldProcess("$scope env $name", 'Remove')) {
                Initialize-Backup
                Add-Content (Join-Path $BackupDir 'env-vars-removed.txt') "$scope`t$name`t$val"
                [Environment]::SetEnvironmentVariable($name, $null, $scope)
                Add-Finding OK 'CLR env' "Removed $scope env var $name (sign out/in to apply)."
            }
        } elseif ($name -match $profilerPattern) {
            $anyEnv = $true
            Add-Finding Warn 'CLR profiler' "$scope env var $name=$val - a CLR profiler is injected into every .NET app (APM/security tools). Buggy profilers can cause OOM." 'Manual: identify the owning product; test by temporarily setting COR_ENABLE_PROFILING=0 (Framework) / CORECLR_ENABLE_PROFILING=0 (.NET 5+)'
        }
    }
}
if (-not $anyEnv) { Add-Finding OK 'CLR env' 'No GC or profiler overrides in Machine/User environment.' }

Write-Section '3. CLR registry configuration'
$regKeys = @(
    @{ Ps = 'HKLM:\SOFTWARE\Microsoft\.NETFramework';             Native = 'HKLM\SOFTWARE\Microsoft\.NETFramework' },
    @{ Ps = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework'; Native = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework' },
    @{ Ps = 'HKCU:\SOFTWARE\Microsoft\.NETFramework';             Native = 'HKCU\SOFTWARE\Microsoft\.NETFramework' }
)
$regGcPattern = '^(GC\w*|gcServer|gcConcurrent|GCgen0size|GCHeapHardLimit\w*)$'
$anyReg = $false
foreach ($k in $regKeys) {
    if (-not (Test-Path $k.Ps)) { continue }
    $props = (Get-ItemProperty $k.Ps).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
    foreach ($p in $props) {
        if ($p.Name -match $regGcPattern) {
            $anyReg = $true
            Add-Finding Problem 'CLR registry' "$($k.Native)\$($p.Name)=$($p.Value) (GC override)" 'Fix: remove value'
            if ($Fix -and $PSCmdlet.ShouldProcess("$($k.Native)\$($p.Name)", 'Remove registry value')) {
                Backup-RegKey $k.Native
                Remove-ItemProperty -Path $k.Ps -Name $p.Name
                Add-Finding OK 'CLR registry' "Removed $($p.Name)."
            }
        } elseif ($p.Name -match '^(COR_ENABLE_PROFILING|COR_PROFILER)$') {
            $anyReg = $true
            Add-Finding Warn 'CLR registry' "$($k.Native)\$($p.Name)=$($p.Value) (profiler)" 'Manual: identify the owning product'
        }
    }
}
if (-not $anyReg) { Add-Finding OK 'CLR registry' 'No GC/profiler overrides under .NETFramework keys.' }

$rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue)
if ($rel) { Add-Finding Info '.NET version' ".NET Framework 4.x release $($rel.Release) (version $($rel.Version))" }
else { Add-Finding Problem '.NET version' '.NET Framework 4.x registration missing.' 'Run with -Repair' }

# .NET 5+ shared runtimes. A framework-dependent WinForms/WPF app needs both
# Microsoft.NETCore.App and Microsoft.WindowsDesktop.App for its own bitness.
$pf64 = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$pf86 = ${env:ProgramFiles(x86)}
$runtimeRoots = @(@{ Arch = 'x64'; Dir = (Join-Path $pf64 'dotnet\shared') })
if ($pf86) { $runtimeRoots += @{ Arch = 'x86'; Dir = (Join-Path $pf86 'dotnet\shared') } }
$anyDesktop = $false
foreach ($rr in $runtimeRoots) {
    foreach ($fx in 'Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App') {
        $fxDir = Join-Path $rr.Dir $fx
        $vers = @(if (Test-Path $fxDir) { Get-ChildItem $fxDir -Directory | Select-Object -ExpandProperty Name })
        if ($vers.Count) {
            if ($fx -eq 'Microsoft.WindowsDesktop.App') { $anyDesktop = $true }
            Add-Finding Info '.NET runtimes' ("{0} {1}: {2}" -f $rr.Arch, $fx, ($vers -join ', '))
        }
    }
}
if (-not $anyDesktop) { Add-Finding Info '.NET runtimes' 'No .NET 5+ desktop runtime (Microsoft.WindowsDesktop.App) installed. Self-contained apps carry their own.' }

# ---------------------------------------------------------------- 4. exploit protection
Write-Section '4. Exploit protection (ASLR)'
try {
    $aslr = (Get-ProcessMitigation -System -ErrorAction Stop).ASLR
    if ("$($aslr.ForceRelocateImages)" -eq 'ON') {
        Add-Finding Problem 'Exploit prot.' 'System-wide Mandatory ASLR (Force randomization for images) is ON. Known to break/fragment address space for older .NET Framework apps.' 'Fix: set to default (off)'
        if ($Fix -and $PSCmdlet.ShouldProcess('System mitigation ForceRelocateImages', 'Disable')) {
            Initialize-Backup
            Get-ProcessMitigation -System | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $BackupDir 'system-mitigations.json')
            Set-ProcessMitigation -System -Disable ForceRelocateImages
            Add-Finding OK 'Exploit prot.' 'Mandatory ASLR set back to off.'
            $script:NeedsReboot = $true
        }
    } else { Add-Finding OK 'Exploit prot.' "Mandatory ASLR: $($aslr.ForceRelocateImages); BottomUp: $($aslr.BottomUp); HighEntropy: $($aslr.HighEntropy)" }
} catch { Add-Finding Info 'Exploit prot.' "Could not read system mitigations: $($_.Exception.Message)" }

# ---------------------------------------------------------------- 5. desktop heap
Write-Section '5. Desktop heap'
$ssKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems'
$winVal = (Get-ItemProperty $ssKey).Windows
if ($winVal -match 'SharedSection=(\d+),(\d+)(?:,(\d+))?') {
    $interactive = [int]$Matches[2]
    if ($interactive -lt 20480) {
        Add-Finding Problem 'Desktop heap' "Interactive desktop heap is $interactive KB (default 20480). Causes WinForms/WPF 'out of memory' with free RAM." 'Fix: set to 20480 (reboot required)'
        if ($Fix -and $PSCmdlet.ShouldProcess('SharedSection', 'Set interactive desktop heap to 20480 KB')) {
            Backup-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems'
            $third = if ($Matches[3]) { ",$($Matches[3])" } else { '' }
            $new = $winVal -replace 'SharedSection=\d+,\d+(,\d+)?', ("SharedSection={0},20480{1}" -f $Matches[1], $third)
            Set-ItemProperty $ssKey -Name Windows -Value $new
            Add-Finding OK 'Desktop heap' 'Interactive desktop heap set to 20480 KB.'
            $script:NeedsReboot = $true
        }
    } else { Add-Finding OK 'Desktop heap' "SharedSection interactive heap = $interactive KB." }
}
$heapEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 243, 244; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 5 -ErrorAction SilentlyContinue)
if ($heapEvents.Count) { Add-Finding Problem 'Desktop heap' "$($heapEvents.Count) desktop-heap allocation failure event(s) in the last 30 days." }

# ---------------------------------------------------------------- 6. GDI / USER / kernel handles
Write-Section '6. Handle quotas and usage (GDI / USER / kernel)'
$quotaKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$q = Get-ItemProperty $quotaKey
$effectiveQuota = @{}
foreach ($qn in 'GDIProcessHandleQuota', 'USERProcessHandleQuota') {
    $prop = $q.PSObject.Properties[$qn]          # StrictMode-safe: value may be absent
    $v = if ($prop) { $prop.Value } else { $null }
    $effectiveQuota[$qn] = if ($null -ne $v -and $v -ge 10000) { [int]$v } else { 10000 }
    if ($null -ne $v -and $v -lt 10000) {
        Add-Finding Problem 'Handle quota' "$qn = $v (default 10000). GDI+ reports exhausted handles as 'Out of memory'." 'Fix: restore to 10000 (reboot required)'
        if ($Fix -and $PSCmdlet.ShouldProcess($qn, 'Set to 10000')) {
            Backup-RegKey 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
            Set-ItemProperty $quotaKey -Name $qn -Value 10000 -Type DWord
            Add-Finding OK 'Handle quota' "$qn restored to 10000."
            $script:NeedsReboot = $true
        }
    } else { Add-Finding OK 'Handle quota' ("$qn = {0}" -f $(if ($null -ne $v) { $v } else { 'not set (default 10000)' })) }
}

# One row per process. Kernel handle counts come from system process info and are
# readable for every process; GDI/USER counts need the process opened, which can fail.
function Get-HandleSnapshot {
    $rows    = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($p in Get-Process) {
        if ($p.Id -in 0, 4) { continue }   # Idle / System
        $gdi = $null; $user = $null
        try {
            $h = $p.Handle
            $gdi  = [int][OomNative]::GetGuiResources($h, 0)
            $user = [int][OomNative]::GetGuiResources($h, 1)
        } catch { $skipped.Add("$($p.Name) ($($p.Id))") }
        $rows.Add([pscustomobject]@{ Name = $p.Name; Id = $p.Id; SessionId = $p.SessionId; Kernel = $p.HandleCount; GDI = $gdi; USER = $user })
    }
    [pscustomobject]@{ Rows = $rows; Skipped = $skipped }
}
$snap = Get-HandleSnapshot

# --- per-process GDI / USER, against the effective quota
$gdiWarn  = [int]($effectiveQuota['GDIProcessHandleQuota']  * 0.8)
$userWarn = [int]($effectiveQuota['USERProcessHandleQuota'] * 0.8)
$hot = @($snap.Rows | Where-Object { ($null -ne $_.GDI -and $_.GDI -ge $gdiWarn) -or ($null -ne $_.USER -and $_.USER -ge $userWarn) })
if ($hot.Count) {
    foreach ($r in $hot) {
        Add-Finding Problem 'GDI leak' ("{0} (PID {1}) uses GDI={2}/{3} USER={4}/{5} - near the per-process limit" -f $r.Name, $r.Id, $r.GDI, $effectiveQuota['GDIProcessHandleQuota'], $r.USER, $effectiveQuota['USERProcessHandleQuota']) 'Restart that app; report the leak to its vendor'
    }
} else {
    $top = $snap.Rows | Where-Object { $null -ne $_.GDI } | Sort-Object GDI -Descending | Select-Object -First 1
    if ($top) { Add-Finding OK 'GDI usage' "Highest GDI user: $($top.Name) with $($top.GDI) objects (warn at $gdiWarn)." }
}

# --- session-wide GDI total (limit ~65,536 per session, shared by all its processes)
$sessionGdiLimit = 65536
$mySession  = (Get-Process -Id $PID).SessionId
$sessionGdi = [int](($snap.Rows | Where-Object { $_.SessionId -eq $mySession -and $null -ne $_.GDI } | Measure-Object GDI -Sum).Sum)
if ($sessionGdi -ge ($sessionGdiLimit * 0.8)) {
    Add-Finding Problem 'Session GDI' "Session $mySession uses $sessionGdi of ~$sessionGdiLimit GDI objects in total. New windows/bitmaps fail with 'out of memory' even if no single app looks bad." 'Close the top GDI users (see table below) or sign out/in'
    $snap.Rows | Where-Object { $_.SessionId -eq $mySession -and $null -ne $_.GDI } | Sort-Object GDI -Descending |
        Select-Object -First 8 Name, Id, GDI, USER | Format-Table -AutoSize | Out-Host
} else { Add-Finding OK 'Session GDI' "Session $mySession GDI total: $sessionGdi of ~$sessionGdiLimit." }

# --- kernel handles (files, events, registry keys, threads, sockets...)
$kernelWarn = 20000; $kernelProblem = 100000
Write-Host '  Top kernel handle users:' -ForegroundColor Gray
$snap.Rows | Sort-Object Kernel -Descending | Select-Object -First 8 Name, Id, Kernel, GDI, USER | Format-Table -AutoSize | Out-Host
$bigK = @($snap.Rows | Where-Object { $_.Kernel -ge $kernelWarn } | Sort-Object Kernel -Descending)
foreach ($r in $bigK) {
    $sev = if ($r.Kernel -ge $kernelProblem) { 'Problem' } else { 'Warn' }
    Add-Finding $sev 'Kernel handles' "$($r.Name) (PID $($r.Id)) holds $($r.Kernel) kernel handles. In .NET this is usually undisposed IDisposable objects (streams, WaitHandles, Process, HttpClient per call)." 'Confirm it keeps growing with -HandleSampleSeconds 60; restart the app; report the leak to its vendor'
}
if (-not $bigK.Count) { Add-Finding OK 'Kernel handles' "No process holds $kernelWarn+ kernel handles." }

# --- coverage: processes we could not open for GDI/USER counts
if ($snap.Skipped.Count) {
    if ($isAdmin) {
        Add-Finding Info 'Handle coverage' "$($snap.Skipped.Count) protected process(es) could not be opened for GDI/USER counts (normal for system processes). Kernel counts cover all processes."
    } else {
        Add-Finding Warn 'Handle coverage' "GDI/USER counts unavailable for $($snap.Skipped.Count) process(es) because this session is not elevated - including any app running elevated or as another user. Kernel counts cover all processes." 'Re-run as administrator for complete GDI/USER coverage'
    }
}

# --- optional second sample to detect growth (a leak keeps climbing)
if ($HandleSampleSeconds -gt 0) {
    Write-Host "  Sampling again in $HandleSampleSeconds s to detect handle growth (keep using the failing app)..." -ForegroundColor Gray
    Start-Sleep -Seconds $HandleSampleSeconds
    $snap2  = Get-HandleSnapshot
    $before = @{}
    foreach ($r in $snap.Rows) { $before[$r.Id] = $r }
    $growth = @(foreach ($r in $snap2.Rows) {
        $b = $before[$r.Id]
        if (-not $b -or $b.Name -ne $r.Name) { continue }   # new process or reused PID
        $dK = $r.Kernel - $b.Kernel
        $dG = if ($null -ne $r.GDI  -and $null -ne $b.GDI)  { $r.GDI  - $b.GDI }  else { 0 }
        $dU = if ($null -ne $r.USER -and $null -ne $b.USER) { $r.USER - $b.USER } else { 0 }
        if ($dK -ge 200 -or $dG -ge 50 -or $dU -ge 50) {
            [pscustomobject]@{ Name = $r.Name; Id = $r.Id; KernelDelta = $dK; GDIDelta = $dG; USERDelta = $dU; Kernel = $r.Kernel; GDI = $r.GDI }
        }
    })
    if ($growth.Count) {
        $growth | Sort-Object KernelDelta -Descending | Format-Table -AutoSize | Out-Host
        foreach ($g in $growth) {
            $perMin = 60.0 / $HandleSampleSeconds
            Add-Finding Warn 'Handle growth' ("{0} (PID {1}) grew kernel {2:+#;-#;0}, GDI {3:+#;-#;0}, USER {4:+#;-#;0} in {5}s (~{6:N0} kernel/min)" -f $g.Name, $g.Id, $g.KernelDelta, $g.GDIDelta, $g.USERDelta, $HandleSampleSeconds, ($g.KernelDelta * $perMin)) 'One sample can be noise; a leak keeps rising across repeated runs and never drops back'
        }
    } else { Add-Finding OK 'Handle growth' "No process grew noticeably over $HandleSampleSeconds s." }
}

# ---------------------------------------------------------------- 7. machine.config
Write-Section '7. .NET Framework configuration files'
foreach ($fw in 'Framework', 'Framework64') {
    $cfgDir = Join-Path $env:WINDIR "Microsoft.NET\$fw\v4.0.30319\Config"
    foreach ($f in 'machine.config', 'web.config') {
        $path = Join-Path $cfgDir $f
        if (-not (Test-Path $path)) { if ($f -eq 'machine.config') { Add-Finding Problem 'Config' "$path is missing." 'Run with -Repair' }; continue }
        try { [xml](Get-Content $path -Raw) | Out-Null; Add-Finding OK 'Config' "$fw\$f parses OK." }
        catch {
            Add-Finding Problem 'Config' "$path is corrupt: $($_.Exception.Message)" "Fix: restore from $f.default if present, else -Repair"
            $default = "$path.default"
            if ($Fix -and (Test-Path $default) -and $PSCmdlet.ShouldProcess($path, "Restore from $f.default")) {
                Initialize-Backup
                Copy-Item $path (Join-Path $BackupDir "$fw-$f.corrupt")
                Copy-Item $default $path -Force
                Add-Finding OK 'Config' "Restored $path from default."
            }
        }
    }
}

# ---------------------------------------------------------------- 8. 32-bit .NET processes
Write-Section '8. Running .NET processes (address-space and runtimeconfig check)'
function Get-ModuleVersion($m) {
    $v = $m.FileVersionInfo.ProductVersion
    if (-not $v) { $v = $m.FileVersionInfo.FileVersion }
    if ($v) { ($v -split '[+ ]')[0] } else { '?' }
}
function New-ModuleInfo([string]$FilePath) {
    $o = [pscustomobject]@{ ModuleName = [IO.Path]::GetFileName($FilePath); FileName = $FilePath }
    $o | Add-Member -MemberType ScriptProperty -Name FileVersionInfo -Value { [Diagnostics.FileVersionInfo]::GetVersionInfo($this.FileName) }
    $o
}
$script:CompanyCache = @{}
function Get-FileCompany([string]$FilePath) {
    if (-not $script:CompanyCache.ContainsKey($FilePath)) {
        $co = ''
        try { $co = "$([Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath).CompanyName)".Trim() } catch { }
        $script:CompanyCache[$FilePath] = $co
    }
    $script:CompanyCache[$FilePath]
}
# Not counted as injected: Windows component store, GAC/native images, GPU drivers, the .NET install itself.
$notInjectedPath = '\\Windows\\(WinSxS|Microsoft\.NET|assembly|System32\\DriverStore|SystemApps)\\|\\dotnet\\(shared|host)\\'
$modSkipped = 0
$netProcs = foreach ($p in Get-Process) {
    if ($p.Id -in 0, 4) { continue }   # Idle / System
    # Modules can't be read for protected, elevated or other users' processes (unless we're elevated).
    # PowerShell then hands back nothing instead of throwing, so check the list before using it.
    $mods = @()
    try { $mods = @($p.Modules | Where-Object { $null -ne $_ -and $_.PSObject.Properties['ModuleName'] }) } catch { }
    if (-not $mods.Count) { $modSkipped++; continue }
    $wow = $false
    try { [void][OomNative]::IsWow64Process($p.Handle, [ref]$wow) } catch { }
    if ($wow -and [Environment]::Is64BitProcess -and -not ($mods | Where-Object { $_.ModuleName -eq 'kernel32.dll' })) {
        # 64-bit Windows PowerShell only got the WOW64 stubs of this 32-bit process: list its real modules natively.
        $paths = @(try { [DntNative]::GetModulePaths($p.Handle) } catch { })
        if ($paths.Count) { $mods = @(foreach ($fp in $paths) { New-ModuleInfo $fp }) }
    }
    try {
        $clr  =$mods | Where-Object { $_.ModuleName -in 'clr.dll', 'mscorwks.dll' } | Select-Object -First 1
        $core = $mods | Where-Object { $_.ModuleName -eq 'coreclr.dll' } | Select-Object -First 1
        if (-not ($clr -or $core)) { continue }
        $coreDir = $null; $selfContained = $false; $netVer = $null
        $runtime = if ($core) {
            # Shared runtime lives in ...\Microsoft.NETCore.App\<version>\coreclr.dll; otherwise it's bundled with the app.
            $coreDir = Split-Path $core.FileName -Parent
            if ((Split-Path $coreDir -Leaf) -match '^\d+\.\d+\.\d+' -and (Split-Path (Split-Path $coreDir -Parent) -Leaf) -eq 'Microsoft.NETCore.App') {
                $netVer = Split-Path $coreDir -Leaf
                ".NET $netVer"
            } else {
                $selfContained = $true
                # Exact version from the app's own CoreLib, e.g. "10.0.14-servicing.26522.126+0427b9a" -> 10.0.14
                $coreLib = Join-Path $coreDir 'System.Private.CoreLib.dll'
                if (Test-Path $coreLib) { $netVer = ("$((Get-Item $coreLib).VersionInfo.ProductVersion)" -split '[-+ ]')[0] }
                if ($netVer -notmatch '^\d+\.\d+\.\d+$') {
                    $fv = $core.FileVersionInfo
                    $netVer = '{0}.{1}' -f $fv.FileMajorPart, $fv.FileMinorPart
                }
                ".NET $netVer (self-contained)"
            }
        } else { "Framework $(Get-ModuleVersion $clr)" }
        $desktop = [bool]($mods | Where-Object { $_.ModuleName -in 'PresentationFramework.dll', 'System.Windows.Forms.dll', 'wpfgfx_cor3.dll', 'wpfgfx_v0400.dll' })
        # Visual C++ runtimes loaded (vcruntime140 -> 14, msvcr120 -> 12, ...); app-local copies like vcruntime140_cor3 are ignored
        $vcrt = (@($mods | ForEach-Object { if ($_.ModuleName -match '^(?:vcruntime|msvcr)(\d{2,3})\.dll$') { [int]$Matches[1] / 10 } }) | Sort-Object -Unique) -join ','
        # Third-party modules from outside the app's folder and the runtime. Section 20 reports the ones
        # found in several apps, which points to something injecting itself (security, overlay, hook tools).
        $appDir = if ($p.Path) { Split-Path $p.Path -Parent } else { '' }
        $appCo  = if ($p.Path) { Get-FileCompany $p.Path } else { '' }
        $foreign = @(foreach ($m in $mods) {
            $fn = "$($m.FileName)"
            if (-not $fn -or $fn -match $notInjectedPath) { continue }
            if ($appDir -and $fn.StartsWith("$appDir\", [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($coreDir -and $fn.StartsWith("$coreDir\", [StringComparison]::OrdinalIgnoreCase)) { continue }
            $co = Get-FileCompany $fn
            if ($co -match 'Microsoft' -or ($appCo -and $co -eq $appCo)) { continue }
            $fn
        })
        [pscustomobject]@{
            Name = $p.Name; Id = $p.Id; Bits = $(if ($wow) { 32 } else { 64 }); Runtime = $runtime; GUI = $desktop; VCRT = $vcrt
            PrivateGB = [math]::Round($p.PrivateMemorySize64 / 1GB, 2); VirtualGB = [math]::Round($p.VirtualMemorySize64 / 1GB, 2)
            Path = $p.Path; IsCore = [bool]$core; SelfContained = $selfContained; NetVersion = $netVer; RuntimeDir = $coreDir
            Foreign = $foreign
        }
    } catch { }
}
$netProcs = @($netProcs)
if ($modSkipped) {
    if ($isAdmin) {
        Add-Finding Info 'Process coverage' "$modSkipped protected process(es) could not be inspected for .NET (normal for system processes)."
    } else {
        Add-Finding Info 'Process coverage' "$modSkipped process(es) could not be inspected because this session is not elevated. A .NET app running elevated, as a service or as another user won't appear below." 'Re-run as administrator to include them'
    }
}
if ($netProcs.Count) {
    $netProcs | Sort-Object Bits, PrivateGB -Descending | Format-Table Name, Id, Bits, Runtime, GUI, VCRT, PrivateGB, VirtualGB -AutoSize | Out-Host
    foreach ($np in ($netProcs | Where-Object { $_.Bits -eq 32 -and ($_.VirtualGB -gt 1.6 -or $_.PrivateGB -gt 1.2) })) {
        Add-Finding Problem '32-bit limit' "$($np.Name) (PID $($np.Id), $($np.Runtime)) is a 32-bit .NET process using $($np.VirtualGB) GB virtual / $($np.PrivateGB) GB private. 32-bit apps hit OOM at ~1.5-2 GB no matter how much RAM you have." 'Use the app''s 64-bit build, or ask the vendor to enable /LARGEADDRESSAWARE'
    }
    if (-not ($netProcs | Where-Object Bits -eq 32)) { Add-Finding OK '32-bit limit' 'No running 32-bit .NET processes.' }

    # Self-contained apps carry their own .NET: Windows Update .NET patches never reach them.
    # Compare each one with the newest installed shared runtime of the same major.minor and bitness.
    $sharedVers = @{}
    foreach ($rr in $runtimeRoots) {
        $fxDir = Join-Path $rr.Dir 'Microsoft.NETCore.App'
        $sharedVers[$rr.Arch] = @(if (Test-Path $fxDir) {
            Get-ChildItem $fxDir -Directory | ForEach-Object { $v = $null; if ([version]::TryParse($_.Name, [ref]$v)) { $v } }
        })
    }
    foreach ($grp in ($netProcs | Where-Object { $_.SelfContained -and $_.RuntimeDir } | Group-Object RuntimeDir)) {
        $sc    = $grp.Group[0]
        $names = ($grp.Group | ForEach-Object Name | Sort-Object -Unique) -join ', '
        $own   = $null
        $compare = ''
        if ([version]::TryParse($sc.NetVersion, [ref]$own) -and $own.Build -ge 0) {
            $arch   = if ($sc.Bits -eq 32) { 'x86' } else { 'x64' }
            $newest = @($sharedVers[$arch]) | Where-Object { $_ -and $_.Major -eq $own.Major -and $_.Minor -eq $own.Minor } | Sort-Object -Descending | Select-Object -First 1
            $compare = if (-not $newest) { "no installed $($own.Major).$($own.Minor) runtime to compare" }
                       elseif ($newest.Build -gt $own.Build) {
                           $behind = $newest.Build - $own.Build
                           "{0} patch{1} behind installed {2}" -f $behind, $(if ($behind -eq 1) { '' } else { 'es' }), $newest
                       }
                       else { "same as installed $newest" }
            $compare = " ($compare)"
        }
        Add-Finding Info 'Self-contained' "${names}: own .NET $($sc.NetVersion)$compare in $($sc.RuntimeDir). Not patched by Windows Update; changes only when the app updates."
    }

    # .NET 5+ apps read GC settings from <app>.runtimeconfig.json next to the exe.
    $hardLimitKeys = '^System\.GC\.(HeapHardLimit\w*)$'
    $seen = @{}
    foreach ($np in ($netProcs | Where-Object { $_.IsCore -and $_.Path })) {
        $rc = [IO.Path]::ChangeExtension($np.Path, '.runtimeconfig.json')
        if ($seen.ContainsKey($rc)) { continue }
        $seen[$rc] = $true
        if (-not (Test-Path $rc)) { continue }   # self-contained single-file apps embed it
        try {
            $json = Get-Content $rc -Raw | ConvertFrom-Json
            $ro = $json.PSObject.Properties['runtimeOptions']
            $cp = if ($ro) { $ro.Value.PSObject.Properties['configProperties'] } else { $null }
            if (-not $cp) { continue }
            foreach ($setting in ($cp.Value.PSObject.Properties | Where-Object Name -like 'System.GC.*')) {
                if ($setting.Name -match $hardLimitKeys) {
                    Add-Finding Problem 'runtimeconfig' "$($np.Name): $($setting.Name)=$($setting.Value) in $rc caps the managed heap - OOM when reached regardless of free RAM." 'Manual: raise or remove it (vendor-owned file; back it up first)'
                } else {
                    Add-Finding Info 'runtimeconfig' "$($np.Name): $($setting.Name)=$($setting.Value) ($rc)"
                }
            }
        } catch { Add-Finding Warn 'runtimeconfig' "$rc could not be parsed: $($_.Exception.Message)" }
    }
} else { Add-Finding Info '32-bit limit' 'No .NET processes visible right now (run while the failing app is open for this check; run elevated to see elevated apps).' }

# ---------------------------------------------------------------- 9. AppInit_DLLs
Write-Section '9. DLL injection (AppInit_DLLs)'
foreach ($ak in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
    $a = Get-ItemProperty $ak -ErrorAction SilentlyContinue
    if ($a -and $a.LoadAppInit_DLLs -eq 1 -and $a.AppInit_DLLs) {
        Add-Finding Warn 'AppInit' "$ak loads into every GUI process: $($a.AppInit_DLLs)" 'Manual: identify the product; these hooks can reserve memory in every process'
    }
}
if (-not ($script:Findings | Where-Object Area -eq 'AppInit')) { Add-Finding OK 'AppInit' 'No AppInit_DLLs injection.' }

# ---------------------------------------------------------------- 10. live allocation test
Write-Section '10. Live allocation test (.NET Framework and CoreCLR)'
if ($SkipAllocationTest) { Add-Finding Info 'Alloc test' 'Skipped.' }
else {
    # PowerShell 7 runs on CoreCLR. Its standard install bundles its own runtime, so this proves
    # CoreCLR can allocate on this machine, not that the installed desktop runtime is healthy.
    $pwshExe = Get-Command pwsh.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
    $tests = @(
        @{ Label = '64-bit .NET Framework'; Exe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'; ChunkMB = 512; Chunks = 4 },  # 2 GB
        @{ Label = '32-bit .NET Framework'; Exe = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'; ChunkMB = 128; Chunks = 6 },  # 768 MB
        @{ Label = 'CoreCLR (PowerShell 7)'; Exe = $pwshExe; ChunkMB = 512; Chunks = 4 }                                                          # 2 GB
    )
    if (-not $pwshExe) { Add-Finding Info 'Alloc test' 'PowerShell 7 (pwsh) not installed - CoreCLR allocation test skipped.' }
    foreach ($t in $tests) {
        if (-not $t.Exe -or -not (Test-Path $t.Exe)) { continue }
        $cmd = @"
`$ErrorActionPreference='Stop'; `$l = New-Object System.Collections.ArrayList; `$done = 0
try { for (`$i=0; `$i -lt $($t.Chunks); `$i++) { `$b = New-Object byte[] ($($t.ChunkMB)MB); for (`$j=0; `$j -lt `$b.Length; `$j += 4096) { `$b[`$j] = 1 }; [void]`$l.Add(`$b); `$done += $($t.ChunkMB) }
      "OK `$done CLR=`$([Environment]::Version)" }
catch { "FAIL after `$done MB: `$(`$_.Exception.GetType().FullName): `$(`$_.Exception.Message)" }
"@
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        $out = (& $t.Exe -NoProfile -NonInteractive -EncodedCommand $enc 2>&1 | Out-String).Trim()
        $target = $t.ChunkMB * $t.Chunks
        if ($out -like 'OK*') { Add-Finding OK 'Alloc test' "$($t.Label) allocated $target MB successfully ($out)." }
        elseif ($out) { Add-Finding Problem 'Alloc test' "$($t.Label) allocation FAILED: $out" 'The runtime itself cannot allocate - see other findings; try -Repair' }
        else { Add-Finding Problem 'Alloc test' "$($t.Label) host failed to start (runtime may not load at all)." 'Try -Repair' }
    }
}

# ---------------------------------------------------------------- 11. event log
Write-Section '11. Recent .NET crashes and errors (14 days)'
$since = (Get-Date).AddDays(-14)
function Get-EventField([string]$Text, [string]$Pattern) {
    if ($Text -match $Pattern) { $Matches[1].Trim() } else { $null }
}
function Get-CrashHint([string]$What) {
    switch -Regex ($What) {
        'OutOfMemory|InsufficientMemory|8007000E'                    { 'Memory/handles: see sections 1, 5, 6 and 8'; break }
        'BadImageFormat'                                             { '32/64-bit mismatch or corrupt native image: see sections 8 and 12'; break }
        'DllNotFound|8007007E'                                       { 'A native DLL is missing - often the Visual C++ Redistributable (matching x86/x64) or a vendor component: see section 14'; break }
        'FileNotFound|FileLoad|TypeLoad|MissingMethod|MissingField'  { 'Missing or mismatched assembly/runtime: see section 3; reinstall the app or its runtime'; break }
        'ConfigurationErrors|TypeInitialization'                     { 'Configuration problem: see section 7 and the app''s .config / runtimeconfig.json'; break }
        'profiler'                                                   { 'A CLR profiler failed to load: see section 2'; break }
        'AccessViolation|ExecutionEngine|c0000005|80131506'          { 'Runtime corruption: corrupt native images, a CLR profiler or an injected DLL - see sections 2, 9 and 12'; break }
        default                                                      { 'App-level failure: send the event details to the app vendor' }
    }
}

$crashes = New-Object System.Collections.Generic.List[object]
# .NET Runtime errors: 1026 unhandled exception, 1025 FailFast, 1023 fatal engine error, 1022 profiler load failure.
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = '.NET Runtime'; Level = 1, 2; StartTime = $since } -ErrorAction SilentlyContinue)) {
    $m   = $e.Message
    $app = Get-EventField $m 'Application:\s*(\S+)'
    $net = Get-EventField $m '\.NET Version:\s*(\S+)'
    $fw  = Get-EventField $m 'Framework Version:\s*(\S+)'
    $runtime = if ($net) { ".NET $net" } elseif ($fw) { "Framework $fw" } else { '' }
    $what = Get-EventField $m 'Exception Info:\s*([\w\.]+)'
    if (-not $what) { $what = Get-EventField $m 'Message:\s*(.+)' }
    if (-not $what) { $what = Get-EventField $m 'Description:\s*(.+)' }
    if (-not $what) { $what = ($m -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) }
    $crashes.Add([pscustomobject]@{ Time = $e.TimeCreated; App = $(if ($app) { $app } else { '(runtime)' }); Runtime = $runtime; What = "$what"; Id = $e.Id })
}
# Application Error 1000 where the crash is in the CLR itself or is the managed-exception code.
# Read from event properties (0 = app, 3 = module, 6 = exception code) so it works on any OS language.
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $since } -ErrorAction SilentlyContinue)) {
    if ($e.Properties.Count -lt 7) { continue }
    $app    = "$($e.Properties[0].Value)"
    $module = "$($e.Properties[3].Value)"
    $code   = ("$($e.Properties[6].Value)" -replace '^0x', '').ToLower()
    $inClr  = $module -match '^(clr|coreclr|mscorwks|clrjit)\.dll$'
    if (-not ($inClr -or $code -eq 'e0434352')) { continue }
    # An unhandled exception also logs a .NET Runtime event for the same crash; skip the duplicate.
    $dup = $crashes | Where-Object { $_.App -eq $app -and [math]::Abs(($_.Time - $e.TimeCreated).TotalSeconds) -le 10 }
    if ($dup) { continue }
    $crashes.Add([pscustomobject]@{ Time = $e.TimeCreated; App = $app; Runtime = ''; What = "0x$code in $module"; Id = $e.Id })
}

if ($crashes.Count) {
    $groups = @($crashes | Group-Object App, What | ForEach-Object {
        $latest = $_.Group | Sort-Object Time -Descending | Select-Object -First 1
        [pscustomobject]@{ App = $latest.App; What = $latest.What; Runtime = $latest.Runtime; Count = $_.Count; Last = $latest.Time }
    } | Sort-Object Last -Descending)
    foreach ($g in ($groups | Select-Object -First 10)) {
        $rt = if ($g.Runtime) { " [$($g.Runtime)]" } else { '' }
        $sev = if ($g.Count -ge 3) { 'Problem' } else { 'Warn' }
        Add-Finding $sev 'Crashes' ("{0}{1} crashed {2}x, last {3:g}: {4}" -f $g.App, $rt, $g.Count, $g.Last, $g.What) (Get-CrashHint $g.What)
    }
    if ($groups.Count -gt 10) { Add-Finding Info 'Crashes' "$($groups.Count - 10) more crash group(s) not shown - see Event Viewer > Application (.NET Runtime / Application Error)." }
} else { Add-Finding OK 'Crashes' 'No .NET app crashes logged in 14 days.' }

# Other sources that log out-of-memory errors (not already covered above).
$oomEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -notin '.NET Runtime', 'Application Error' -and $_.Message -match 'OutOfMemoryException|out of memory|0x8007000E|E_OUTOFMEMORY|InsufficientMemoryException' } |
    Select-Object -First 10)
foreach ($e in $oomEvts) {
    $line = ($e.Message -split "`r?`n" | Where-Object { $_ -match 'Exception|memory' } | Select-Object -First 1)
    Add-Finding Warn 'Event log' ("{0:g} {1}: {2}" -f $e.TimeCreated, $e.ProviderName, $line) (Get-CrashHint 'OutOfMemory')
}
if (-not $crashes.Count -and -not $oomEvts.Count) {
    Add-Finding Info 'Event log' 'Nothing logged. If the error is a dialog, note the exact text and whether the app is 32- or 64-bit.'
}

# ---------------------------------------------------------------- 12. NGen native images
Write-Section '12. NGen native images (.NET Framework only)'
$ngens = @(foreach ($fw in @{ Bits = 32; Dir = 'Framework' }, @{ Bits = 64; Dir = 'Framework64' }) {
    $exe = Join-Path $env:WINDIR "Microsoft.NET\$($fw.Dir)\v4.0.30319\ngen.exe"
    if (Test-Path $exe) {
        [pscustomobject]@{ Bits = $fw.Bits; Exe = $exe; Cache = (Join-Path $env:WINDIR "assembly\NativeImages_v4.0.30319_$($fw.Bits)") }
    }
})
function Invoke-NGen($n, [string[]]$NgArgs) {
    $out = & $n.Exe @NgArgs /nologo 2>&1
    [pscustomobject]@{ Exit = $LASTEXITCODE; Output = ($out | Out-String).Trim() }
}
function Get-NativeImageStats($dir) {
    if (-not (Test-Path $dir)) { return $null }
    $files = @(Get-ChildItem $dir -Recurse -File -Force -ErrorAction SilentlyContinue)
    [pscustomobject]@{ Count = $files.Count; MB = [math]::Round((($files | Measure-Object Length -Sum).Sum / 1MB), 0) }
}

if (-not $ngens.Count) { Add-Finding Problem 'NGen' 'ngen.exe not found for .NET Framework 4.x.' 'Run with -Repair' }
foreach ($n in $ngens) {
    $st = Invoke-NGen $n 'queue', 'status'
    if ($st.Output -match 'is running') {
        Add-Finding Info 'NGen' "$($n.Bits)-bit NGen service is running - compiling queued assemblies in the background. Framework apps may start slowly until it finishes."
    } elseif ($st.Output -match 'is stopped') {
        Add-Finding OK 'NGen' "$($n.Bits)-bit NGen service is idle (nothing compiling)."
    } else {
        Add-Finding Info 'NGen' "$($n.Bits)-bit ngen queue status (exit $($st.Exit)): $(($st.Output -split "`r?`n" | Select-Object -Last 1))"
    }

    $stats = Get-NativeImageStats $n.Cache
    if (-not $stats) {
        Add-Finding Problem 'NGen cache' "$($n.Cache) is missing - every Framework app JIT-compiles everything (slow start, more memory)." 'Fix: ngen update (run with -Fix)'
    } elseif ($stats.Count -lt 50) {
        Add-Finding Warn 'NGen cache' "$($n.Bits)-bit native image cache looks nearly empty ($($stats.Count) files, $($stats.MB) MB)." 'Fix: ngen update (run with -Fix)'
    } else {
        Add-Finding OK 'NGen cache' "$($n.Bits)-bit native image cache: $($stats.Count) files, $($stats.MB) MB."
    }
}

$mscorsvw = @(Get-Process mscorsvw -ErrorAction SilentlyContinue)
if ($mscorsvw.Count) {
    Add-Finding Info 'NGen' ("{0} mscorsvw.exe worker(s) compiling now, {1:N0} MB private memory in total." -f $mscorsvw.Count, (($mscorsvw | Measure-Object PrivateMemorySize64 -Sum).Sum / 1MB))
}

$ngenErrors = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = '.NET Runtime Optimization Service'; Level = 1, 2; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 20 -ErrorAction SilentlyContinue)
if ($ngenErrors.Count) {
    $first = ($ngenErrors[0].Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    Add-Finding Warn 'NGen events' ("{0} .NET Runtime Optimization Service error(s) in 30 days; latest {1:g}: {2}" -f $ngenErrors.Count, $ngenErrors[0].TimeCreated, $first) 'Fix: ngen update (run with -Fix); if Framework apps still crash, -ResetNativeImages'
} else { Add-Finding OK 'NGen events' 'No .NET Runtime Optimization Service errors in 30 days.' }

function Invoke-NGenRefresh($n) {
    foreach ($action in 'executeQueuedItems', 'update') {
        $r = Invoke-NGen $n $action, '/silent'
        if ($r.Exit -eq 0) { Add-Finding OK 'NGen' "$($n.Bits)-bit ngen $action completed." }
        else {
            $tail = ($r.Output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 3) -join ' | '
            Add-Finding Warn 'NGen' "$($n.Bits)-bit ngen $action exited $($r.Exit): $tail" 'Some assemblies failed to compile; apps still run (JIT). Check the NGen events above.'
        }
    }
}

if ($Fix -and -not $ResetNativeImages) {
    foreach ($n in $ngens) {
        if ($PSCmdlet.ShouldProcess("$($n.Bits)-bit NGen", 'executeQueuedItems + update')) {
            Write-Host "  Running $($n.Bits)-bit ngen executeQueuedItems + update (can take several minutes)..." -ForegroundColor Gray
            Invoke-NGenRefresh $n
        }
    }
}

if ($ResetNativeImages) {
    Write-Warning 'Resetting the .NET Framework native image cache. Rebuilding can take 10-30+ minutes. Files in use by running .NET Framework apps (including Windows PowerShell itself) cannot be deleted.'
    foreach ($n in $ngens) {
        if (-not (Test-Path $n.Cache)) { continue }
        if ($PSCmdlet.ShouldProcess($n.Cache, 'Delete native image cache contents and rebuild with ngen update')) {
            Initialize-Backup   # restore point; the images themselves are regenerated, not backed up
            foreach ($item in @(Get-ChildItem $n.Cache -Force)) {
                Remove-Item $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
            $left = Get-NativeImageStats $n.Cache
            if ($left -and $left.Count) {
                Add-Finding Warn 'NGen reset' "$($n.Bits)-bit cache: $($left.Count) file(s) were in use and could not be deleted." 'Close .NET Framework apps (or reboot) and re-run -ResetNativeImages, ideally from pwsh'
            } else { Add-Finding OK 'NGen reset' "$($n.Bits)-bit cache cleared." }
            Write-Host "  Rebuilding $($n.Bits)-bit native images (ngen update + executeQueuedItems)..." -ForegroundColor Gray
            Invoke-NGenRefresh $n
            $after = Get-NativeImageStats $n.Cache
            if ($after) { Add-Finding Info 'NGen reset' "$($n.Bits)-bit cache rebuilt: $($after.Count) files, $($after.MB) MB." }
        }
    }
}

# ---------------------------------------------------------------- 13. Windows Update (.NET updates)
Write-Section '13. Windows Update: .NET update failures and pending reboot (90 days)'
$wuSince     = (Get-Date).AddDays(-90)
$dotnetTitle = '\.NET'
$wuHints = @{
    '0x800f0922' = 'Servicing failed (often a full or missing System Reserved/EFI partition, or a pending reboot): reboot, run with -Repair (DISM + SFC), then retry'
    '0x80073712' = 'Component store is damaged: run with -Repair (DISM + SFC), reboot, then retry'
    '0x800f081f' = 'Source files not found (component store damage): run with -Repair, reboot, then retry'
    '0x800f0831' = 'A prerequisite update is missing or the component store is damaged: run with -Repair, then install the latest cumulative update first'
    '0x80070570' = 'Corrupt file or download: run with -Repair, clear the download by retrying, check the disk'
    '0x80070643' = 'MSI installer failed: run the Microsoft .NET Framework Repair Tool, reboot, then retry'
    '0x80070005' = 'Access denied: security software or permissions blocked the install; retry after reboot'
    '0x80240017' = 'Not applicable to this machine (wrong product or architecture) - usually harmless'
}
function Get-WUHint([string]$Code) {
    $h = $wuHints[$Code.ToLower()]
    if ($h) { $h } else { "Look up error $Code; retry after a reboot, then try -Repair" }
}
function Get-KB([string]$Text) { if ($Text -match '(KB\d{6,8})') { $Matches[1].ToUpper() } else { $null } }

# --- update history (local, no internet needed)
$wuHistory = @()
$dotnetKBs = @{}   # KB -> title, used to recognise .NET packages in the Setup log
try {
    $wuSession  = New-Object -ComObject Microsoft.Update.Session
    $wuSearcher = $wuSession.CreateUpdateSearcher()
    $histCount  = $wuSearcher.GetTotalHistoryCount()
    if ($histCount) {
        $wuHistory = @($wuSearcher.QueryHistory(0, [math]::Min($histCount, 1000)) | ForEach-Object {
            if (-not $_.Title -or $_.Operation -ne 1) { return }   # installs only
            [pscustomobject]@{ Date = $_.Date.ToLocalTime(); Title = $_.Title; KB = (Get-KB $_.Title); Result = [int]$_.ResultCode; Code = ('0x{0:x8}' -f $_.HResult) }
        })
    }
} catch { Add-Finding Info 'Updates' "Could not read Windows Update history: $($_.Exception.Message)" }

$dotnetHist = @($wuHistory | Where-Object { $_.Title -match $dotnetTitle })
foreach ($h in $dotnetHist) { if ($h.KB) { $dotnetKBs[$h.KB] = $h.Title } }
$recent = @($dotnetHist | Where-Object { $_.Date -ge $wuSince })
$stillFailing = 0
foreach ($grp in ($recent | Group-Object { if ($_.KB) { $_.KB } else { $_.Title } })) {
    $entries  = @($grp.Group | Sort-Object Date -Descending)
    $failures = @($entries | Where-Object { $_.Result -in 4, 5 })
    if (-not $failures.Count) { continue }
    $latest = $entries[0]
    $lastFail = $failures[0]
    if ($latest.Result -in 4, 5) {
        $stillFailing++
        Add-Finding Problem 'Updates' ("{0} FAILED {1}x, last {2:g} with {3}" -f $latest.Title, $failures.Count, $lastFail.Date, $lastFail.Code) ((Get-WUHint $lastFail.Code) + '. A failed .NET update can leave the runtime half-updated; once it installs, re-run with -Fix to refresh NGen images.')
    } else {
        Add-Finding Info 'Updates' ("{0} failed {1}x (last {2:g}, {3}) but later installed on {4:g}." -f $latest.Title, $failures.Count, $lastFail.Date, $lastFail.Code, $latest.Date)
    }
}
if ($dotnetHist.Count -and -not $stillFailing) {
    $lastOk = $dotnetHist | Where-Object Result -eq 2 | Sort-Object Date -Descending | Select-Object -First 1
    if ($lastOk) { Add-Finding OK 'Updates' ("No .NET updates currently failing. Last .NET update installed {0:g}: {1}" -f $lastOk.Date, $lastOk.Title) }
} elseif (-not $dotnetHist.Count) {
    Add-Finding Info 'Updates' 'No .NET updates in the Windows Update history (the machine may be managed by WSUS/Intune or updated offline).'
}

# --- Setup log: servicing failures, including offline/wusa installs not in the WU history
$setupEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Setup'; Id = 2, 20; StartTime = $wuSince } -ErrorAction SilentlyContinue)
$installedAt = @{}
foreach ($e in ($setupEvts | Where-Object Id -eq 2)) {
    $kb = Get-KB (($e.Properties | ForEach-Object { "$($_.Value)" }) -join ' ')
    if ($kb -and $e.Message -match 'Installed' -and (-not $installedAt[$kb] -or $e.TimeCreated -gt $installedAt[$kb])) { $installedAt[$kb] = $e.TimeCreated }
}
foreach ($e in ($setupEvts | Where-Object Id -eq 20)) {
    $text = (($e.Properties | ForEach-Object { "$($_.Value)" }) -join ' ') + ' ' + $e.Message
    $kb   = Get-KB $text
    $isNet = ($kb -and $dotnetKBs.ContainsKey($kb)) -or ($text -match 'DotNet|NetFx|\.NET')
    if (-not $isNet) { continue }
    if ($kb -and $installedAt[$kb] -and $installedAt[$kb] -gt $e.TimeCreated) { continue }   # later succeeded
    if ($kb -and ($recent | Where-Object { $_.KB -eq $kb })) { continue }                    # already reported from WU history
    $code = if ($text -match '(0x[0-9a-fA-F]{8})') { $Matches[1].ToLower() } else { 'unknown' }
    $name = if ($kb -and $dotnetKBs[$kb]) { $dotnetKBs[$kb] } elseif ($kb) { $kb } else { 'a .NET package' }
    Add-Finding Problem 'Updates' ("Servicing failed for {0} on {1:g} with {2} (Setup log)" -f $name, $e.TimeCreated, $code) (Get-WUHint $code)
}

# --- where .NET 5+ updates come from
try {
    $mu = (New-Object -ComObject Microsoft.Update.ServiceManager).Services | ForEach-Object { $_ } |
        Where-Object { $_.ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d' }
    if ($mu -and $mu.IsRegisteredWithAU) { Add-Finding OK 'Updates' 'Microsoft Update is enabled, so .NET 5+ runtimes are updated through Windows Update.' }
    else { Add-Finding Info 'Updates' '"Receive updates for other Microsoft products" is off: .NET 5+ runtimes are NOT updated by Windows Update.' 'Manual: enable it in Settings > Windows Update > Advanced options, or update runtimes from Microsoft' }
} catch { }

# --- pending reboot
$rebootReasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')  { $rebootReasons += 'component servicing (CBS)' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootReasons += 'Windows Update' }
$pfro = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
if ($rebootReasons.Count) {
    Add-Finding Warn 'Reboot' "A reboot is pending ($($rebootReasons -join ', ')). Updates - possibly .NET - are not finished until you restart, and files can be half-replaced meanwhile." 'Reboot before troubleshooting further'
} elseif ($pfro) {
    Add-Finding Info 'Reboot' "Some files are queued to be replaced at next restart ($(@($pfro).Count / 2) operation(s)); usually from an installer."
} else { Add-Finding OK 'Reboot' 'No reboot pending.' }

# --- optional: applicable .NET updates not yet installed (online search)
if ($CheckAvailableUpdates) {
    Write-Host '  Searching for available updates online (can take a few minutes)...' -ForegroundColor Gray
    try {
        if (-not $wuSearcher) { $wuSearcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher() }
        $result = $wuSearcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $avail = @($result.Updates | ForEach-Object { $_ } | Where-Object { $_.Title -match $dotnetTitle })
        if ($avail.Count) {
            foreach ($u in $avail) {
                $state = if ($u.IsDownloaded) { 'downloaded, waiting to install' } else { 'not downloaded' }
                Add-Finding Warn 'Updates' "Available, not installed: $($u.Title) ($state)" 'Install it from Settings > Windows Update'
            }
        } else { Add-Finding OK 'Updates' 'No applicable .NET updates waiting to be installed.' }
    } catch { Add-Finding Info 'Updates' "Online update search failed: $($_.Exception.Message)" }
} else { Add-Finding Info 'Updates' 'Available-update search skipped (use -CheckAvailableUpdates; contacts Windows Update online).' }

# ---------------------------------------------------------------- 14. Visual C++ Redistributables
Write-Section '14. Visual C++ Redistributables (native dependency of many .NET apps)'
$vcSince = (Get-Date).AddDays(-90)
function Get-Prop($Obj, [string]$Name) { $p = $Obj.PSObject.Properties[$Name]; if ($p) { $p.Value } else { $null } }
function ConvertTo-Ver3($Text) { if ("$Text" -match '(\d+)\.(\d+)\.(\d+)') { '{0}.{1}.{2}' -f $Matches[1], $Matches[2], $Matches[3] } else { $null } }
$guidPattern = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
$orphanHelp  = 'Use Microsoft''s "Program Install and Uninstall" troubleshooter, or back up and delete the stale registry entry'

# --- Programs and Features entries (both registry views)
$uninstRoots = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
$allArpKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$vcArp = @(foreach ($root in $uninstRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($k in Get-ChildItem $root -ErrorAction SilentlyContinue) {
        [void]$allArpKeys.Add($k.PSChildName)
        $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        $dn = "$(Get-Prop $p 'DisplayName')"
        if ($dn -notmatch 'Visual C\+\+.*(Redistributable|Runtime)') { continue }
        $arch = if ($dn -match '\b(x64|amd64)\b') { 'x64' } elseif ($dn -match '\bx86\b') { 'x86' } elseif ($dn -match 'arm64') { 'arm64' } else { '?' }
        $cache = Get-Prop $p 'BundleCachePath'
        [pscustomobject]@{
            Name = $dn; Version = "$(Get-Prop $p 'DisplayVersion')"; Arch = $arch; Key = $k.PSChildName; RegPath = $k.Name
            IsBundle = [bool]($cache -or (Get-Prop $p 'BundleProviderKey')); BundleCache = $cache
            IsMsi = ((Get-Prop $p 'WindowsInstaller') -eq 1); IsSystem = ((Get-Prop $p 'SystemComponent') -eq 1)
        }
    }
})

# --- Windows Installer's own records
$wiOk = $false; $wiProducts = @{}; $wi = $null; $wiType = $null
try {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $wiType = $wi.GetType()
    foreach ($code in $wiType.InvokeMember('Products', 'GetProperty', $null, $wi, $null)) {
        $name = "$($wiType.InvokeMember('ProductInfo', 'GetProperty', $null, $wi, @($code, 'ProductName')))"
        if ($name -notmatch 'Visual C\+\+') { continue }
        $lp = $(try { $wiType.InvokeMember('ProductInfo', 'GetProperty', $null, $wi, @($code, 'LocalPackage')) } catch { $null })
        $wiProducts[$code.ToUpper()] = [pscustomobject]@{ Code = $code; Name = $name; LocalPackage = $lp }
    }
    $wiOk = $true
} catch { Add-Finding Info 'VC++' "Could not query Windows Installer, so orphan checks are partial: $($_.Exception.Message)" }

# --- inventory (top-level entries only; the Minimum/Additional runtime parts are hidden in Programs and Features)
foreach ($a in 'x64', 'x86', 'arm64') {
    $top = @($vcArp | Where-Object { $_.Arch -eq $a -and -not $_.IsSystem } | Sort-Object { [version](ConvertTo-Ver3 $_.Version) })
    if (-not $top.Count) { continue }
    $parts = foreach ($t in $top) {
        $label = if ($t.Name -match '(20\d\d(?:-20\d\d)?)') { $Matches[1] } elseif ($t.Version -like '14.*') { 'v14' } else { '?' }
        "$label ($($t.Version))"
    }
    Add-Finding Info 'VC++' ("{0}: {1}" -f $a, ($parts -join ', '))
}
if (-not $vcArp.Count) { Add-Finding Info 'VC++' 'No Visual C++ Redistributables are installed.' }

$vcProblems = 0
# --- orphan 1: installer entries whose cached installer is gone
foreach ($b in ($vcArp | Where-Object { $_.IsBundle -and $_.BundleCache })) {
    if (-not (Test-Path $b.BundleCache)) {
        $vcProblems++
        Add-Finding Problem 'VC++ orphan' "$($b.Name): its cached installer is missing ($($b.BundleCache)), so it can't be repaired, uninstalled or cleanly upgraded. This is a common reason VC++ upgrades fail." "Run the SAME version's VC_redist installer with /repair to re-cache it. Otherwise: $orphanHelp ($($b.RegPath))"
    }
}
if ($wiOk) {
    # --- orphan 2: Windows Installer products whose cached MSI is gone, or with no Programs and Features entry
    foreach ($wp in $wiProducts.Values) {
        if (-not $wp.LocalPackage -or -not (Test-Path $wp.LocalPackage)) {
            $vcProblems++
            Add-Finding Problem 'VC++ orphan' "$($wp.Name) $($wp.Code): its cached MSI is missing ($(if ($wp.LocalPackage) { $wp.LocalPackage } else { 'not recorded' })). Upgrading or removing it fails with error 1612 or 1714." "Repair it with the exact same version's installer, or use Microsoft's ""Program Install and Uninstall"" troubleshooter to remove it"
        }
        if (-not $allArpKeys.Contains($wp.Code)) {
            $vcProblems++
            Add-Finding Warn 'VC++ orphan' "$($wp.Name) $($wp.Code) is registered with Windows Installer but has no Programs and Features entry, so it can't be removed normally." "msiexec /x $($wp.Code)  (or the Program Install and Uninstall troubleshooter)"
        }
    }
    # --- orphan 3: Programs and Features entries Windows Installer doesn't know about
    foreach ($m in ($vcArp | Where-Object { $_.IsMsi -and $_.Key -match $guidPattern })) {
        if ($wiProducts.ContainsKey($m.Key.ToUpper())) { continue }
        $state = $(try { [int]$wiType.InvokeMember('ProductState', 'GetProperty', $null, $wi, @($m.Key)) } catch { -1 })
        if ($state -ne 5) {
            $vcProblems++
            Add-Finding Problem 'VC++ orphan' "$($m.Name) is listed in Programs and Features but Windows Installer has no record of it (state $state). Installers can skip or fail on this stale entry." "${orphanHelp}: $($m.RegPath)"
        }
    }
}
# --- orphan 4: dependency records that point at installers which no longer exist
$depRoot = 'HKLM:\SOFTWARE\Classes\Installer\Dependencies'
if (Test-Path $depRoot) {
    foreach ($dk in Get-ChildItem $depRoot -ErrorAction SilentlyContinue) {
        $dp = Get-ItemProperty $dk.PSPath -ErrorAction SilentlyContinue
        $ddn = "$(Get-Prop $dp 'DisplayName')"
        if ($dk.PSChildName -notmatch 'VC_Runtime|^VC,redist' -and $ddn -notmatch 'Visual C\+\+') { continue }
        foreach ($dep in @(Get-ChildItem (Join-Path $dk.PSPath 'Dependents') -ErrorAction SilentlyContinue)) {
            $id = $dep.PSChildName
            if ($id -notmatch $guidPattern) { continue }
            if ($allArpKeys.Contains($id) -or $wiProducts.ContainsKey($id.ToUpper())) { continue }
            $vcProblems++
            $label = if ($ddn) { $ddn } else { $dk.PSChildName }
            Add-Finding Warn 'VC++ orphan' "$label is still marked as needed by $id, which is no longer installed. Stale dependency records can block uninstalling or upgrading it." "${orphanHelp}: $($dep.Name)"
        }
    }
}

# --- v14 (2015-2022) consistency per architecture
$sys64 = if ([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem) { Join-Path $env:WINDIR 'System32' } else { Join-Path $env:WINDIR 'Sysnative' }
$sys32 = if ([Environment]::Is64BitOperatingSystem) { Join-Path $env:WINDIR 'SysWOW64' } else { Join-Path $env:WINDIR 'System32' }
$v14Missing = @()
$archList = @('x86'); if ([Environment]::Is64BitOperatingSystem) { $archList = @('x64', 'x86') }
if ($vcArp | Where-Object { $_.Arch -eq 'arm64' }) { $archList += 'arm64' }
foreach ($a in $archList) {
    $bundles = @($vcArp | Where-Object { $_.Arch -eq $a -and $_.IsBundle -and $_.Version -like '14.*' })
    $minimum = @($vcArp | Where-Object { $_.Arch -eq $a -and $_.Name -match 'Minimum Runtime' -and $_.Version -like '14.*' })
    $addl    = @($vcArp | Where-Object { $_.Arch -eq $a -and $_.Name -match 'Additional Runtime' -and $_.Version -like '14.*' })
    $regVer = $null
    foreach ($rk in "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\$a", "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$a") {
        if (-not $regVer) { $regVer = ConvertTo-Ver3 (Get-RegValue $rk 'Version') }
    }
    $dllDir  = switch ($a) { 'x86' { $sys32 } default { $sys64 } }
    $dllPath = Join-Path $dllDir 'vcruntime140.dll'
    $dllVer  = if ($a -ne 'arm64' -and (Test-Path $dllPath)) { ConvertTo-Ver3 (Get-Item $dllPath).VersionInfo.FileVersion } else { $null }

    if (-not ($bundles.Count -or $minimum.Count -or $regVer)) {
        $v14Missing += $a
        Add-Finding Info 'VC++ v14' "$a Visual C++ 2015-2022 (v14) is not installed$(if ($dllVer) { " (but vcruntime140.dll $dllVer is present, probably from another installer)" })."
        continue
    }
    if ($bundles.Count -gt 1) {
        $vcProblems++
        Add-Finding Warn 'VC++ orphan' ("{0} v14 has {1} installer entries ({2}). Only one should exist; the older one is orphaned and can make newer installers fail or report 'another version is installed'." -f $a, $bundles.Count, (($bundles | ForEach-Object { $_.Version }) -join ', ')) "${orphanHelp}: $((($bundles | Sort-Object { [version](ConvertTo-Ver3 $_.Version) } | Select-Object -First 1).RegPath))"
    }
    if ($bundles.Count -and -not $minimum.Count) {
        $vcProblems++
        Add-Finding Problem 'VC++ v14' "$a v14 installer entry exists but its Minimum Runtime package is not installed - the redistributable is broken." "Run the latest VC_redist.$a.exe with /repair"
    }
    if (-not $dllVer -and $a -ne 'arm64') {
        $vcProblems++
        Add-Finding Problem 'VC++ v14' "$a v14 is registered but $dllPath is missing." "Run the latest VC_redist.$a.exe with /repair"
    }
    $verMap = [ordered]@{}
    if ($bundles.Count) { $verMap['installer'] = ConvertTo-Ver3 ($bundles | Sort-Object { [version](ConvertTo-Ver3 $_.Version) } -Descending | Select-Object -First 1).Version }
    if ($minimum.Count) { $verMap['Minimum Runtime'] = ConvertTo-Ver3 $minimum[0].Version }
    if ($addl.Count)    { $verMap['Additional Runtime'] = ConvertTo-Ver3 $addl[0].Version }
    if ($regVer)        { $verMap['registry'] = $regVer }
    if ($dllVer)        { $verMap['vcruntime140.dll'] = $dllVer }
    $distinct = @($verMap.Values | Where-Object { $_ } | Sort-Object -Unique)
    if ($distinct.Count -gt 1) {
        $vcProblems++
        Add-Finding Warn 'VC++ v14' ("{0} v14 versions disagree: {1}. A partial upgrade, rollback, or another installer overwrote files." -f $a, (($verMap.GetEnumerator() | ForEach-Object { "$($_.Key) $($_.Value)" }) -join ', ')) "Run the latest VC_redist.$a.exe with /repair"
    } else {
        $note = if (-not $bundles.Count) { ' (no installer entry: it was installed by another product, which is fine)' } else { '' }
        Add-Finding OK 'VC++ v14' "$a v14 $($distinct[0]): installer, runtime packages, registry and DLLs agree$note."
    }
}
if ($v14Missing -contains 'x86') {
    $x86Net = @($netProcs | Where-Object { $_.Bits -eq 32 })
    if ($x86Net.Count) {
        Add-Finding Warn 'VC++ v14' "32-bit .NET apps are running ($(($x86Net | ForEach-Object Name | Sort-Object -Unique) -join ', ')) but the x86 v14 redistributable is not installed. 32-bit apps need the x86 package even on 64-bit Windows." 'Install VC_redist.x86.exe if one of them reports missing DLLs'
    }
}

# --- an install already in progress blocks every other MSI (error 1618)
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress') {
    Add-Finding Warn 'VC++ install' 'A Windows Installer operation is in progress (or was interrupted). Other installs, including VC++, fail with 1618 until it finishes.' 'Wait for it, or reboot'
}

# --- recent install failures
$installerHints = @{
    1601 = 'Windows Installer service unavailable: reboot and retry'
    1602 = 'Cancelled by the user'
    1603 = 'Fatal error: often a pending reboot, an orphaned registration (see above) or security software - check the log'
    1612 = 'Installer source unavailable: the cached installer is missing (orphaned registration) - repair with the exact same version'
    1618 = 'Another install was in progress: retry when it finishes, or after a reboot'
    1625 = 'Blocked by policy (Group Policy / software restriction)'
    1638 = 'Another version is already installed: installing an older v14 over a newer one always fails; if a NEWER installer fails with this, look for orphaned entries above'
    1714 = 'The old version could not be removed, usually because its cached MSI is missing (orphan) - see above'
}
function Get-InstallerCode($Code) {
    if ("$Code" -match '^0x8007([0-9a-fA-F]{4})$') { [Convert]::ToInt32($Matches[1], 16) }
    elseif ("$Code" -match '^0x0+$') { 0 }
    elseif ("$Code" -match '^\d+$') { [int]$Code }
    else { -1 }
}
function Get-InstallerHint($Code) {
    $n = Get-InstallerCode $Code
    if ($installerHints.ContainsKey($n)) { $installerHints[$n] } else { "Error $Code - check the installer log" }
}
$successCodes = 0, 3010, 1641

# Burn logs from VC_redist.*.exe (%TEMP% of whoever ran it; Windows\Temp for SYSTEM/Windows Update)
$logDirs = @($env:TEMP, (Join-Path $env:WINDIR 'Temp'))
if ($isAdmin) { $logDirs += @(Get-ChildItem (Join-Path $env:SystemDrive 'Users\*\AppData\Local\Temp') -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName) }
$vcLogs = @(foreach ($d in $logDirs) { Get-ChildItem $d -Filter 'dd_vcredist*.log' -File -ErrorAction SilentlyContinue }) |
    Sort-Object FullName -Unique | Where-Object { $_.LastWriteTime -ge $vcSince } | Sort-Object LastWriteTime
$logRuns = @(foreach ($lf in $vcLogs) {
    $exit = (Select-String -Path $lf.FullName -Pattern 'Exit code: (0x[0-9a-fA-F]+)' -ErrorAction SilentlyContinue | Select-Object -Last 1)
    if (-not $exit) { continue }
    $code = $exit.Matches[0].Groups[1].Value.ToLower()
    $verLine  = Select-String -Path $lf.FullName -Pattern "WixBundleFileVersion' to value '([^']+)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    $planLine = Select-String -Path $lf.FullName -Pattern 'Plan begin, \d+ packages, action: (\w+)' -ErrorAction SilentlyContinue | Select-Object -First 1
    $larch = if ($lf.Name -match 'dd_vcredist_(amd64|x86|arm64)') { $Matches[1] -replace 'amd64', 'x64' } else { '?' }
    $label = "VC_redist.$larch"
    if ($verLine)  { $label += " $(ConvertTo-Ver3 $verLine.Matches[0].Groups[1].Value)" }
    if ($planLine) { $label += " ($($planLine.Matches[0].Groups[1].Value.ToLower()))" }
    [pscustomobject]@{ Time = $lf.LastWriteTime; Arch = $larch; Code = $code; Num = (Get-InstallerCode $code); Log = $lf.FullName; Name = $label }
})
foreach ($run in ($logRuns | Where-Object { $_.Num -notin $successCodes } | Sort-Object Time -Descending | Select-Object -First 5)) {
    $laterOk = $logRuns | Where-Object { $_.Arch -eq $run.Arch -and $_.Time -gt $run.Time -and $_.Num -in $successCodes }
    if ($laterOk) {
        Add-Finding Info 'VC++ install' ("{0} failed on {1:g} ({2}) but a later install succeeded." -f $run.Name, $run.Time, $run.Code)
    } else {
        $sev = if ($run.Num -eq 1638) { 'Warn' } else { 'Problem' }
        Add-Finding $sev 'VC++ install' ("{0} failed on {1:g} with {2}. Log: {3}" -f $run.Name, $run.Time, $run.Code, $run.Log) (Get-InstallerHint $run.Code)
    }
}

# Windows Installer events (1033 install, 1034 removal): properties 0 = product, 3 = status
$msiEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 1033, 1034; StartTime = $vcSince } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties.Count -ge 4 -and "$($_.Properties[0].Value)" -match 'Visual C\+\+' })
$msiFails = @($msiEvts | Where-Object { (Get-InstallerCode "$($_.Properties[3].Value)") -notin $successCodes })
foreach ($grp in ($msiFails | Group-Object { "$($_.Properties[0].Value)|$($_.Properties[3].Value)" } | Select-Object -First 5)) {
    $latest = $grp.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $pname = "$($latest.Properties[0].Value)"; $status = "$($latest.Properties[3].Value)"
    $op = if ($latest.Id -eq 1034) { 'removal' } else { 'install' }
    $laterOk = $msiEvts | Where-Object { "$($_.Properties[0].Value)" -eq $pname -and $_.Id -eq $latest.Id -and $_.TimeCreated -gt $latest.TimeCreated -and (Get-InstallerCode "$($_.Properties[3].Value)") -in $successCodes }
    if ($laterOk) { Add-Finding Info 'VC++ install' ("{0} {1} failed with {2} on {3:g} but later succeeded." -f $pname, $op, $status, $latest.TimeCreated) }
    else { Add-Finding Problem 'VC++ install' ("{0} {1} failed {2}x with {3}, last {4:g}." -f $pname, $op, $grp.Count, $status, $latest.TimeCreated) (Get-InstallerHint $status) }
}
if (-not ($logRuns | Where-Object { $_.Num -notin $successCodes }) -and -not $msiFails.Count) {
    $lastRun = $logRuns | Sort-Object Time -Descending | Select-Object -First 1
    $lastTxt = if ($lastRun) { " Last VC_redist run: {0:g}, {1}." -f $lastRun.Time, $lastRun.Name } else { '' }
    Add-Finding OK 'VC++ install' "No failed Visual C++ installs in 90 days.$lastTxt"
}

# --- crashes inside the C++ runtime DLLs (any app)
$vcModRegex = '^(vcruntime\d+(_1)?|msvcp\d+(_\w+)?|msvcr\d+|ucrtbase|concrt\d+|vcomp\d+)\.dll$'
$vcCrashes = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = (Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties.Count -ge 7 -and "$($_.Properties[3].Value)" -match $vcModRegex } |
    ForEach-Object { [pscustomobject]@{ App = "$($_.Properties[0].Value)"; Module = "$($_.Properties[3].Value)"; Code = "$($_.Properties[6].Value)"; Time = $_.TimeCreated } })
foreach ($g in ($vcCrashes | Group-Object App, Module | Select-Object -First 8)) {
    $latest = $g.Group | Sort-Object Time -Descending | Select-Object -First 1
    $hint = if ($latest.Module -match '^ucrtbase') {
        'ucrtbase.dll is part of Windows: run -Repair (SFC) if many apps crash here; a single app crashing here is usually its own bug (code c0000409 = the app aborted)'
    } else { 'Repair the matching Visual C++ redistributable (x86 for 32-bit apps); if it keeps crashing, report it to the app vendor' }
    Add-Finding Warn 'VC++ crash' ("{0} crashed {1}x in {2} (last {3:g}, code 0x{4})" -f $latest.App, $g.Count, $latest.Module, $latest.Time, $latest.Code) $hint
}

if (-not $vcProblems -and $wiOk) { Add-Finding OK 'VC++ orphan' 'No orphaned or broken Visual C++ registrations found.' }

# ---------------------------------------------------------------- 15. application control
Write-Section '15. Application control: WDAC, Smart App Control, AppLocker, Defender (30 days)'
$acSince = (Get-Date).AddDays(-30)
function Get-EventData($Evt) {
    # Event fields by name (stable across OS languages, unlike the message text)
    $h = @{}
    try { foreach ($d in @(([xml]$Evt.ToXml()).Event.EventData.Data)) { $h[$d.GetAttribute('Name')] = $d.InnerText } } catch { }
    $h
}
function Get-First($Table, [string[]]$Keys) {
    foreach ($k in $Keys) { if ($Table.ContainsKey($k) -and $Table[$k]) { return $Table[$k] } }
    ''
}
# \Device\HarddiskVolume3\... -> C:\...
$script:DeviceMap = @{}
try {
    foreach ($drv in [IO.DriveInfo]::GetDrives()) {
        $letter = $drv.Name.Substring(0, 2)
        $sb = New-Object Text.StringBuilder 1024
        if ([DntNative]::QueryDosDevice($letter, $sb, 1024)) { $script:DeviceMap[$sb.ToString()] = $letter }
    }
} catch { }
function ConvertFrom-DevicePath([string]$Path) {
    foreach ($k in $script:DeviceMap.Keys) {
        if ($Path.StartsWith("$k\", [StringComparison]::OrdinalIgnoreCase)) { return $script:DeviceMap[$k] + $Path.Substring($k.Length) }
    }
    $Path
}
# Does a block involve .NET? Running .NET apps (section 8), runtime folders, native images, runtime DLLs.
$netAppPaths = @{}
foreach ($np in $netProcs) { if ($np.Path) { $netAppPaths[$np.Path.ToLower()] = $np.Name } }
$netFileRegex = '\\(Microsoft\.NET|dotnet|assembly\\NativeImages_[^\\]+)\\|\.ni\.(dll|exe)$|\\(clr|coreclr|clrjit|mscoree|mscoreei|hostfxr|hostpolicy|System\.Private\.CoreLib)\.dll$'
function Test-NetRelated([string]$Proc, [string]$File) {
    $netAppPaths.ContainsKey("$Proc".ToLower()) -or "$File" -match $netFileRegex -or "$Proc" -match $netFileRegex
}
$acReported = 0

# --- Smart App Control
$sac = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
switch ("$sac") {
    '1' { Add-Finding Info 'App control' 'Smart App Control is ON: it blocks unsigned or unknown apps and DLLs, including unsigned .NET apps and assemblies. Blocks show below as Code Integrity events.' }
    '2' { Add-Finding Info 'App control' 'Smart App Control is in evaluation mode (Windows may switch it on, after which unsigned apps and DLLs get blocked).' }
    default { Add-Finding Info 'App control' 'Smart App Control is off.' }
}

# --- WDAC policies (CiTool needs admin; Windows 11 22H2+)
$ciTool = Join-Path $env:WINDIR 'System32\CiTool.exe'
if ($isAdmin -and (Test-Path $ciTool)) {
    try {
        $ciJson = (& $ciTool -lp -json 2>$null | Out-String) | ConvertFrom-Json
        $pols = @(Get-Prop $ciJson 'Policies')
        $custom = @($pols | Where-Object { $_ -and (Get-Prop $_ 'IsEnforced') -and -not (Get-Prop $_ 'IsSystemPolicy') })
        if ($custom.Count) {
            $names = ($custom | ForEach-Object { $n = Get-Prop $_ 'FriendlyName'; if ($n) { $n } else { Get-Prop $_ 'PolicyID' } }) -join '; '
            Add-Finding Info 'App control' "$($custom.Count) non-Windows WDAC policy(ies) enforced: $names. They can block .NET apps and their DLLs."
        } else { Add-Finding OK 'App control' 'No WDAC policies enforced besides the ones built into Windows.' }
    } catch { }
}

# --- Code Integrity blocks. 3077/3076 = WDAC/SAC policy (enforced/audit); 3033/3034 = signing level not met.
$ciEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3033, 3034, 3076, 3077; StartTime = $acSince } -MaxEvents 5000 -ErrorAction SilentlyContinue)
$ciRows = @(foreach ($e in $ciEvts) {
    $d = Get-EventData $e
    $file = ConvertFrom-DevicePath (Get-First $d 'FileNameBuffer', 'File Name')
    $proc = ConvertFrom-DevicePath (Get-First $d 'ProcessNameBuffer', 'Process Name')
    $net  = Test-NetRelated $proc $file
    # 3033 is mostly noise (third-party DLLs refused by protected Windows processes): keep only .NET-related ones.
    if ($e.Id -in 3033, 3034 -and -not $net) { continue }
    [pscustomobject]@{ Id = $e.Id; Time = $e.TimeCreated; File = $file; Proc = $proc; Net = $net
                       Policy = (Get-First $d 'PolicyNameBuffer', 'PolicyName', 'Policy Name') }
})
$ciBlocks = @($ciRows | Where-Object { $_.Id -in 3077, 3033 })
foreach ($g in ($ciBlocks | Group-Object File, Proc | Sort-Object { -[int]$_.Group[0].Net }, { -$_.Count } | Select-Object -First 8)) {
    $l = $g.Group | Sort-Object Time -Descending | Select-Object -First 1
    $procName = Split-Path $l.Proc -Leaf
    if ($l.Id -eq 3077) {
        $why = if ($l.Policy) { "policy '$($l.Policy)'" } else { 'a Code Integrity policy' }
        $sev = if ($l.Net) { 'Problem' } else { 'Warn' }
        Add-Finding $sev 'App control' ("{0} was blocked from loading into {1} by {2}, {3}x, last {4:g}." -f $l.File, $procName, $why, $g.Count, $l.Time) 'Smart App Control or a WDAC policy blocked it: get a signed build from the vendor, or ask whoever manages the policy to allow it (Smart App Control can only be turned off, not given exceptions)'
    } else {
        Add-Finding Warn 'App control' ("{0} could not load into {1}: it doesn't meet the signing level that process requires ({2}x, last {3:g})." -f $l.File, $procName, $g.Count, $l.Time) 'Usually harmless; matters only if it is the failing app or one of its DLLs (repair or reinstall the app)'
    }
    $acReported++
}
$ciAudit = @($ciRows | Where-Object { $_.Id -in 3076, 3034 })
if ($ciAudit.Count) {
    $files = ($ciAudit | ForEach-Object { Split-Path $_.File -Leaf } | Sort-Object -Unique | Select-Object -First 5) -join ', '
    Add-Finding Info 'App control' "$($ciAudit.Count) .NET-related audit-mode Code Integrity event(s) (would be blocked if the policy were enforced): $files"
}

# --- AppLocker
$alEnforced = @()
try {
    $alXml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
    $alEnforced = @($alXml.SelectNodes('//RuleCollection') | Where-Object { $_.HasChildNodes -and $_.GetAttribute('EnforcementMode') -ne 'AuditOnly' } | ForEach-Object { $_.GetAttribute('Type') })
} catch { }
if ($alEnforced.Count) {
    $svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
    $svcTxt = if ($svc) { "Application Identity service: $($svc.Status)" } else { 'Application Identity service not found' }
    $dllTxt = if ($alEnforced -contains 'Dll') { ' DLL rules also apply to .NET assemblies loaded from disk.' } else { '' }
    Add-Finding Info 'App control' "AppLocker rules are enforced for: $($alEnforced -join ', ') ($svcTxt).$dllTxt"
}
$alEvts = @(foreach ($log in 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script') {
    Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 8004, 8007; StartTime = $acSince } -MaxEvents 2000 -ErrorAction SilentlyContinue
})
$alRows = @(foreach ($e in $alEvts) {
    $d = Get-EventData $e
    $file = Get-First $d 'FullFilePath', 'FilePath'
    [pscustomobject]@{ Time = $e.TimeCreated; File = $file; Rule = (Get-First $d 'RuleName', 'RuleNameBuffer'); Net = (Test-NetRelated '' $file) -or $netAppPaths.ContainsKey($file.ToLower()) }
})
foreach ($g in ($alRows | Group-Object File | Sort-Object Count -Descending | Select-Object -First 5)) {
    $l = $g.Group | Sort-Object Time -Descending | Select-Object -First 1
    $sev = if ($l.Net) { 'Problem' } else { 'Warn' }
    Add-Finding $sev 'App control' ("AppLocker blocked {0} {1}x, last {2:g}." -f $l.File, $g.Count, $l.Time) 'Ask whoever manages AppLocker to allow it (AppLocker event log: Applications and Services Logs > Microsoft > Windows > AppLocker)'
    $acReported++
}

# --- Defender: Attack Surface Reduction rules and quarantined files
$asrNames = @{
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless they meet a prevalence, age, or trusted list criterion'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
}
function Get-AsrName([string]$Id) { $k = $Id.Trim('{}').ToLower(); if ($asrNames.ContainsKey($k)) { $asrNames[$k] } else { "ASR rule $Id" } }
try {
    $mp = Get-MpPreference -ErrorAction Stop
    $asrIds  = @($mp.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
    $asrActs = @($mp.AttackSurfaceReductionRules_Actions)
    $asrOn = @(for ($i = 0; $i -lt $asrIds.Count; $i++) {
        $act = if ($i -lt $asrActs.Count) { [int]$asrActs[$i] } else { 0 }
        if ($act -in 1, 6) { [pscustomobject]@{ Id = "$($asrIds[$i])".ToLower(); Mode = $(if ($act -eq 1) { 'block' } else { 'warn' }) } }
    })
    if ($asrOn.Count) {
        Add-Finding Info 'App control' "$($asrOn.Count) Defender Attack Surface Reduction rule(s) active in block/warn mode."
        if ($asrOn | Where-Object Id -eq '01443614-cd74-433a-b99e-2ecdc07bfc25') {
            Add-Finding Warn 'App control' "ASR rule '$(Get-AsrName '01443614-cd74-433a-b99e-2ecdc07bfc25')' is on. It blocks new or rarely seen executables, which often catches in-house or freshly updated .NET apps." 'If an app is blocked (Defender event 1121 below), ask whoever manages Defender to add an exclusion'
        }
    }
} catch { }
$defLog = 'Microsoft-Windows-Windows Defender/Operational'
$asrEvts = @(Get-WinEvent -FilterHashtable @{ LogName = $defLog; Id = 1121; StartTime = $acSince } -MaxEvents 2000 -ErrorAction SilentlyContinue)
$asrRows = @(foreach ($e in $asrEvts) {
    $d = Get-EventData $e
    [pscustomobject]@{ Time = $e.TimeCreated; Rule = (Get-First $d 'ID'); Path = (Get-First $d 'Path'); Proc = (Get-First $d 'Process Name') }
})
foreach ($g in ($asrRows | Group-Object Rule, Path | Sort-Object Count -Descending | Select-Object -First 5)) {
    $l = $g.Group | Sort-Object Time -Descending | Select-Object -First 1
    $sev = if (Test-NetRelated $l.Proc $l.Path) { 'Problem' } else { 'Warn' }
    Add-Finding $sev 'App control' ("Defender ASR blocked {0} (process {1}) {2}x, last {3:g}: {4}." -f $l.Path, (Split-Path $l.Proc -Leaf), $g.Count, $l.Time, (Get-AsrName $l.Rule)) 'Ask whoever manages Defender to add an ASR exclusion for this file'
    $acReported++
}
# Malware detections (1116) on exe/dll files: a quarantined app file looks like FileNotFound or a crash on start.
$avEvts = @(Get-WinEvent -FilterHashtable @{ LogName = $defLog; Id = 1116; StartTime = $acSince } -MaxEvents 500 -ErrorAction SilentlyContinue)
$avRows = @(foreach ($e in $avEvts) {
    $d = Get-EventData $e
    $path = (Get-First $d 'Path') -replace '^\w+:_', ''
    if ($path -notmatch '\.(exe|dll)\b') { continue }
    [pscustomobject]@{ Time = $e.TimeCreated; Threat = (Get-First $d 'Threat Name'); Path = $path }
})
foreach ($g in ($avRows | Group-Object Path | Select-Object -First 5)) {
    $l = $g.Group | Sort-Object Time -Descending | Select-Object -First 1
    Add-Finding Warn 'App control' ("Defender detected {0} in {1} ({2:g}). If it was quarantined, the app that uses it fails to load it." -f $l.Threat, $l.Path, $l.Time) 'Check Windows Security > Protection history. Restore only if you are sure it is a false positive'
    $acReported++
}
if (-not $acReported) { Add-Finding OK 'App control' 'No Code Integrity, AppLocker or Defender blocks affecting .NET apps in 30 days.' }

# ---------------------------------------------------------------- 16. TLS and cryptography
Write-Section '16. TLS and cryptography (.NET Framework HTTPS connections)'
$netfx35 = "$(Get-RegValue 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' 'Install')" -eq '1'
$tlsKeys = @(
    @{ Ps = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319';             Native = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' }
    @{ Ps = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; Native = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' }
)
if ($netfx35) {
    $tlsKeys += @{ Ps = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727';             Native = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' }
    $tlsKeys += @{ Ps = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'; Native = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' }
}
if (-not [Environment]::Is64BitOperatingSystem) { $tlsKeys = @($tlsKeys | Where-Object { $_.Ps -notmatch 'WOW6432Node' }) }
$tlsMissing = @(); $tlsZero = @()
foreach ($tk in $tlsKeys) {
    foreach ($vn in 'SchUseStrongCrypto', 'SystemDefaultTlsVersions') {
        $val = Get-RegValue $tk.Ps $vn
        if ($null -eq $val) { $tlsMissing += $tk.Native } elseif ("$val" -eq '0') { $tlsZero += "$($tk.Native)\$vn" }
    }
}
$tlsMissing = @($tlsMissing | Select-Object -Unique)
if ($tlsZero.Count) {
    Add-Finding Warn 'TLS' "Set to 0: $($tlsZero -join ', '). This forces .NET Framework apps onto old TLS versions that most servers now refuse." 'Fix: set SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1'
}
if ($tlsMissing.Count) {
    Add-Finding Info 'TLS' ("SchUseStrongCrypto / SystemDefaultTlsVersions not set under {0}. Apps built for .NET Framework 4.6.2 or older{1} may then try only TLS 1.0 and fail to connect to servers that require TLS 1.2+." -f (($tlsMissing | ForEach-Object { $_ -replace '^HKLM\\SOFTWARE\\', '' }) -join ', '), $(if ($netfx35) { ' (and 3.5 apps)' } else { '' })) 'Fix: set SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1 (Microsoft''s recommended setting; restart the apps afterwards)'
}
if (-not $tlsZero.Count -and -not $tlsMissing.Count) { Add-Finding OK 'TLS' '.NET Framework uses the OS TLS defaults and strong crypto (SchUseStrongCrypto / SystemDefaultTlsVersions = 1).' }
if ($Fix -and ($tlsZero.Count -or $tlsMissing.Count)) {
    foreach ($tk in $tlsKeys) {
        if ($PSCmdlet.ShouldProcess($tk.Native, 'Set SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1')) {
            if (Test-Path $tk.Ps) { Backup-RegKey $tk.Native } else { Initialize-Backup; New-Item -Path $tk.Ps -Force | Out-Null }
            Set-ItemProperty -Path $tk.Ps -Name SchUseStrongCrypto -Value 1 -Type DWord
            Set-ItemProperty -Path $tk.Ps -Name SystemDefaultTlsVersions -Value 1 -Type DWord
        }
    }
    if (-not $WhatIfPreference) { Add-Finding OK 'TLS' 'Set SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1. Restart .NET Framework apps to pick it up.' }
}

# SCHANNEL protocol switches (client side is what apps use)
$schRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$schOff = @()
foreach ($proto in 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3') {
    $ck = "$schRoot\$proto\Client"
    $en = Get-RegValue $ck 'Enabled'; $dbd = Get-RegValue $ck 'DisabledByDefault'
    if ("$en" -eq '0' -or "$dbd" -eq '1') {
        $state = if ("$en" -eq '0') { 'disabled' } else { 'off by default' }
        if ($proto -eq 'TLS 1.2') {
            Add-Finding Problem 'TLS' "TLS 1.2 is $state for clients ($ck). Nearly every HTTPS connection from .NET apps will fail." 'Manual: set Enabled=1 and DisabledByDefault=0 (check whether a group policy or hardening tool set it)'
        } else { $schOff += "$proto $state" }
    }
}
if ($schOff.Count) { Add-Finding Info 'TLS' "Client protocols turned off in SCHANNEL: $($schOff -join ', '). Apps that hard-code those versions can't connect; apps using OS defaults are fine." }
$fips = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' 'Enabled'
if ("$fips" -eq '1') {
    Add-Finding Warn 'Crypto' 'FIPS mode is on. .NET Framework apps that use MD5, RijndaelManaged or other non-FIPS classes throw InvalidOperationException ("not part of the Windows Platform FIPS validated algorithms").' 'Manual: usually set by group policy for compliance; ask IT, or the vendor for a FIPS-compliant build'
} else { Add-Finding OK 'Crypto' 'FIPS mode is off.' }
$schEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Schannel'; Id = 36870, 36871; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 500 -ErrorAction SilentlyContinue)
if ($schEvts.Count) {
    Add-Finding Warn 'TLS' ("{0} Schannel credential error(s) (36870/36871) in 7 days, last {1:g}: Windows could not set up TLS for an app." -f $schEvts.Count, $schEvts[0].TimeCreated) 'Usually disabled protocols/cipher suites (see above) or broken permissions on C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys'
}

# ---------------------------------------------------------------- 17. .NET 5+ host resolution
Write-Section '17. .NET 5+ host resolution ("You must install .NET" errors)'
$hostReported = 0
$reg32 = $null
try { $reg32 = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry32') } catch { }
foreach ($rr in $runtimeRoots) {
    $root  = Split-Path $rr.Dir -Parent   # ...\dotnet
    $rtVers = @(if (Test-Path (Join-Path $rr.Dir 'Microsoft.NETCore.App')) {
        Get-ChildItem (Join-Path $rr.Dir 'Microsoft.NETCore.App') -Directory | ForEach-Object { $v = $null; if ([version]::TryParse(($_.Name -split '-')[0], [ref]$v)) { $v } }
    })
    $fxrVers = @(if (Test-Path (Join-Path $root 'host\fxr')) {
        Get-ChildItem (Join-Path $root 'host\fxr') -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'hostfxr.dll') } |
            ForEach-Object { $v = $null; if ([version]::TryParse(($_.Name -split '-')[0], [ref]$v)) { $v } }
    })
    # Where apphost looks first: HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\<arch>\InstallLocation (32-bit registry view)
    $regLoc = $null
    if ($reg32) { $rk = $reg32.OpenSubKey("SOFTWARE\dotnet\Setup\InstalledVersions\$($rr.Arch)"); if ($rk) { $regLoc = $rk.GetValue('InstallLocation'); $rk.Close() } }
    if ($regLoc) {
        $regTrim = $regLoc.TrimEnd('\')
        if (-not (Test-Path (Join-Path $regTrim 'host\fxr'))) {
            Add-Finding Problem '.NET host' "$($rr.Arch) .NET is registered at $regLoc, but there's no .NET there. Framework-dependent $($rr.Arch) apps will say .NET is not installed." "Reinstall the latest $($rr.Arch) .NET runtime, or fix HKLM\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\$($rr.Arch)\InstallLocation"
            $hostReported++
        } elseif ($regTrim -ne $root.TrimEnd('\')) {
            Add-Finding Warn '.NET host' "$($rr.Arch) apps load .NET from $regLoc (registered location), not $root." 'Expected only for a custom install location; otherwise reinstall the runtime'
            $hostReported++
        }
        if ($rr.Arch -eq 'x64' -and $regTrim -match '\(x86\)') {
            Add-Finding Problem '.NET host' "The x64 .NET install location points at the 32-bit folder ($regLoc). 64-bit apps can't start." 'Reinstall the latest x64 .NET runtime'
            $hostReported++
        }
    }
    if (-not $rtVers.Count) { continue }
    $newestRt = $rtVers | Sort-Object -Descending | Select-Object -First 1
    if (-not $fxrVers.Count) {
        Add-Finding Problem '.NET host' "$($rr.Arch): .NET runtimes are installed in $($rr.Dir) but hostfxr.dll is missing from $root\host\fxr. Every framework-dependent $($rr.Arch) .NET app fails with 'You must install .NET'." "Repair or reinstall the .NET $($newestRt.Major).$($newestRt.Minor) $($rr.Arch) runtime"
        $hostReported++
    } else {
        $newestFxr = $fxrVers | Sort-Object -Descending | Select-Object -First 1
        if (($newestFxr.Major * 1000 + $newestFxr.Minor) -lt ($newestRt.Major * 1000 + $newestRt.Minor)) {
            Add-Finding Warn '.NET host' "$($rr.Arch): newest host (hostfxr $newestFxr) is older than the newest runtime ($newestRt). Looks like a partial install; .NET $($newestRt.Major) apps may fail to start." "Repair or reinstall the .NET $($newestRt.Major).$($newestRt.Minor) $($rr.Arch) runtime"
            $hostReported++
        }
    }
}

# dotnet.exe on PATH: the first one wins for "dotnet app.dll" and the dotnet CLI
$pathDirs = @(foreach ($scope in 'Machine', 'User') { "$([Environment]::GetEnvironmentVariable('PATH', $scope))" -split ';' | Where-Object { $_ } })
$firstDotnet = $pathDirs | Where-Object { Test-Path (Join-Path ([Environment]::ExpandEnvironmentVariables($_)) 'dotnet.exe') } | Select-Object -First 1
if ($firstDotnet -and [Environment]::Is64BitOperatingSystem -and $pf86 -and ([Environment]::ExpandEnvironmentVariables($firstDotnet)).StartsWith($pf86, [StringComparison]::OrdinalIgnoreCase)) {
    Add-Finding Warn '.NET host' "The 32-bit dotnet.exe ($firstDotnet) comes first on PATH. 'dotnet' commands and 'dotnet app.dll' run 32-bit and won't see the x64 runtimes." 'Manual: move the x64 dotnet folder before the (x86) one in the system PATH'
    $hostReported++
}

# DOTNET_ROOT variables override where apps look for .NET
foreach ($vn in 'DOTNET_ROOT', 'DOTNET_ROOT(x86)', 'DOTNET_ROOT_X64', 'DOTNET_ROOT_X86', 'DOTNET_ROOT_ARM64') {
    foreach ($scope in 'Machine', 'User') {
        $val = [Environment]::GetEnvironmentVariable($vn, $scope)
        if (-not $val) { continue }
        $hostReported++
        if (-not (Test-Path (Join-Path $val 'host\fxr'))) {
            Add-Finding Problem '.NET host' "$vn ($scope) = $val, but there's no .NET in that folder. Apps that honor it will say .NET is not installed." "Manual: remove $vn or point it at a .NET install folder"
        } elseif ($vn -in 'DOTNET_ROOT', 'DOTNET_ROOT_X64' -and $pf86 -and $val.StartsWith($pf86, [StringComparison]::OrdinalIgnoreCase)) {
            Add-Finding Warn '.NET host' "$vn ($scope) = $val points at the 32-bit .NET folder; 64-bit apps will look there for their runtime." "Manual: use DOTNET_ROOT(x86) for the 32-bit folder, or remove $vn"
        } else {
            Add-Finding Info '.NET host' "$vn ($scope) = $val. Framework-dependent apps load .NET from there instead of Program Files."
        }
    }
}
foreach ($vn in 'DOTNET_ROLL_FORWARD', 'DOTNET_ROLL_FORWARD_TO_PRERELEASE', 'DOTNET_MULTILEVEL_LOOKUP') {
    foreach ($scope in 'Machine', 'User') {
        $val = [Environment]::GetEnvironmentVariable($vn, $scope)
        if ($val) { Add-Finding Info '.NET host' "$vn ($scope) = $val changes which runtime version apps pick."; $hostReported++ }
    }
}

# Apps that failed to start because their framework wasn't found (logged by the app host)
$hostEvts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = '.NET Runtime'; Level = 1, 2; StartTime = (Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'You must install|framework .*(was not|not) found|hostfxr|install or update \.NET' })
$hostRows = @(foreach ($e in $hostEvts) {
    $m = $e.Message
    $app = Get-EventField $m 'Application:\s*(\S+)'
    if (-not $app) { $app = Get-EventField $m 'App:\s*(.+)' }
    $fw = if ($m -match "Framework:\s*'([^']+)',\s*(?:\(minimum\)\s*)?version\s*'([^']+)'\s*\((\w+)\)") { "$($Matches[1]) $($Matches[2]) ($($Matches[3]))" } else { '' }
    [pscustomobject]@{ Time = $e.TimeCreated; App = $(if ($app) { $app } else { '(unknown app)' }); Fw = $fw }
})
foreach ($g in ($hostRows | Group-Object App, Fw | Select-Object -First 5)) {
    $l = $g.Group | Sort-Object Time -Descending | Select-Object -First 1
    $need = if ($l.Fw) { " It needs $($l.Fw)." } else { '' }
    Add-Finding Problem '.NET host' ("{0} failed to start {1}x because .NET wasn't found (last {2:g}).{3}" -f $l.App, $g.Count, $l.Time, $need) 'Install that runtime (same major version and x64/x86; WinForms/WPF apps need the Windows Desktop Runtime), then check the findings above'
    $hostReported++
}
if (-not $hostReported) { Add-Finding OK '.NET host' 'App host can find the installed .NET runtimes; no ".NET not found" start failures in 30 days.' }

# ---------------------------------------------------------------- 18. component store / .NET 3.5
Write-Section '18. Windows component store and .NET Framework 3.5'
# NetFx3 optional feature: 1 = enabled, 2 = disabled, 3 = absent (payload removed)
$fx3 = Get-CimInstance Win32_OptionalFeature -Filter "Name='NetFx3'" -ErrorAction SilentlyContinue
$fx3State = if ($fx3) { [int]$fx3.InstallState } else { 0 }
if ($isAdmin) {
    try {
        $fx3Feat = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop
        if ("$($fx3Feat.State)" -match 'Pending') {
            Add-Finding Warn '.NET 3.5' ".NET Framework 3.5 is $($fx3Feat.State): the change finishes at the next reboot." 'Reboot'
        }
    } catch { }
}
switch ($fx3State) {
    1 {
        if ($netfx35) { Add-Finding OK '.NET 3.5' '.NET Framework 3.5 (includes 2.0 and 3.0) is enabled.' }
        else { Add-Finding Warn '.NET 3.5' '.NET Framework 3.5 is enabled as a Windows feature, but its setup registration (NDP\v3.5) is missing. It looks half-installed.' 'Elevated: DISM /Online /Disable-Feature /FeatureName:NetFx3, reboot, then DISM /Online /Enable-Feature /FeatureName:NetFx3 /All' }
    }
    { $_ -in 2, 3 } { Add-Finding Info '.NET 3.5' '.NET Framework 3.5 is not enabled. Only apps built for .NET 2.0-3.5 need it; Windows offers to install it when one starts (needs Windows Update, or install media on WSUS-managed PCs: errors 0x800F0954 / 0x800F081F).' }
    default { Add-Finding Info '.NET 3.5' 'Could not read the .NET Framework 3.5 feature state.' }
}

# Component store health. CheckHealth only reads the flag a previous scan left, so it takes seconds.
if ($isAdmin) {
    $dismOut = (& dism.exe /English /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String)
    if ($dismOut -match 'No component store corruption detected') {
        Add-Finding OK 'Component store' 'DISM: no component store corruption detected.'
    } elseif ($dismOut -match 'component store is repairable') {
        Add-Finding Problem 'Component store' 'DISM: the component store is corrupt but repairable. Windows updates (including .NET Framework updates) can fail until it is repaired.' 'In an elevated prompt: DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow, then reboot and retry Windows Update (or re-run this script with -Repair, which runs both). If DISM fails with 0x800f081f or 0x800f0906 (can''t download repair files, common with WSUS), mount a Windows ISO of the same version and add /Source:WIM:<drive>:\sources\install.wim:<index> /LimitAccess'
    } elseif ($dismOut -match 'not repairable|cannot be repaired') {
        Add-Finding Problem 'Component store' 'DISM: the component store is corrupt and cannot be repaired online.' 'Repair install of Windows (in-place upgrade keeping apps and files)'
    } else {
        $line = ($dismOut -split "`r?`n" | Where-Object { $_ -match 'Error|corrupt' } | Select-Object -First 1)
        Add-Finding Info 'Component store' "DISM /CheckHealth gave no clear result. $line"
    }
} else { Add-Finding Info 'Component store' 'Component store health not checked (DISM needs an elevated session).' 'Re-run as administrator to include it' }

# Servicing operations waiting for a reboot. pending.xml older than the last boot means one got stuck.
$pendingXml = Join-Path $env:WINDIR 'WinSxS\pending.xml'
if (Test-Path $pendingXml) {
    $bootTime = $null
    try { $bootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { }
    $pxTime = (Get-Item $pendingXml -Force).LastWriteTime
    if ($bootTime -and $pxTime -lt $bootTime) {
        Add-Finding Problem 'Component store' ("{0} is from {1:g}, before the last boot ({2:g}). An update's install got stuck across a reboot, and later updates (including .NET ones) can keep failing." -f $pendingXml, $pxTime, $bootTime) 'Reboot once more; if it stays, run -Repair, then check C:\Windows\Logs\CBS\CBS.log'
    } else {
        Add-Finding Warn 'Component store' ("Servicing operations are waiting for a reboot ({0}, {1:g})." -f $pendingXml, $pxTime) 'Reboot to finish installing updates'
    }
}

# CBS log: real errors (level "Error"), plus corruption found by SFC/DISM, in the last 30 days.
$cbsLog = Join-Path $env:WINDIR 'Logs\CBS\CBS.log'
$cbsErrors = @(); $cbsCorrupt = @()
try {
    $fs = [IO.File]::Open($cbsLog, 'Open', 'Read', 'ReadWrite')
    try {
        $max = 16MB
        if ($fs.Length -gt $max) { [void]$fs.Seek(-$max, 'End') }
        $sr = New-Object IO.StreamReader($fs)
        $cbsText = $sr.ReadToEnd()
    } finally { $fs.Close() }
    $cbsSince = (Get-Date).AddDays(-30).ToString('yyyy-MM-dd')
    foreach ($ln in ($cbsText -split "`r?`n")) {
        if ($ln -notmatch '^\d{4}-\d\d-\d\d ' -or $ln.Substring(0, 10) -lt $cbsSince) { continue }
        if ($ln -match '^(\S+ \S+), Error\s+(\w+)\s+(.*)$') { $cbsErrors += [pscustomobject]@{ Time = $Matches[1]; Text = $Matches[3].Trim() } }
        elseif ($ln -match 'Corrupt|cannot repair|Repair failed') { $cbsCorrupt += $ln }
    }
} catch { }
if ($cbsErrors.Count) {
    $byCode = $cbsErrors | Group-Object { if ($_.Text -match 'HRESULT = (0x[0-9a-fA-F]{8})') { $Matches[1].ToLower() } else { 'other' } } | Sort-Object Count -Descending
    foreach ($g in ($byCode | Select-Object -First 3)) {
        $l = $g.Group | Select-Object -Last 1
        $txt = if ($l.Text.Length -gt 160) { $l.Text.Substring(0, 160) + '...' } else { $l.Text }
        $hint = if ($g.Name -ne 'other') { Get-WUHint $g.Name } else { 'Run with -Repair (DISM + SFC); if it keeps happening, look up the error text' }
        Add-Finding Warn 'Component store' ("CBS.log: {0} servicing error(s) ({1}) in 30 days, last {2}: {3}" -f $g.Count, $g.Name, $l.Time, $txt) $hint
    }
}
if ($cbsCorrupt.Count) {
    $l = $cbsCorrupt | Select-Object -Last 1
    $txt = if ($l.Length -gt 200) { $l.Substring(0, 200) + '...' } else { $l }
    Add-Finding Warn 'Component store' "CBS.log reports corruption $($cbsCorrupt.Count)x in 30 days, last: $txt" 'Run with -Repair (DISM /RestoreHealth + SFC)'
}
if (-not $cbsErrors.Count -and -not $cbsCorrupt.Count -and (Test-Path $cbsLog)) { Add-Finding OK 'Component store' 'No servicing errors in CBS.log in 30 days.' }

# ---------------------------------------------------------------- 19. temp folders and disk space
Write-Section '19. Temp folders and disk space'
# GetTempPath() reads TMP first, then TEMP. Windows\Temp is what services use.
$tempDirs = [ordered]@{}
foreach ($vn in 'TMP', 'TEMP') {
    $val = [Environment]::GetEnvironmentVariable($vn)
    if ($val -and -not ($tempDirs.Values -contains $val)) { $tempDirs["%$vn%"] = $val }
}
$tempDirs['Windows\Temp'] = Join-Path $env:WINDIR 'Temp'
foreach ($label in $tempDirs.Keys) {
    $dir = $tempDirs[$label]
    if (-not (Test-Path $dir)) {
        Add-Finding Problem 'Temp' "$label points to $dir, which doesn't exist. .NET calls that create temp files (XmlSerializer, WPF, installers) fail." 'Manual: create the folder or fix the variable (System Properties > Environment Variables)'
        continue
    }
    try {
        # GetTempFileName() names files tmpXXXX.tmp: 65,535 names, then it fails with "The file exists".
        $tmpCount = 0; $allCount = 0
        foreach ($f in [IO.Directory]::EnumerateFiles($dir, 'tmp*.tmp')) { $tmpCount++ }
        foreach ($f in [IO.Directory]::EnumerateFiles($dir)) { $allCount++ }
        if ($tmpCount -ge 60000) {
            Add-Finding Problem 'Temp' ("{0} ({1}) holds {2:N0} tmp*.tmp files. At 65,535, Path.GetTempFileName() fails with an IOException in every .NET app." -f $label, $dir, $tmpCount) 'Manual: close apps and delete old files from this folder (Disk Cleanup > Temporary files)'
        } elseif ($tmpCount -ge 20000 -or $allCount -ge 100000) {
            Add-Finding Warn 'Temp' ("{0} ({1}) holds {2:N0} files ({3:N0} tmp*.tmp). Something is leaking temp files; at 65,535 tmp*.tmp, .NET temp-file creation fails." -f $label, $dir, $allCount, $tmpCount) 'Manual: delete old files from this folder and find the app that leaves them'
        } else {
            Add-Finding OK 'Temp' ("{0} ({1}): {2:N0} files." -f $label, $dir, $allCount)
        }
    } catch {
        if ($_.Exception.GetBaseException() -is [UnauthorizedAccessException]) { Add-Finding Info 'Temp' "$label ($dir) can't be read without admin rights." }
        else { Add-Finding Warn 'Temp' "$label ($dir) could not be read: $($_.Exception.GetBaseException().Message)" }
    }
}
# Live test: exactly what .NET apps call.
try {
    $probeTmp = [IO.Path]::GetTempFileName()
    Remove-Item $probeTmp -Force -WhatIf:$false -ErrorAction SilentlyContinue
    Add-Finding OK 'Temp' "Path.GetTempFileName() works ($([IO.Path]::GetTempPath()))."
} catch {
    Add-Finding Problem 'Temp' "Path.GetTempFileName() failed: $($_.Exception.Message)" 'Fix the temp folder findings above (full, missing or no write access)'
}
# Free space on the system drive and the temp drive(s)
$drvs = @($env:SystemDrive) + @($tempDirs.Values | ForEach-Object { if ($_ -match '^([A-Za-z]:)') { $Matches[1].ToUpper() } }) | Select-Object -Unique
foreach ($dl in $drvs) {
    $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$dl'" -ErrorAction SilentlyContinue
    if (-not $ld -or -not $ld.Size) { continue }
    $freeGB = [math]::Round($ld.FreeSpace / 1GB, 1)
    $isSys = $dl -eq $env:SystemDrive
    if ($freeGB -lt 2) {
        Add-Finding Problem 'Disk space' "$dl has only $freeGB GB free. Apps, temp files, NGen and updates fail when the disk fills up." 'Free up space (Disk Cleanup, Storage Sense)'
    } elseif ($isSys -and $freeGB -lt 10) {
        Add-Finding Warn 'Disk space' "$dl (system drive) has $freeGB GB free. Cumulative and .NET updates can fail with less than ~10 GB." 'Free up space before installing updates'
    } else { Add-Finding OK 'Disk space' "$dl has $freeGB GB free." }
}

# ---------------------------------------------------------------- 20. injected modules
Write-Section '20. Third-party DLLs injected into .NET apps'
$secVendors = 'CrowdStrike|SentinelOne|Sentinel Labs|Symantec|Broadcom|McAfee|Trellix|Sophos|ESET|Kaspersky|Bitdefender|Trend Micro|Carbon Black|VMware|Cylance|BlackBerry|Palo Alto|Cisco|Malwarebytes|Avast|AVG|Norton|Gen Digital|Webroot|OpenText|F-Secure|WithSecure|Check Point|Fortinet|Elastic|Tanium|Ivanti|BeyondTrust|CyberArk|Avecto|Digital Guardian|Forcepoint|Zscaler|Netskope|Cybereason|Huntress|Deep Instinct|Morphisec|ThreatLocker|Airlock|Varonis|Rapid7|Qualys'
$hookVendors = 'NVIDIA|Advanced Micro|AMD|Intel|RivaTuner|Unwinder|Overwolf|Discord|Valve|Razer|Logitech|SteelSeries|Corsair|Nahimic|A-Volute|Micro-Star|ASUS|Realtek|Dolby|Waves|NZXT|Elgato|OBS|Medal|Rewind'
if ($netProcs.Count) {
    $injRows = @(foreach ($np in $netProcs) { foreach ($f in @($np.Foreign)) { [pscustomobject]@{ File = $f; App = $np.Name } } })
    # Something in two or more different apps, from outside their folders, is being injected (or is a shell extension).
    # Files that ship with Windows (catalog-signed "Microsoft Windows") don't count, even without a Microsoft company name (icu.dll).
    $winSigned = @{}
    function Test-WindowsSigned([string]$FilePath) {
        if (-not $winSigned.ContainsKey($FilePath)) {
            $subj = ''
            try { $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop; if ($sig.SignerCertificate) { $subj = $sig.SignerCertificate.Subject } } catch { }
            $winSigned[$FilePath] = $subj -match '^CN=Microsoft (Windows|Corporation)(,|$)'
        }
        $winSigned[$FilePath]
    }
    $injected = @($injRows | Group-Object File | Where-Object { @($_.Group | ForEach-Object App | Sort-Object -Unique).Count -ge 2 } |
        Where-Object { -not (Test-WindowsSigned $_.Name) } |
        Sort-Object { @($_.Group | ForEach-Object App | Sort-Object -Unique).Count } -Descending)
    # Crashes in the last 30 days whose faulting module is one of them
    $crashMods = @{}
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = (Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue)) {
        if ($e.Properties.Count -lt 4) { continue }
        $mn = "$($e.Properties[3].Value)".ToLower()
        if (-not $crashMods.ContainsKey($mn)) { $crashMods[$mn] = New-Object System.Collections.Generic.List[string] }
        $crashMods[$mn].Add("$($e.Properties[0].Value)")
    }
    $shown = 0
    foreach ($g in $injected) {
        $apps = @($g.Group | ForEach-Object App | Sort-Object -Unique)
        $co = Get-FileCompany $g.Name
        $kind = if ($co -match $secVendors) { ', security software' } elseif ($co -match $hookVendors) { ', hardware/overlay utility' } else { '' }
        $coTxt = if ($co) { "$co$kind" } else { "no company name$kind" }
        $leaf = (Split-Path $g.Name -Leaf).ToLower()
        $appList = if ($apps.Count -gt 4) { (($apps | Select-Object -First 4) -join ', ') + ", +$($apps.Count - 4) more" } else { $apps -join ', ' }
        if ($crashMods.ContainsKey($leaf)) {
            $crashApps = ($crashMods[$leaf] | Sort-Object -Unique | Select-Object -First 4) -join ', '
            Add-Finding Warn 'Injected DLL' ("{0} ({1}) is loaded into {2} .NET apps ({3}), and apps crashed inside it {4}x in 30 days ({5})." -f $g.Name, $coTxt, $apps.Count, $appList, $crashMods[$leaf].Count, $crashApps) 'Update or temporarily disable that product (or exclude the app from it) and see if the crashes stop'
        } elseif ($shown -lt 10) {
            Add-Finding Info 'Injected DLL' ("{0} ({1}) is loaded into {2} .NET apps: {3}" -f $g.Name, $coTxt, $apps.Count, $appList)
            $shown++
        }
    }
    if ($injected.Count -gt $shown -and $shown -ge 10) { Add-Finding Info 'Injected DLL' "$($injected.Count - $shown) more shared third-party DLL(s) not shown." }
    if (-not $injected.Count) { Add-Finding OK 'Injected DLL' 'No third-party DLL is loaded into more than one running .NET app from outside its folder.' }
    else { Add-Finding Info 'Injected DLL' 'Security, overlay and shell-extension DLLs load into many apps by design. They matter when the failing app crashes, hangs or leaks inside one of them: compare with the crash module in section 11.' }
} else { Add-Finding Info 'Injected DLL' 'No .NET processes visible right now (run while the failing app is open).' }

# ---------------------------------------------------------------- repair
if ($Repair) {
    Write-Section 'Repair: DISM + SFC'
    if ($PSCmdlet.ShouldProcess('Windows component store', 'DISM /RestoreHealth')) {
        & dism.exe /Online /Cleanup-Image /RestoreHealth
    }
    if ($PSCmdlet.ShouldProcess('System files', 'sfc /scannow')) {
        & sfc.exe /scannow
    }
    Add-Finding Info 'Repair' 'DISM and SFC completed - review output above. If .NET Framework is still broken, run the Microsoft .NET Framework Repair Tool.'
    Add-Finding Info 'Repair' 'DISM/SFC do not cover .NET 5+ runtimes. If a .NET desktop app fails to start, reinstall the matching Windows Desktop Runtime (same version and x64/x86) from Microsoft.'
}

# ---------------------------------------------------------------- summary
Write-Section 'Summary'
$problems = @($script:Findings | Where-Object { $_.Severity -in 'Problem', 'Warn' })
if ($problems.Count) { $problems | Format-Table Severity, Area, Detail -Wrap -AutoSize | Out-Host }
else { Write-Host 'No system-level cause found.' -ForegroundColor Green
       Write-Host 'The problem is most likely inside the failing app itself (e.g. a 32-bit app hitting ~2 GB, or its own leak). Re-run while it is open and in use so checks 6 and 8 can see it.' }
if ($script:BackupReady) { Write-Host "Backups saved in: $BackupDir" -ForegroundColor Cyan }
if ($script:NeedsReboot) { Write-Host 'A REBOOT is required for some fixes to take effect.' -ForegroundColor Yellow }
if (-not $Fix -and ($problems | Where-Object Action -like 'Fix:*')) { Write-Host 'Re-run elevated with -Fix to apply the fixes marked "Fix:".' -ForegroundColor Cyan }

$report = Join-Path $OutputDirectory "DotNetTroubleshooter-report-$stamp.csv"
$script:Findings | Export-Csv $report -NoTypeInformation -WhatIf:$false
Write-Host "Full report: $report"
if ($script:Transcribing) {
    Write-Host "Console log: $LogPath"
    Stop-Transcript | Out-Null
    # The colored tag is written with -NoNewline, which the transcript records as its own line.
    # Rejoin "  [ OK ]" + "message" into one line so the log reads like the console.
    try {
        $logText = [IO.File]::ReadAllText($LogPath)
        $logText = [regex]::Replace($logText, '(?m)^(\s*\[(?: OK |INFO|WARN|FAIL)\])[ \t]*\r?\n', '$1 ')
        [IO.File]::WriteAllText($LogPath, $logText, (New-Object Text.UTF8Encoding $true))
    } catch { }
}
