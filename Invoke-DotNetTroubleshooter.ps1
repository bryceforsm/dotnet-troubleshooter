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

    Default is report-only. Use -Fix to apply safe fixes (backups + restore point first).
    Use -Repair to also run DISM /RestoreHealth and SFC to repair .NET Framework system files.
    -Fix also runs "ngen executeQueuedItems" and "ngen update" (no-ops when the cache is healthy).
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
if ([Environment]::GetEnvironmentVariable('DOTNET_ROOT', 'Machine') -or [Environment]::GetEnvironmentVariable('DOTNET_ROOT', 'User')) {
    Add-Finding Info '.NET runtimes' 'DOTNET_ROOT is set; framework-dependent apps may load a runtime from that folder instead of Program Files.'
}

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
$netProcs = foreach ($p in Get-Process) {
    try {
        $mods = @($p.Modules)
        $clr  = $mods | Where-Object { $_.ModuleName -in 'clr.dll', 'mscorwks.dll' } | Select-Object -First 1
        $core = $mods | Where-Object { $_.ModuleName -eq 'coreclr.dll' } | Select-Object -First 1
        if (-not ($clr -or $core)) { continue }
        $runtime = if ($core) {
            # Shared runtime lives in ...\Microsoft.NETCore.App\<version>\coreclr.dll; otherwise it's bundled with the app.
            $coreDir = Split-Path $core.FileName -Parent
            if ((Split-Path $coreDir -Leaf) -match '^\d+\.\d+\.\d+' -and (Split-Path (Split-Path $coreDir -Parent) -Leaf) -eq 'Microsoft.NETCore.App') {
                ".NET $(Split-Path $coreDir -Leaf)"
            } else {
                $fv = $core.FileVersionInfo
                ".NET {0}.{1} (self-contained)" -f $fv.FileMajorPart, $fv.FileMinorPart
            }
        } else { "Framework $(Get-ModuleVersion $clr)" }
        $desktop = [bool]($mods | Where-Object { $_.ModuleName -in 'PresentationFramework.dll', 'System.Windows.Forms.dll', 'wpfgfx_cor3.dll', 'wpfgfx_v0400.dll' })
        $wow = $false; [void][OomNative]::IsWow64Process($p.Handle, [ref]$wow)
        [pscustomobject]@{
            Name = $p.Name; Id = $p.Id; Bits = $(if ($wow) { 32 } else { 64 }); Runtime = $runtime; GUI = $desktop
            PrivateGB = [math]::Round($p.PrivateMemorySize64 / 1GB, 2); VirtualGB = [math]::Round($p.VirtualMemorySize64 / 1GB, 2)
            Path = $p.Path; IsCore = [bool]$core
        }
    } catch { }
}
$netProcs = @($netProcs)
if ($netProcs.Count) {
    $netProcs | Sort-Object Bits, PrivateGB -Descending | Format-Table Name, Id, Bits, Runtime, GUI, PrivateGB, VirtualGB -AutoSize | Out-Host
    foreach ($np in ($netProcs | Where-Object { $_.Bits -eq 32 -and ($_.VirtualGB -gt 1.6 -or $_.PrivateGB -gt 1.2) })) {
        Add-Finding Problem '32-bit limit' "$($np.Name) (PID $($np.Id), $($np.Runtime)) is a 32-bit .NET process using $($np.VirtualGB) GB virtual / $($np.PrivateGB) GB private. 32-bit apps hit OOM at ~1.5-2 GB no matter how much RAM you have." 'Use the app''s 64-bit build, or ask the vendor to enable /LARGEADDRESSAWARE'
    }
    if (-not ($netProcs | Where-Object Bits -eq 32)) { Add-Finding OK '32-bit limit' 'No running 32-bit .NET processes.' }

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

$report = Join-Path $env:TEMP "DotNetTroubleshooter-report-$stamp.csv"
$script:Findings | Export-Csv $report -NoTypeInformation
Write-Host "Full report: $report"
