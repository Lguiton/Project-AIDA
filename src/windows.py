"""
Windows bridge: lets AIDA (running in WSL) look at and fix the Windows side of the same PC.

WSL can start Windows programs ("interop"), so AIDA runs Windows PowerShell (powershell.exe) and reads
its JSON output. Nothing is installed on Windows. Commands run as the Windows user who started WSL:
read-only checks work for a normal user; restarting Windows services needs WSL to be started from an
administrator terminal (the tools say so plainly when that is the problem).

Settings (.env):
  AIDA_POWERSHELL                 path to powershell.exe (default: found automatically)
  AIDA_MONITOR_WINDOWS            auto (default: on when powershell.exe is found) | on | off
  AIDA_WINDOWS_SERVICES           Windows services monitoring watches (default below)
  AIDA_WINDOWS_RESTARTABLE_SERVICES  Windows services AIDA may restart (default below)
  AIDA_WINDOWS_SIGNATURE_DAYS     alert when Defender signatures are older than this (default 3)

Security: only validated names and whole numbers are ever placed into a PowerShell command.
"""
import base64
import json
import os
import re
import shutil
import subprocess

DEFAULT_POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
DEFAULT_WATCHED_SERVICES = "WinDefend,mpssvc,BFE,EventLog,Dnscache,Winmgmt,Spooler"
DEFAULT_RESTARTABLE_SERVICES = "Spooler,BITS,wuauserv,WSearch,W32Time"

SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")

# Every script starts like this: UTF-8 output, no progress bars (they corrupt captured output)
_PREAMBLE = ("[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ProgressPreference = 'SilentlyContinue'; "
             "$ErrorActionPreference = 'SilentlyContinue'; ")


def find_powershell() -> str | None:
    configured = os.getenv("AIDA_POWERSHELL", "").strip()
    if configured:
        return configured if os.path.exists(configured) else None
    found = shutil.which("powershell.exe")
    if found:
        return found
    return DEFAULT_POWERSHELL if os.path.exists(DEFAULT_POWERSHELL) else None


def available() -> bool:
    return find_powershell() is not None


def monitoring_enabled() -> bool:
    mode = os.getenv("AIDA_MONITOR_WINDOWS", "auto").strip().lower()
    if mode in ("off", "0", "false", "no"):
        return False
    return available()


def _names(env_name: str, default: str) -> list[str]:
    raw = os.getenv(env_name, default)
    return [n.strip() for n in raw.split(",") if n.strip() and SERVICE_NAME.match(n.strip())]


def watched_services() -> list[str]:
    return _names("AIDA_WINDOWS_SERVICES", DEFAULT_WATCHED_SERVICES)


def restartable_services() -> list[str]:
    return _names("AIDA_WINDOWS_RESTARTABLE_SERVICES", DEFAULT_RESTARTABLE_SERVICES)


def ps_list(names: list[str]) -> str:
    """A PowerShell array literal of already-validated names."""
    return "@(" + ",".join(f"'{n}'" for n in names if SERVICE_NAME.match(n)) + ")"


def encode(script: str) -> str:
    """-EncodedCommand (base64 of UTF-16LE) so quotes survive the trip from WSL to Windows untouched."""
    return base64.b64encode((_PREAMBLE + script).encode("utf-16-le")).decode()


def decode(encoded: str) -> str:
    return base64.b64decode(encoded).decode("utf-16-le")


class WindowsUnavailable(Exception):
    pass


def run(script: str, timeout: int = 60) -> tuple[bool, str]:
    """Run a PowerShell script on Windows. Returns (succeeded, output)."""
    powershell = find_powershell()
    if not powershell:
        raise WindowsUnavailable("Windows PowerShell is not reachable from here (AIDA is not running under WSL, "
                                 "or Windows interop is turned off).")
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encode(script)],
            capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"Windows PowerShell did not finish within {timeout} seconds"
    except OSError as e:
        raise WindowsUnavailable(f"Could not start Windows PowerShell: {e}")
    text = lambda b: (b or b"").decode("utf-8", errors="replace").replace("\r", "").strip()
    output, errors = text(result.stdout), text(result.stderr)
    if result.returncode != 0:
        return False, (errors or output or f"exit code {result.returncode}")[:2000]
    return True, output


def run_json(script: str, timeout: int = 60):
    """Run a script whose last output is ConvertTo-Json; returns the parsed value."""
    ok, output = run(script, timeout)
    if not ok:
        raise RuntimeError(output)
    # PowerShell may print warnings before the JSON; parse from the first bracket
    start = min([i for i in (output.find("{"), output.find("[")) if i >= 0], default=-1)
    if start < 0:
        raise RuntimeError(f"unexpected output from Windows: {output[:300]}")
    return json.loads(output[start:])


def as_list(value) -> list:
    """ConvertTo-Json turns one-item arrays into a bare object and empty arrays into null."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


SNAPSHOT_SCRIPT = r"""
$o = [ordered]@{}
$os = Get-CimInstance Win32_OperatingSystem
$o.computer = $env:COMPUTERNAME
$o.os = "$($os.Caption) (build $($os.BuildNumber))"
$o.uptime_hours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
$o.mem_total_mb = [math]::Round($os.TotalVisibleMemorySize / 1024)
$o.mem_free_mb = [math]::Round($os.FreePhysicalMemory / 1024)
$o.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    [ordered]@{ drive = $_.DeviceID; size_gb = [math]::Round($_.Size / 1GB, 1); free_gb = [math]::Round($_.FreeSpace / 1GB, 1) } })
$o.services = @(foreach ($n in __SERVICES__) {
    $s = Get-Service -Name $n
    if ($s) { [ordered]@{ name = $s.Name; display = $s.DisplayName; status = "$($s.Status)"; start = "$($s.StartType)" } }
    else { [ordered]@{ name = $n; display = $n; status = 'NotFound'; start = '' } } })
$mp = Get-MpComputerStatus
if ($mp) {
    $o.defender = [ordered]@{ mode = "$($mp.AMRunningMode)"; antivirus = [bool]$mp.AntivirusEnabled;
        realtime = [bool]$mp.RealTimeProtectionEnabled; signature_age_days = [int]$mp.AntivirusSignatureAge;
        quick_scan_age_days = [int]$mp.QuickScanAge }
} else { $o.defender = $null }
$o.antivirus_products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { $_.displayName })
$o.firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = "$($_.Name)"; enabled = ("$($_.Enabled)" -eq 'True') } })
$o.pending_reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$o.is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$o | ConvertTo-Json -Depth 4 -Compress
"""


def snapshot(services: list[str] | None = None) -> dict:
    """One PowerShell call that gathers everything monitoring and windows_health need."""
    script = SNAPSHOT_SCRIPT.replace("__SERVICES__", ps_list(services if services is not None else watched_services()))
    data = run_json(script, timeout=90)
    for key in ("disks", "services", "antivirus_products", "firewall"):
        data[key] = as_list(data.get(key))
    return data


def signature_days_limit() -> float:
    try:
        return float(os.getenv("AIDA_WINDOWS_SIGNATURE_DAYS", "3"))
    except ValueError:
        return 3.0


def problems(snap: dict, disk_pct: float, mem_pct: float) -> list[tuple[str, str, str]]:
    """(key, check, description) for everything wrong in a snapshot. Shared by monitoring and windows_health."""
    found = []
    for disk in snap["disks"]:
        size, free = disk.get("size_gb") or 0, disk.get("free_gb") or 0
        if size and (size - free) / size * 100 >= disk_pct:
            found.append((f"win-disk:{disk['drive']}", "windows_disk",
                          f"The Windows drive {disk['drive']} is {(size - free) / size * 100:.0f}% full "
                          f"({free:.1f} GB free of {size:.1f} GB). Investigate what is using the space."))
    total, free_mb = snap.get("mem_total_mb") or 0, snap.get("mem_free_mb") or 0
    if total and free_mb / total * 100 < mem_pct:
        found.append(("win-memory", "windows_memory",
                      f"Windows is low on memory: {free_mb / 1024:.1f} GB free of {total / 1024:.1f} GB "
                      f"({free_mb / total * 100:.0f}%). Find what is using memory."))
    for service in snap["services"]:
        if service.get("start") == "Automatic" and service.get("status") not in ("Running", "StartPending"):
            found.append((f"win-service:{service['name']}", "windows_service",
                          f"The Windows service {service.get('display') or service['name']} ({service['name']}) is set to "
                          f"start automatically but is {service.get('status', 'not running')}. Check why it stopped."))
    defender = snap.get("defender")
    others = [p for p in snap["antivirus_products"] if "defender" not in str(p).lower()]
    if defender and defender.get("mode") in ("Normal", "") and defender.get("antivirus"):
        if not defender.get("realtime"):
            found.append(("win-defender:realtime", "windows_defender",
                          "Microsoft Defender real-time protection is OFF on Windows. Turn it back on in Windows Security."))
        age = defender.get("signature_age_days") or 0
        if age > signature_days_limit():
            found.append(("win-defender:signatures", "windows_defender",
                          f"Microsoft Defender virus definitions are {age} days old. Update Defender signatures."))
    elif defender is not None and not others and not defender.get("antivirus"):  # unknown status is not an alarm
        found.append(("win-defender:none", "windows_defender",
                      "No active antivirus was found on Windows (Microsoft Defender is off and no other product is registered)."))
    for profile in snap["firewall"]:
        if not profile.get("enabled"):
            found.append((f"win-firewall:{profile['profile']}", "windows_firewall",
                          f"The Windows Firewall {profile['profile']} profile is turned OFF. Turn it back on in Windows Security."))
    return found
