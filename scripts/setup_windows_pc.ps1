<#
  Prepare a Windows PC so AIDA (on another computer) can look after it over SSH.

  Run ON THE WINDOWS PC YOU WANT TO ADD, in PowerShell opened with "Run as administrator":

      Set-ExecutionPolicy -Scope Process Bypass
      .\setup_windows_pc.ps1 -PublicKey "ssh-ed25519 AAAA... aida"

  (-PublicKey = the one line in ~/.ssh/aida_ed25519.pub on the computer that runs AIDA.)

  What it does, and nothing else:
    1. Checks that WSL (Ubuntu) is installed for this Windows user. AIDA's helper runs inside it and reaches
       Windows the same way AIDA does on its own PC.
    2. Installs and starts Windows' built-in OpenSSH Server (set to start automatically).
    3. Allows SSH (port 22) through Windows Firewall on PRIVATE networks only (your home network), not public Wi-Fi.
    4. Authorizes AIDA's key (key login only for AIDA; your password is never used or stored).
    5. Makes SSH logins open the WSL (Ubuntu) shell instead of cmd.exe.
  Undo later: Settings > System > Optional features > remove "OpenSSH Server".
#>
param(
    [Parameter(Mandatory = $true)][string]$PublicKey
)
$ErrorActionPreference = 'Stop'

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Done($text) { Write-Host "   OK: $text" -ForegroundColor Green }
function Stop-With($text) { Write-Host "`nSTOPPED: $text" -ForegroundColor Yellow; exit 1 }

# ---- 0. checks --------------------------------------------------------------------------
$PublicKey = $PublicKey.Trim()
if ($PublicKey -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+( .*)?$') {
    Stop-With "That does not look like a public key. Copy the single line from ~/.ssh/aida_ed25519.pub (it starts with ssh-ed25519)."
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isElevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) { Stop-With "Open PowerShell with 'Run as administrator' and run this script again." }
$userName = $env:USERNAME
if ($userName -match '\s') { Write-Host "   Note: this Windows user name contains a space; AIDA needs a user name without spaces." -ForegroundColor Yellow }

# ---- 1. WSL -----------------------------------------------------------------------------
Step "Checking WSL (Ubuntu)"
$bash = Join-Path $env:WINDIR 'System32\bash.exe'
$distros = ''
try { $distros = ((& wsl.exe --list --quiet) -join "`n") -replace "`0", '' } catch { }
if (-not (Test-Path $bash) -or -not $distros.Trim()) {
    Stop-With ("WSL with Ubuntu is not set up for $userName yet. Run:  wsl --install -d Ubuntu`n" +
               "   restart the PC, open Ubuntu once to create your Linux user, run in Ubuntu:  sudo apt install -y python3-venv`n" +
               "   then run this script again.")
}
Done "WSL distributions: $(($distros -split "`n" | Where-Object { $_.Trim() }) -join ', ')"

# ---- 2. OpenSSH Server --------------------------------------------------------------------
Step "OpenSSH Server"
$capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Select-Object -First 1
if (-not $capability) { Stop-With "This Windows edition does not offer OpenSSH Server." }
if ($capability.State -ne 'Installed') {
    Write-Host "   Installing (can take a few minutes)..."
    Add-WindowsCapability -Online -Name $capability.Name | Out-Null
}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Done "sshd is $((Get-Service sshd).Status) and starts automatically"

# ---- 3. Firewall (private networks only) ------------------------------------------------------
Step "Windows Firewall"
$ruleName = 'AIDA-OpenSSH-Private'
if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $ruleName -DisplayName 'OpenSSH Server for AIDA (private networks)' -Enabled True `
        -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Private | Out-Null
}
# The capability's own rule allows every network profile; limit it to private networks too
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Set-NetFirewallRule -Profile Private
Done "port 22 open on private networks only"
$public = Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Public'
if ($public) {
    Write-Host ("   Note: '$($public[0].Name)' is set to Public, so AIDA cannot reach this PC on it. If this is your home " +
                "network, set it to Private: Settings > Network & internet > (your connection) > Private network.") -ForegroundColor Yellow
}

# ---- 4. AIDA's key --------------------------------------------------------------------------
Step "Authorizing AIDA's key"
# Windows OpenSSH reads administrators_authorized_keys for members of Administrators (this user, since the script
# runs elevated as them) and the user's own authorized_keys otherwise: write both, so either way the key works.
$adminKeyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
$sshDir = Join-Path $env:USERPROFILE '.ssh'
New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
$userKeyFile = Join-Path $sshDir 'authorized_keys'
foreach ($keyFile in @($adminKeyFile, $userKeyFile)) {
    $existing = @(if (Test-Path $keyFile) { Get-Content $keyFile -ErrorAction SilentlyContinue })
    if ($existing -notcontains $PublicKey) { Add-Content -Path $keyFile -Value $PublicKey -Encoding ascii }
}
# Required permissions, or sshd ignores the file: Administrators and SYSTEM only
& icacls.exe $adminKeyFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
Done "key added for AIDA ($adminKeyFile and $userKeyFile)"

# ---- 5. SSH logins open WSL -----------------------------------------------------------------
Step "SSH logins open the WSL (Ubuntu) shell"
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value $bash -PropertyType String -Force | Out-Null
Restart-Service sshd
Done "default shell is $bash"

# ---- summary --------------------------------------------------------------------------------
$addresses = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.InterfaceAlias -notlike 'vEthernet*' } |
    Select-Object -ExpandProperty IPAddress
Write-Host "`nThis PC is ready." -ForegroundColor Green
Write-Host "  Windows user:  $userName"
Write-Host "  Address(es):   $($addresses -join ', ')"
Write-Host "`nOn the computer that runs AIDA (in Ubuntu), test the login once:"
Write-Host "  ssh -i ~/.ssh/aida_ed25519 $userName@$($addresses | Select-Object -First 1)"
Write-Host "Then install AIDA's helper:"
Write-Host "  bash scripts/install_agent.sh $userName@$($addresses | Select-Object -First 1)"
Write-Host "`nKeep this PC from sleeping while you want it monitored (Settings > System > Power)."
