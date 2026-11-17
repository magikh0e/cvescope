# Installed programs + exact Windows build for cvescope's "osquery" collector.
# Read-only: it reads the registry's uninstall keys and the OS version, nothing else.
#
#   powershell -ExecutionPolicy Bypass -File windows-inventory.ps1 -Out \\server\share\inventory
#
# Then point a collector at the files:
#   [[inventory]]
#   type = "osquery"
#   path = "//server/share/inventory/*.json"

param([string]$Out = "$env:USERPROFILE\cvescope-inventory")

$ErrorActionPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$keys = @(
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$programs = Get-ItemProperty $keys |
  Where-Object { $_.DisplayName -and $_.DisplayVersion -and -not $_.SystemComponent } |
  Select-Object DisplayName, DisplayVersion, Publisher |
  Sort-Object DisplayName -Unique

$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$os = Get-CimInstance Win32_OperatingSystem
$result = [ordered]@{
  host     = $env:COMPUTERNAME
  os       = [ordered]@{
    name            = $os.Caption
    build           = $os.BuildNumber
    ubr             = "$($cv.UBR)"
    display_version = $cv.DisplayVersion
  }
  programs = @($programs)
}

$file = Join-Path $Out "$($env:COMPUTERNAME).json"
$result | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $file
Write-Output "wrote $file ($(@($programs).Count) programs)"
