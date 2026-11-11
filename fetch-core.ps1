# SakuNet: download the sing-box Windows core next to SakuNet.exe.
# Usage:  powershell -ExecutionPolicy Bypass -File .\fetch-core.ps1
$ErrorActionPreference = "Stop"
$Version = "1.14.4"   # sing-box >= 1.14 is required for Snell v6 support
$Name = "sing-box-$Version-windows-amd64"
$Url = "https://github.com/SagerNet/sing-box/releases/download/v$Version/$Name.zip"
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Tmp = Join-Path $env:TEMP "sakunet-core"
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
$Zip = Join-Path $Tmp "$Name.zip"
Write-Host "Downloading $Url"
Invoke-WebRequest -Uri $Url -OutFile $Zip
Expand-Archive -Path $Zip -DestinationPath $Tmp -Force
# Copy sing-box.exe AND its bundled libraries (libcronet.dll is required
# by the Naive outbound, wintun.dll by the TUN inbound) next to SakuNet.exe.
Copy-Item (Join-Path $Tmp "$Name\sing-box.exe") $Dir -Force
Get-ChildItem (Join-Path $Tmp $Name) -Filter *.dll | Copy-Item -Destination $Dir -Force
if (-not (Test-Path (Join-Path $Dir "wintun.dll"))) {
    Write-Warning "wintun.dll not found in the sing-box package: TUN mode will not work, everything else is unaffected."
}
& (Join-Path $Dir "sing-box.exe") version
Write-Host "Core installed in $Dir"
