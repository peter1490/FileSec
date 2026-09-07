# Authenticode-sign a Windows file (the .exe and/or the installers).
#
# Signing is mandatory when RELEASE_SIGNING_REQUIRED=1 (official upstream tag
# releases). Without that flag, missing credentials only warn and exit 0 so forks
# and manual development runs can still build unsigned artifacts.
# Provide a code-signing certificate as a base64-encoded .pfx in the
# WINDOWS_CERT_BASE64 secret and its password in WINDOWS_CERT_PASSWORD.
#
# For organizations using Azure Trusted Signing or an HSM/cloud CSP instead of a
# local .pfx, replace the signtool invocation below with the relevant
# `signtool sign /dlib ...` (Trusted Signing) call — see docs/RELEASE.md.
param(
  [Parameter(Mandatory = $true)][string]$File
)
$ErrorActionPreference = "Stop"

if (-not $env:WINDOWS_CERT_BASE64) {
  if ($env:RELEASE_SIGNING_REQUIRED -eq "1") {
    throw "RELEASE_SIGNING_REQUIRED=1 but WINDOWS_CERT_BASE64 is not set."
  }
  Write-Warning "WINDOWS_CERT_BASE64 not set - leaving '$File' UNSIGNED."
  exit 0
}
if (-not $env:WINDOWS_CERT_PASSWORD -and $env:RELEASE_SIGNING_REQUIRED -eq "1") {
  throw "RELEASE_SIGNING_REQUIRED=1 but WINDOWS_CERT_PASSWORD is not set."
}

$pfx = Join-Path $env:RUNNER_TEMP "filesec-codesign.pfx"
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:WINDOWS_CERT_BASE64))

try {
  $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" `
    -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
  if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)." }

  & $signtool.FullName sign `
    /fd SHA256 `
    /f $pfx `
    /p $env:WINDOWS_CERT_PASSWORD `
    /tr http://timestamp.digicert.com `
    /td SHA256 `
    $File
  if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE" }
  Write-Host "Signed: $File"
}
finally {
  Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}
