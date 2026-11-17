# Verify that a built FileSec executable embeds the required application
# manifest (RT_MANIFEST, resource type 24, id 1) declaring per-monitor-v2 DPI
# awareness, which GPUI needs to render crisply on every monitor — see
# crates/filesec-gui/build_support/windows_resources.rs (audit FS-15). The
# check reads the resource back out of the final .exe with the Windows SDK's
# mt.exe, so it tests what ships, not what the build script intended.
#
# Usage: ./packaging/windows/verify_resources.ps1 -File target/release/filesec.exe
param(
    [Parameter(Mandatory = $true)]
    [string]$File
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $File)) {
    throw "Executable not found: $File"
}

$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$mt = Get-ChildItem -Path $kits -Recurse -Filter 'mt.exe' -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\mt\.exe$' } |
    Sort-Object -Property FullName -Descending |
    Select-Object -First 1
if (-not $mt) {
    throw "mt.exe (Windows SDK) not found under $kits"
}

$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$extracted = Join-Path $tempRoot ("manifest-" + [IO.Path]::GetFileName($File) + ".xml")
& $mt.FullName -nologo "-inputresource:$File;#1" "-out:$extracted"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $extracted)) {
    throw "$File has no RT_MANIFEST (type 24) resource #1"
}

$xml = Get-Content -Raw -LiteralPath $extracted
if ($xml -notmatch '<dpiAwareness[^>]*>\s*PerMonitorV2\s*</dpiAwareness>') {
    throw "$File embeds a manifest without <dpiAwareness>PerMonitorV2</dpiAwareness>"
}
if ($xml -notmatch 'Microsoft\.Windows\.Common-Controls') {
    throw "$File embeds a manifest without the Common Controls v6 dependency"
}
Write-Host "OK: $File embeds the per-monitor-v2 DPI-aware application manifest"
