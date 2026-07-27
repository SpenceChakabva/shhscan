<#
.SYNOPSIS
  demo.ps1 - seed fresh fixtures and run shhscan against all three sources.
  PowerShell equivalent of scripts/demo.sh.

.EXAMPLE
  .\scripts\demo.ps1
#>
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$Dir = ".demo"

Write-Host "==> seeding test data"
& (Join-Path $PSScriptRoot "seed-testdata.ps1") -Dir $Dir | Out-Null

Write-Host "==> building shhscan.exe"
go build -o shhscan.exe .
$bin = ".\shhscan.exe"

function Section($t) {
  Write-Host ""
  Write-Host ("-" * 60) -ForegroundColor DarkGray
  Write-Host "  $t"
  Write-Host ("-" * 60) -ForegroundColor DarkGray
}

Section "1) GIT HISTORY  (secret deleted from working tree, still in history)"
& $bin git "$Dir\repo"

Section "2) FILESYSTEM   (real secrets flagged; UUIDs/SHAs filtered; node_modules skipped)"
& $bin fs "$Dir\files"

Section "3) DOCKER IMAGE (secrets in a layer .env and in the image config)"
& $bin docker "$Dir\image.tar"

Section "4) ALLOWLIST    (false-positive fixtures - expect: no secrets found)"
& $bin fs "testdata\allowlist-cases"

Write-Host ""
Write-Host "done. re-run any scan with --json for CI-shaped output."
# note: shhscan exits 1 when it finds secrets - that's expected here.
$global:LASTEXITCODE = 0
