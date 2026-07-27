<#
.SYNOPSIS
  seed-testdata.ps1 - build throwaway fixtures for exercising shhscan on Windows.

  PowerShell equivalent of scripts/seed-testdata.sh. Secrets are generated FRESH
  and RANDOM on every run and written only into the target directory
  (default .demo, git-ignored). Nothing sensitive is ever committed.

  Produces:
    <Dir>\repo        a git repo with a secret added then "removed" in history
    <Dir>\files       a directory tree mixing real secrets with false positives
    <Dir>\image.tar   a synthetic 'docker save' tarball with secrets in a layer

.EXAMPLE
  .\scripts\seed-testdata.ps1
  .\scripts\seed-testdata.ps1 -Dir .demo
#>
param([string]$Dir = ".demo")

$ErrorActionPreference = "Stop"

function Rand([int]$n, [string]$set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
  -join (1..$n | ForEach-Object { $set[(Get-Random -Maximum $set.Length)] })
}
function RandUpper([int]$n) { Rand $n "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" }

if (Test-Path $Dir) { Remove-Item -Recurse -Force $Dir }
New-Item -ItemType Directory -Path $Dir | Out-Null

$AWS_ID     = "AKIA$(RandUpper 16)"
$AWS_SECRET = Rand 40
$GH_PAT     = "ghp_$(Rand 36)"
$STRIPE     = "sk_live_$(Rand 24)"
$SENDGRID   = "SG.$(Rand 22).$(Rand 43)"
$DB_PASS    = Rand 18

# --- 1) git repo with a secret buried in history ----------------------------
$repo = Join-Path $Dir "repo"
New-Item -ItemType Directory -Path $repo | Out-Null
Push-Location $repo
try {
  git init -q
  git config user.email demo@example.com
  git config user.name  demo
  @"
DEBUG = True
AWS_ACCESS_KEY_ID = "$AWS_ID"
AWS_SECRET_ACCESS_KEY = "$AWS_SECRET"
GITHUB_TOKEN = "$GH_PAT"
"@ | Set-Content -NoNewline config.py
  git add .; git commit -qm "add service config"
  # "fix" it later - the secret stays in history
  "DEBUG = True`nAWS_ACCESS_KEY_ID = os.environ[""AWS_ACCESS_KEY_ID""]" | Set-Content -NoNewline config.py
  git add .; git commit -qm "move creds to environment variables"
} finally { Pop-Location }

# --- 2) filesystem tree: real secrets + false positives ---------------------
$files = Join-Path $Dir "files"
New-Item -ItemType Directory -Path (Join-Path $files "src") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $files "node_modules") | Out-Null
@"
STRIPE_KEY=$STRIPE
DATABASE_URL=postgres://admin:$DB_PASS@db.internal:5432/prod
# these should be IGNORED (false positives):
REQUEST_ID=550e8400-e29b-41d4-a716-446655440000
BUILD_SHA=da39a3ee5e6b4b0d3255bfef95601890afd80709
"@ | Set-Content (Join-Path $files ".env")
"const ghToken = ""$GH_PAT"";" | Set-Content (Join-Path $files "src\app.js")
"SENDGRID=$SENDGRID" | Set-Content (Join-Path $files "node_modules\leaked.txt")

# --- 3) synthetic docker save tarball (needs tar.exe, built into Win10 1803+) -
$img = Join-Path $Dir "_img"
New-Item -ItemType Directory -Path (Join-Path $img "rootfs\app") | Out-Null
"SENDGRID_API_KEY=$SENDGRID" | Set-Content (Join-Path $img "rootfs\app\.env")
tar -C (Join-Path $img "rootfs") -cf (Join-Path $img "layer.tar") app
"{""config"":{""Env"":[""PATH=/usr/bin"",""API_TOKEN=$GH_PAT""]}}" | Set-Content (Join-Path $img "config.json")
"[{""Config"":""config.json"",""Layers"":[""layer.tar""]}]"          | Set-Content (Join-Path $img "manifest.json")
tar -C $img -cf (Join-Path $Dir "image.tar") layer.tar config.json manifest.json
Remove-Item -Recurse -Force $img

Write-Host "seeded fixtures in $Dir\"
Write-Host "  repo\       git history with a buried secret"
Write-Host "  files\      real secrets + false positives"
Write-Host "  image.tar   docker layer + config secrets"
Write-Host ("expected true positives: {0} , {1}... , {2}..." -f $AWS_ID, $GH_PAT.Substring(0,8), $STRIPE.Substring(0,12))
