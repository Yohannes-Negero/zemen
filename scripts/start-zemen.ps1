# Optional helper: asks for your connection details (password is hidden),
# checks everything, then starts Zemen with the dashboard.
#
# Run it from PowerShell opened in this folder:
#   powershell -ExecutionPolicy Bypass -File .\start-zemen.ps1
#
# The manual steps in START_HERE.txt do the same thing one command at a time.
# (This script could not be run on Windows by its author; if it misbehaves,
# use the manual steps and tell me what it printed.)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$url = Read-Host "OpenSearch URL [http://localhost:9200]"
if ([string]::IsNullOrWhiteSpace($url)) { $url = "http://localhost:9200" }
$user = Read-Host "Username [admin]"
if ([string]::IsNullOrWhiteSpace($user)) { $user = "admin" }
$sec = Read-Host "Password (hidden)" -AsSecureString

$env:ZEMEN_OPENSEARCH_URL = $url
$env:ZEMEN_OPENSEARCH_USERNAME = $user
$env:ZEMEN_OPENSEARCH_PASSWORD = [System.Net.NetworkCredential]::new("", $sec).Password
if ($url -like "https*") { $env:ZEMEN_OPENSEARCH_INSECURE_SKIP_VERIFY = "true" }

& .\zemen.exe init
& .\zemen.exe doctor
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "doctor reported a problem. Fix it (see START_HERE.txt, section 'If something goes wrong') and run this again."
    exit 1
}
& .\zemen.exe init-indices
& .\zemen.exe sync
Write-Host ""
Write-Host "Starting Zemen. Dashboard: http://127.0.0.1:8080   (Ctrl+C to stop)"
& .\zemen.exe run
