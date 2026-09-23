param([string]$Environment = "dev")
$ErrorActionPreference = "Stop"
$example = "env/.env.$Environment.example"
$target = "env/.env.$Environment"
if (-not (Test-Path $example)) { throw "Missing environment template: $example" }
if (-not (Test-Path $target)) {
  Copy-Item $example $target
  Write-Host "Created $target from template."
} else {
  Write-Host "$target already exists; leaving it unchanged."
}
Write-Host ""
Write-Host "Edit SHAREPOINT_SITE_URL and API_BASE_URL, then run:"
Write-Host "  atk provision --env $Environment"
