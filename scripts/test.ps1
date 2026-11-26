param(
    [ValidateSet("vuln", "fixed")]
    [string]$Target = "fixed"
)

Set-Location (Join-Path $PSScriptRoot "..")
$env:TARGET = "http://bwapp-$Target"
docker compose --profile tests run --rm tests
exit $LASTEXITCODE
