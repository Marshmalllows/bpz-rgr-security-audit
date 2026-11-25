param(
    [ValidateSet("before", "after")]
    [string]$Label = "before"
)

$ErrorActionPreference = "Continue"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

$image = if ($Label -eq "before") { "raesene/bwapp:latest" } else { "bpz-rgr/bwapp-fixed:latest" }
$src = Join-Path $env:TEMP "bpz-rgr-src/$Label"
$out = Join-Path $root "scans/$Label"

if (Test-Path $src) { Remove-Item -Recurse -Force $src }
New-Item -ItemType Directory -Force $src, $out | Out-Null

$cid = docker create $image
docker cp "${cid}:/app/." $src
docker rm $cid | Out-Null

docker run --rm -v "${root}:/work" -v "${src}:/src:ro" -w /work semgrep/semgrep:1.95.0 `
    semgrep scan --metrics=off --quiet `
    --config security/semgrep/xss.yml --config p/php --config p/xss `
    --json --output "scans/$Label/semgrep.json" /src

docker run --rm -v "${root}:/work" -v "${src}:/src:ro" zricethezav/gitleaks:v8.21.2 `
    detect --no-git --source /src `
    --report-format json --report-path "/work/scans/$Label/gitleaks.json" --exit-code 0

docker run --rm -v "${root}:/work" -v trivy-cache:/root/.cache -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.57.1 `
    image --quiet --scanners vuln --format json --output "/work/scans/$Label/trivy.json" $image

docker run --rm -v "${root}:/work" -v trivy-cache:/root/.cache -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.57.1 `
    image --quiet --format cyclonedx --output "/work/scans/$Label/sbom.cdx.json" $image

docker run --rm -v "${root}:/work" -v "${src}:/src:ro" -w /work node:20-alpine `
    npx --yes retire@5.2.5 --path /src --outputformat json --outputpath "scans/$Label/retire.json" --exitwith 0

python (Join-Path $PSScriptRoot "summarize.py") $out
