$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

docker compose up -d --build

foreach ($port in 8080, 8081) {
    $url = "http://127.0.0.1:$port/install.php?install=yes"
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
            if ($r.Content -match "installed|already") { Write-Host "bWAPP on $port ready"; break }
        } catch { }
        Start-Sleep -Seconds 2
    }
}

Write-Host "Vulnerable: http://127.0.0.1:8080/login.php"
Write-Host "Fixed:      http://127.0.0.1:8081/login.php"
Write-Host "Login: bee / bug"
