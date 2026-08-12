$ErrorActionPreference = "Stop"

$composeFile = Join-Path $PSScriptRoot "compose.yaml"
$composeArgs = @("compose", "--project-name", "wgd-network-policy-it", "--file", $composeFile)
$result = 0

function Invoke-Compose {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & docker @composeArgs @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
}

try {
    Invoke-Compose up --build -d gateway target-a target-b target-c target-denied
    Invoke-Compose up -d managed-peer unmanaged-peer
    Invoke-Compose wait managed-peer unmanaged-peer
    Invoke-Compose exec -T gateway /tests/gateway-assert.sh
}
catch {
    $result = 1
    Write-Error $_
    & docker @composeArgs logs
}
finally {
    & docker @composeArgs down --volumes --remove-orphans
}

exit $result
