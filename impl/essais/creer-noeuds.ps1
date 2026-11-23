<#
.SYNOPSIS
  Crée et configure des Nœuds S3m d'essai : <Racine>\node<port d'écoute>.

.DESCRIPTION
  Chaque Nœud reçoit une identité neuve (s3m-node init --identite, sans
  assistant), ses propres ports et un volume de petite taille :
    écoute (blocs et annuaire)   PremierPort + i        (4101, 4102, …)
    administration à distance    PremierPort + i + 1000 (5101, 5102, …)
    tableau de bord local        PremierPort + i + 4700 (8801, 8802, …)
  L'ouverture de port UPnP est désactivée (30 demandes à la box seraient
  inutiles) ; les Nœuds se trouvent par l'annonce sur le réseau local.
  Un Nœud déjà créé est laissé tel quel.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\impl\essais\creer-noeuds.ps1
  powershell -ExecutionPolicy Bypass -File .\impl\essais\creer-noeuds.ps1 -Nombre 10 -CapaciteGo 5
#>
param(
    [string]$Racine = "D:\nodes",
    [int]$Nombre = 30,
    [int]$PremierPort = 4101,
    [int]$CapaciteGo = 2,
    # Partenaires minimum par stripe (0 = valeur normale, 6).
    [int]$MinPartenaires = 0,
    [string]$Exe = (Join-Path $PSScriptRoot "..\dist\windows\s3m-node.exe")
)
$ErrorActionPreference = "Stop"

$Exe = (Resolve-Path $Exe).Path
New-Item -ItemType Directory -Force -Path $Racine | Out-Null
# JSON sans BOM (le Nœud lit de l'UTF-8 strict).
$utf8 = New-Object System.Text.UTF8Encoding $false

for ($i = 0; $i -lt $Nombre; $i++) {
    $port = $PremierPort + $i
    $dir = Join-Path $Racine "node$port"
    $cfg = Join-Path $dir "node.json"
    if (Test-Path $cfg) {
        Write-Host "node$port : déjà créé, laissé tel quel"
        continue
    }
    & $Exe init $dir --identite | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "échec de s3m-node init pour $dir" }

    $c = Get-Content -Raw -Encoding UTF8 $cfg | ConvertFrom-Json
    $c.listen = "/ip4/0.0.0.0/tcp/$port"
    $c.admin_listen = "/ip4/0.0.0.0/tcp/$($port + 1000)"
    $c.api_port = $port + 4700
    $c.upnp = $false
    $c.mdns = $true
    $c.volumes[0].max_capacity_bytes = [int64]$CapaciteGo * 1GB
    $c.dispersal.min_confirmations = $MinPartenaires
    [System.IO.File]::WriteAllText($cfg, ($c | ConvertTo-Json -Depth 32), $utf8)
    Write-Host ("node{0} : créé (écoute {0}, administration {1}, tableau de bord {2})" -f $port, ($port + 1000), ($port + 4700))
}
Write-Host "Terminé. Lancement : powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\lancer-noeuds.ps1`""
