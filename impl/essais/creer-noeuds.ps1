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
  Le rattachement automatique des utilisateurs est activé (désactivable par
  -SansRattachementAuto) : quota par utilisateur et nombre d'utilisateurs
  réglables ; le budget total vaut quota × utilisateurs.
  Un Nœud déjà créé est laissé tel quel, sauf avec -Reconfigurer (ports,
  volume et rattachement réappliqués ; identité et données conservées).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\impl\essais\creer-noeuds.ps1
  powershell -ExecutionPolicy Bypass -File .\impl\essais\creer-noeuds.ps1 -Nombre 10 -CapaciteGo 5
  powershell -ExecutionPolicy Bypass -File .\impl\essais\creer-noeuds.ps1 -Reconfigurer
#>
param(
    [string]$Racine = "D:\nodes",
    [int]$Nombre = 30,
    [int]$PremierPort = 4101,
    [int]$CapaciteGo = 2,
    # Partenaires minimum par stripe (0 = valeur normale, 6).
    [int]$MinPartenaires = 0,
    # Rattachement automatique : quota par utilisateur (Mo) et utilisateurs au plus.
    [int]$QuotaMo = 256,
    [int]$UtilisateursMax = 4,
    [switch]$SansRattachementAuto,
    # Réapplique la configuration aux Nœuds déjà créés.
    [switch]$Reconfigurer,
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
    $existe = Test-Path $cfg
    if ($existe -and -not $Reconfigurer) {
        Write-Host "node$port : déjà créé, laissé tel quel (-Reconfigurer pour réappliquer)"
        continue
    }
    if ($existe) {
        # Nœud en marche : ne pas modifier ses fichiers sous lui.
        $pidFile = Join-Path $dir "node.pid"
        if (Test-Path $pidFile) {
            $p = Get-Process -Id ([int](Get-Content $pidFile -TotalCount 1)) -ErrorAction SilentlyContinue
            if ($p -and $p.Path -eq $Exe) {
                Write-Host "node$port : en marche, non reconfiguré (arrêtez-le d'abord)"
                continue
            }
        }
        # La politique enregistrée dans l'état l'emporterait sur la configuration.
        $state = Join-Path $dir "data\state.json"
        if (Test-Path $state) {
            # Remplacement textuel (« null ») : le reste de l'état n'est pas réécrit.
            $txt = [System.IO.File]::ReadAllText($state)
            $new = [regex]::Replace($txt, '("attach_policy"\s*:\s*)\{[^{}]*\}', '${1}null')
            if ($new -ne $txt) { [System.IO.File]::WriteAllText($state, $new, $utf8) }
        }
    }
    if (-not $existe) {
        & $Exe init $dir --identite | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "échec de s3m-node init pour $dir" }
    }

    $c = Get-Content -Raw -Encoding UTF8 $cfg | ConvertFrom-Json
    $c.listen = "/ip4/0.0.0.0/tcp/$port"
    $c.admin_listen = "/ip4/0.0.0.0/tcp/$($port + 1000)"
    $c.api_port = $port + 4700
    $c.upnp = $false
    $c.mdns = $true
    $c.volumes[0].max_capacity_bytes = [int64]$CapaciteGo * 1GB
    $c.dispersal.min_confirmations = $MinPartenaires
    $c.attach.enabled = -not $SansRattachementAuto
    $c.attach.quota_bytes = [int64]$QuotaMo * 1MB
    $c.attach.max_users = $UtilisateursMax
    $c.attach.budget_bytes = [int64]$QuotaMo * 1MB * $UtilisateursMax
    [System.IO.File]::WriteAllText($cfg, ($c | ConvertTo-Json -Depth 32), $utf8)
    $etat = if ($existe) { "reconfiguré" } else { "créé" }
    $auto = if ($SansRattachementAuto) { "sans rattachement automatique" } else { "rattachement automatique : $UtilisateursMax × $QuotaMo Mo" }
    Write-Host ("node{0} : {3} (écoute {0}, administration {1}, tableau de bord {2}, {4})" -f $port, ($port + 1000), ($port + 4700), $etat, $auto)
}
Write-Host "Terminé. Lancement : powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\lancer-noeuds.ps1`""
