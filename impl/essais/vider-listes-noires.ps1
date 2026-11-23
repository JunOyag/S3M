<#
.SYNOPSIS
  Vide la liste noire de tous les Nœuds S3m d'essai de <Racine> (dossiers node*).

.DESCRIPTION
  Appelle « s3m-node blacklist-clear » sur chaque Nœud. Un Nœud en marche
  réécrirait son état par-dessus : il est laissé tel quel, sauf avec
  -Redemarrer (arrêt par arreter-noeuds.ps1, liste noire vidée, relance par
  lancer-noeuds.ps1). Les Nœuds retirés de la liste noire pourront redevenir
  partenaires ; les fragments effacés lors de la rupture ne reviennent pas,
  la réparation les replace.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\impl\essais\vider-listes-noires.ps1
  powershell -ExecutionPolicy Bypass -File .\impl\essais\vider-listes-noires.ps1 -Redemarrer
#>
param(
    [string]$Racine = "D:\nodes",
    [switch]$Redemarrer,
    [string]$Exe = (Join-Path $PSScriptRoot "..\dist\windows\s3m-node.exe")
)
$ErrorActionPreference = "Stop"

$Exe = (Resolve-Path $Exe).Path
$dirs = Get-ChildItem -Directory -Path $Racine -Filter "node*" |
    Where-Object { Test-Path (Join-Path $_.FullName "node.json") } |
    Sort-Object Name
if (-not $dirs) { throw "aucun Nœud dans $Racine" }

if ($Redemarrer) {
    & (Join-Path $PSScriptRoot "arreter-noeuds.ps1") -Racine $Racine -Exe $Exe
}

function Test-NodeRunning([string]$dir) {
    $pidFile = Join-Path $dir "node.pid"
    if (-not (Test-Path $pidFile)) { return $false }
    $p = Get-Process -Id ([int](Get-Content $pidFile -TotalCount 1)) -ErrorAction SilentlyContinue
    return [bool]($p -and $p.Path -eq $Exe)
}

$vides = 0
$ignores = 0
foreach ($d in $dirs) {
    if (Test-NodeRunning $d.FullName) {
        Write-Host "$($d.Name) : en marche, laissé tel quel (-Redemarrer pour l'arrêter et le relancer)"
        $ignores++
        continue
    }
    $out = & $Exe blacklist-clear (Join-Path $d.FullName "node.json") 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$($d.Name) : échec — $out"
        continue
    }
    Write-Host "$($d.Name) : $out"
    $vides++
}
Write-Host "$vides Nœud(s) traité(s), $ignores laissé(s) en marche."

if ($Redemarrer) {
    & (Join-Path $PSScriptRoot "lancer-noeuds.ps1") -Racine $Racine -Exe $Exe
}
