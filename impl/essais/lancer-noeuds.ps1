<#
.SYNOPSIS
  Lance les Nœuds S3m d'essai de <Racine> (dossiers node*), en arrière-plan.

.DESCRIPTION
  Chaque Nœud tourne sans fenêtre ; sa sortie va dans node.out.log et
  node.err.log de son dossier, son numéro de processus dans node.pid (lu
  par arreter-noeuds.ps1). Un Nœud déjà lancé est laissé tel quel. Les
  lancements sont espacés : au premier démarrage, chaque Nœud calcule sa
  preuve d'identité (1 à 2 minutes de calcul).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\impl\essais\lancer-noeuds.ps1
#>
param(
    [string]$Racine = "D:\nodes",
    [int]$IntervalleSecondes = 3,
    [string]$Exe = (Join-Path $PSScriptRoot "..\dist\windows\s3m-node.exe")
)
$ErrorActionPreference = "Stop"

$Exe = (Resolve-Path $Exe).Path
$dirs = Get-ChildItem -Directory -Path $Racine -Filter "node*" |
    Where-Object { Test-Path (Join-Path $_.FullName "node.json") } |
    Sort-Object Name
if (-not $dirs) { throw "aucun Nœud dans $Racine (lancez d'abord creer-noeuds.ps1)" }

function Get-NodeProcess([string]$dir) {
    $pidFile = Join-Path $dir "node.pid"
    if (-not (Test-Path $pidFile)) { return $null }
    $id = [int](Get-Content $pidFile -TotalCount 1)
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    # Le numéro peut avoir été réattribué à un autre programme.
    if ($p -and $p.Path -eq $Exe) { return $p }
    return $null
}

$lances = 0
foreach ($d in $dirs) {
    if (Get-NodeProcess $d.FullName) {
        Write-Host "$($d.Name) : déjà lancé"
        continue
    }
    $p = Start-Process -FilePath $Exe -ArgumentList "`"$(Join-Path $d.FullName 'node.json')`"" `
        -WorkingDirectory $d.FullName -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $d.FullName "node.out.log") `
        -RedirectStandardError (Join-Path $d.FullName "node.err.log")
    Set-Content -Path (Join-Path $d.FullName "node.pid") -Value $p.Id -Encoding ascii
    Write-Host "$($d.Name) : lancé (processus $($p.Id))"
    $lances++
    Start-Sleep -Seconds $IntervalleSecondes
}
Write-Host "$lances Nœud(s) lancé(s). Adresse du tableau de bord de chacun : ligne « Dashboard » de son node.out.log."
