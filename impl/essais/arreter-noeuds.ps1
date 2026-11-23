<#
.SYNOPSIS
  Arrête les Nœuds S3m d'essai lancés par lancer-noeuds.ps1.

.DESCRIPTION
  N'arrête que les processus inscrits dans les fichiers node.pid de
  <Racine>\node*, et seulement s'il s'agit bien de s3m-node.exe : aucun
  autre programme n'est touché, ni un Nœud lancé autrement. L'état de
  chaque Nœud est enregistré régulièrement : l'arrêt n'en perd au plus que
  les toutes dernières minutes.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\impl\essais\arreter-noeuds.ps1
#>
param(
    [string]$Racine = "D:\nodes",
    [string]$Exe = (Join-Path $PSScriptRoot "..\dist\windows\s3m-node.exe")
)
$ErrorActionPreference = "Stop"

$Exe = (Resolve-Path $Exe).Path
$arretes = 0
Get-ChildItem -Directory -Path $Racine -Filter "node*" | Sort-Object Name | ForEach-Object {
    $pidFile = Join-Path $_.FullName "node.pid"
    if (-not (Test-Path $pidFile)) { return }
    $id = [int](Get-Content $pidFile -TotalCount 1)
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($p -and $p.Path -eq $Exe) {
        Stop-Process -Id $id -Force -Confirm:$false
        Write-Host "$($_.Name) : arrêté (processus $id)"
        $arretes++
    } else {
        Write-Host "$($_.Name) : n'était pas lancé"
    }
    Remove-Item $pidFile -Force
}
Write-Host "$arretes Nœud(s) arrêté(s)."
