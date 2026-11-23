<#
.SYNOPSIS
  Remet en cohérence les Nœuds S3m d'essai de <Racine> après des fraudes
  en cascade : arrêt, réconciliation, relance.

.DESCRIPTION
  Arrête les Nœuds (arreter-noeuds.ps1), puis « s3m-node essais-reconcilier » :
  chaque fragment qu'un Nœud croit confié à un autre Nœud d'essai est
  cherché dans le stockage de ce dernier ; introuvable (effacé lors d'une
  rupture), il est oublié et la réparation le replacera, au lieu d'être
  challengé et de déclencher une nouvelle « fraude ». Toutes les listes
  noires sont ensuite vidées. Les Nœuds sont relancés (lancer-noeuds.ps1),
  sauf avec -SansRelance.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\impl\essais\reconcilier-noeuds.ps1
#>
param(
    [string]$Racine = "D:\nodes",
    [switch]$SansRelance,
    [string]$Exe = (Join-Path $PSScriptRoot "..\dist\windows\s3m-node.exe")
)
$ErrorActionPreference = "Stop"

$Exe = (Resolve-Path $Exe).Path
& (Join-Path $PSScriptRoot "arreter-noeuds.ps1") -Racine $Racine -Exe $Exe
& $Exe essais-reconcilier $Racine
if ($LASTEXITCODE -ne 0) { throw "échec de la réconciliation" }
if (-not $SansRelance) {
    & (Join-Path $PSScriptRoot "lancer-noeuds.ps1") -Racine $Racine -Exe $Exe
}
