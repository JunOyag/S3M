# Executables Windows de S3m (deploiement.packaging) : Noeud, Connecteur en
# ligne de commande et application de barre des taches S3m.exe, en release,
# avec preuve VDF et lecteur WinFsp, plus les DLL MPIR de chiavdf a cote des
# binaires (chargees au demarrage).
#
# Prerequis : Rust, Visual Studio (MSVC), CMake, LLVM ; WinFsp pour monter le
# lecteur. Licence de MPIR a faire valider avant toute distribution.
#
# Usage, depuis la racine du depot (PowerShell) :
#   powershell -ExecutionPolicy Bypass -File .\impl\package-windows.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Add-ToPath([string]$dir) {
    if ($dir -and (Test-Path $dir)) { $env:PATH = "$dir;$env:PATH" }
}

# Outils : cargo, CMake (winget ou installation standard), LLVM.
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Add-ToPath (Join-Path $env:USERPROFILE '.cargo\bin')
}
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    $cm = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages') -Directory -Filter 'Kitware.CMake_*' -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ChildItem $_.FullName -Directory -Filter 'cmake-*' } |
        Select-Object -First 1
    if ($cm) { Add-ToPath (Join-Path $cm.FullName 'bin') } else { Add-ToPath 'C:\Program Files\CMake\bin' }
}
if (-not $env:LIBCLANG_PATH) { $env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin' }
foreach ($tool in 'cargo', 'cmake') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool introuvable : installez-le puis relancez." }
}
if (-not (Test-Path (Join-Path $env:LIBCLANG_PATH 'libclang.dll'))) {
    throw "LLVM introuvable ($env:LIBCLANG_PATH) : winget install LLVM.LLVM, ou definissez LIBCLANG_PATH."
}
$winfsp = Join-Path ${env:ProgramFiles(x86)} 'WinFsp\bin\winfsp-x64.dll'
if (-not (Test-Path $winfsp)) { Write-Warning "WinFsp absent : le lecteur ne pourra pas etre monte (winget install WinFsp.WinFsp)." }

function Build-Bin([string]$crate, [string]$features, [string]$bin) {
    Write-Host "== $bin ($features)"
    Push-Location (Join-Path $here $crate)
    try {
        cargo build --release --features $features --bin $bin
        if ($LASTEXITCODE -ne 0) { throw "echec de la compilation de $bin" }
    } finally { Pop-Location }
}

Build-Bin 'node' 'vdf' 's3m-node'
Build-Bin 'connector' 'vdf mount' 's3m-connector'
Build-Bin 'connector' 'vdf tray' 'S3m'

$dist = Join-Path $here 'dist\windows'
# Vide le dossier sans le supprimer (il peut etre ouvert dans l'Explorateur).
New-Item -ItemType Directory -Force $dist | Out-Null
Get-ChildItem $dist -Force | Remove-Item -Recurse -Force
# Dossier de compilation partagé (impl\.cargo\config.toml).
Copy-Item (Join-Path $here 'target\release\s3m-node.exe') $dist
Copy-Item (Join-Path $here 'target\release\s3m-connector.exe') $dist
Copy-Item (Join-Path $here 'target\release\S3m.exe') $dist

# DLL MPIR de la version de chiavdf effectivement compilee.
$meta = cargo metadata --format-version 1 --manifest-path (Join-Path $here 'connector\Cargo.toml') --features vdf | ConvertFrom-Json
$chia = $meta.packages | Where-Object { $_.name -eq 'chiavdf' } | Select-Object -First 1
if (-not $chia) { throw 'chiavdf introuvable dans les dependances' }
$mpir = Join-Path (Split-Path -Parent $chia.manifest_path) 'mpir_gc_x64'
Copy-Item (Join-Path $mpir '*.dll') $dist

Write-Host ""
Write-Host "Executables et DLL dans $dist :"
Get-ChildItem $dist | ForEach-Object { Write-Host "  $($_.Name)" }
