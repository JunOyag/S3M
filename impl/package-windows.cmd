@echo off
rem Lance package-windows.ps1 sans modifier la politique d'execution de PowerShell.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0package-windows.ps1" %*
