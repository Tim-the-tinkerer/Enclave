# Enclave - one-step release build. Double-click BUILD INSTALLER.bat to run this.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "== Enclave release build ==" -ForegroundColor Cyan

Write-Host "`n[1/3] Self-test..." -ForegroundColor Cyan
dotnet run --project src\EnclaveCli -c Release -- selftest
if ($LASTEXITCODE -ne 0) { Write-Host "Self-test FAILED. Nothing was built." -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }

Write-Host "`n[2/3] Building app..." -ForegroundColor Cyan
if (Test-Path publish) { Remove-Item publish -Recurse -Force }
dotnet publish src\EnclaveApp\EnclaveApp.csproj -c Release -r win-x64 --self-contained true -o publish
if ($LASTEXITCODE -ne 0) { Write-Host "Build FAILED." -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }

Write-Host "`n[3/3] Building installer..." -ForegroundColor Cyan
$candidates = @(
  "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
$iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
  $roots = @("$env:LOCALAPPDATA","${env:ProgramFiles(x86)}","$env:ProgramFiles") | Where-Object { $_ -and (Test-Path $_) }
  $found = Get-ChildItem $roots -Recurse -Filter ISCC.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($found) { $iscc = $found.FullName }
}
if (-not $iscc) { Write-Host "Inno Setup not found. Install from https://jrsoftware.org/isdl.php then run this again." -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }
& $iscc .\Enclave.iss
if ($LASTEXITCODE -ne 0) { Write-Host "Installer FAILED." -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }

$setup = Get-ChildItem .\Output -Filter *.exe | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host "`nDONE. Your installer is ready:" -ForegroundColor Green
Write-Host "  $($setup.FullName)" -ForegroundColor Green
Start-Process explorer -ArgumentList "/select,`"$($setup.FullName)`""
Read-Host "Press Enter to close"
