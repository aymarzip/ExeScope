# ExeScope Build Script for PowerShell
param(
    [string]$Configuration = "Release",
    [switch]$RunTests = $true
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Building ExeScope Suite (.NET 8 Windows)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Check dotnet installation
try {
    $dotnetVersion = dotnet --version
    Write-Host "Found .NET SDK Version: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Error ".NET SDK is not installed or not found on PATH. Please install .NET 8.0 SDK."
    exit 1
}

# 1. Restore NuGet packages
Write-Host "`n[1/4] Restoring packages..." -ForegroundColor Yellow
dotnet restore ExeScope.sln

# 2. Build solution
Write-Host "`n[2/4] Compiling ExeScope ($Configuration)..." -ForegroundColor Yellow
dotnet build ExeScope.sln -c $Configuration --no-restore

# 3. Run automated tests if requested
if ($RunTests) {
    Write-Host "`n[3/4] Running automated test suite..." -ForegroundColor Yellow
    dotnet test tests/ExeScope.Tests/ExeScope.Tests.csproj -c $Configuration --no-build --verbosity normal
} else {
    Write-Host "`n[3/4] Skipping tests (-RunTests:$false)" -ForegroundColor DarkGray
}

# 4. Summary and publish paths
Write-Host "`n[4/4] Build Completed Successfully!" -ForegroundColor Green
Write-Host "Binaries located at:"
Write-Host "  UI Application:  src/ExeScope.UI/bin/$Configuration/net8.0-windows/ExeScope.UI.exe" -ForegroundColor White
Write-Host "  Test Target:     src/ExeScope.TestTarget/bin/$Configuration/net8.0-windows/ExeScope.TestTarget.exe" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
