@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   Building ExeScope Suite (.NET 8 Windows)
echo ============================================================

where dotnet >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] .NET SDK is not found on PATH. Please install .NET 8.0 SDK.
    exit /b 1
)

set CONFIG=Release
if "%~1" neq "" set CONFIG=%~1

echo.
echo [1/3] Restoring packages...
dotnet restore ExeScope.sln
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Package restore failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [2/3] Building solution (%CONFIG%)...
dotnet build ExeScope.sln -c %CONFIG% --no-restore
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed.
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Running tests...
dotnet test tests/ExeScope.Tests/ExeScope.Tests.csproj -c %CONFIG% --no-build --verbosity normal
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Tests failed.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================
echo   Build and tests completed successfully!
echo   Main UI Executable: src\ExeScope.UI\bin\%CONFIG%\net8.0-windows\ExeScope.UI.exe
echo   Test Target EXE:    src\ExeScope.TestTarget\bin\%CONFIG%\net8.0-windows\ExeScope.TestTarget.exe
echo ============================================================
exit /b 0
