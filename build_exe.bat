@echo off
rem ============================================================
rem  Panabit Portal Mock - Windows EXE Builder
rem  Usage: double-click this file. Requires Python 3.8+.
rem  Output: dist\PanabitPortalMock.exe
rem  NOTE: keep this file ASCII-only (no Chinese) so cmd parses
rem        it correctly on any code page.
rem ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================
echo   Panabit Portal Mock - EXE Builder
echo ============================================
echo.

rem ---- locate a WORKING python: try "py" launcher first, then python ----
set "PY="
py -3 --version >nul 2>nul
if errorlevel 1 (
    python --version >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python not found or not runnable.
        echo Please install Python 3.8+ from:
        echo   https://www.python.org/downloads/
        echo IMPORTANT: during installation check BOTH:
        echo   - "Add Python to PATH"
        echo   - "py launcher" (checked by default)
        echo.
        pause
        exit /b 1
    ) else (
        set "PY=python"
    )
) else (
    set "PY=py -3"
)
echo Python: %PY%
%PY% --version
if errorlevel 1 (
    echo [ERROR] Python does not run correctly. Reinstall Python and add it to PATH.
    pause
    exit /b 1
)

echo.
echo [1/3] Installing PyInstaller ...
%PY% -m pip install --upgrade pyinstaller -q
if errorlevel 1 (
    echo [ERROR] Failed to install PyInstaller. Please check network.
    pause
    exit /b 1
)

echo.
echo [2/3] Building EXE (30-60 seconds) ...
rem --uac-admin: EXE auto-requests admin (UAC prompt) so firewall rules can be written
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name PanabitPortalMock portal_mock_gui.py
if errorlevel 1 (
    echo [ERROR] Build failed. Please send the error message above.
    pause
    exit /b 1
)

echo.
echo [3/3] Done!
echo --------------------------------------------
echo   EXE: %cd%\dist\PanabitPortalMock.exe
echo   Double-click it to run. No Python needed.
echo --------------------------------------------
pause
