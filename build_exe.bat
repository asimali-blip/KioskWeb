@echo off
REM ============================================================================
REM  Build Standalone EXE — Wavetec Kiosk Web Dashboard
REM  RUN THIS ON A WINDOWS MACHINE THAT HAS PYTHON + INTERNET ACCESS.
REM
REM  This creates a folder (dist\kiosk_web\) containing kiosk_web.exe plus
REM  everything it needs — Python itself, Flask, Waitress, etc. are all
REM  bundled inside. The machine that RUNS this exe does NOT need Python
REM  installed at all.
REM
REM  This machine (the one doing the build) DOES need Python, only to run
REM  PyInstaller itself — once the build finishes, copy the whole
REM  dist\kiosk_web\ folder to wherever it needs to run.
REM ============================================================================

cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python was not found on THIS machine.
    echo This machine needs Python to run the build tool ^(PyInstaller^) —
    echo the machine you deploy TO will not need Python at all.
    pause
    exit /b 1
)

echo Checking for PyInstaller...
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller and dependencies...
    python -m pip install pyinstaller
)

python -m pip show flask waitress openpyxl cryptography >nul 2>&1
if errorlevel 1 (
    echo Installing app dependencies...
    python -m pip install -r requirements.txt
)

echo.
echo ============================================================
echo   Building kiosk_web.exe (folder mode — recommended)
echo ============================================================
echo.

REM --onedir (folder mode), not --onefile:
REM   --onefile re-extracts itself into a temp folder on every single
REM   run, which is fragile on locked-down servers and slower to start.
REM   --onedir just runs directly — faster, and nothing to extract.
python -m PyInstaller --onedir --console --name kiosk_web app.py --noconfirm

echo.
if exist "dist\kiosk_web\kiosk_web.exe" (
    echo Copying templates\, static\, and Caddy/IIS config files into the build...
    xcopy /E /I /Y templates "dist\kiosk_web\templates" >nul
    xcopy /E /I /Y static "dist\kiosk_web\static" >nul
    if exist Caddyfile copy /Y Caddyfile "dist\kiosk_web\" >nul
    if exist web.config copy /Y web.config "dist\kiosk_web\" >nul
    if exist HTTPS_SETUP.md copy /Y HTTPS_SETUP.md "dist\kiosk_web\" >nul
    if exist HOSTING_ON_IIS.md copy /Y HOSTING_ON_IIS.md "dist\kiosk_web\" >nul
    if exist README.md copy /Y README.md "dist\kiosk_web\" >nul

    echo.
    echo ============================================================
    echo   SUCCESS
    echo ============================================================
    echo   Your build is here: dist\kiosk_web\
    echo.
    echo   Before deploying, also copy these into that SAME folder:
    echo     - plink.exe and pscp.exe   (PuTTY suite — for device SSH)
    echo     - slide2.png               (if using Job 3)
    echo     - patch.zip                (if using Job 4)
    echo     - cfu.apk                  (if using Job 6)
    echo     - caddy.exe                (only if using HTTPS via Caddy)
    echo.
    echo   Then copy the WHOLE dist\kiosk_web\ folder to the target
    echo   machine and run kiosk_web.exe — no Python needed there at all.
    echo ============================================================
) else (
    echo Build failed — check the messages above for errors.
)

pause
