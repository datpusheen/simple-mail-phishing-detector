@echo off
setlocal

cd /d "%~dp0"

if "%~1"=="" (
    echo Keo tha file email .eml hoac .txt vao shortcut nay de kiem tra.
    echo.
    echo Hoac chay:
    echo "%~nx0" "C:\path\to\email.eml"
    echo.
    pause
    exit /b 1
)

if not exist "%~1" (
    echo Khong tim thay file:
    echo %~1
    echo.
    pause
    exit /b 1
)

echo Dang kiem tra email:
echo %~1
echo.

set "MAIN_PY=%~dp0src\main.py"
set "EMAIL_FILE=%~1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& python $env:MAIN_PY --email $env:EMAIL_FILE --verbose; exit $LASTEXITCODE"
set "RESULT=%ERRORLEVEL%"

echo.
if "%RESULT%"=="2" (
    echo Ket qua: phat hien phishing.
) else if "%RESULT%"=="1" (
    echo Ket qua: phat hien spam.
) else if "%RESULT%"=="0" (
    echo Ket qua: chua phat hien phishing/spam.
) else if "%RESULT%"=="3" (
    echo Ket qua: chua the hoan tat phan tich. Hay kiem tra API key hoac cau hinh LLM.
) else (
    echo Ket qua: kiem tra that bai hoac chua hoan tat.
)

echo.
pause
exit /b %RESULT%
