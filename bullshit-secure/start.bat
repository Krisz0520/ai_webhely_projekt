@echo off
cd /d "%~dp0"
title Bullshit-elemzes
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo A Node.js nincs telepitve. Megnyitom a letoltooldalt.
  echo Telepitsd az LTS verziot, majd inditsd ujra ezt a fajlt.
  start https://nodejs.org
  pause
  exit /b 1
)
set URL=http://localhost:3000
if exist certs\cert.pem set URL=https://localhost:8443
start "" /min cmd /c "timeout /t 2 /nobreak >nul & start %URL%"
echo Fut: %URL%   (leallitas: Ctrl+C vagy zard be ezt az ablakot)
echo.
node server.js
pause
