@echo off
echo Starting api...
taskkill /F /IM go-jwt-api.exe 2>nul
timeout /t 2 /nobreak >nul
CompileDaemon --command="./go-jwt-api.exe" -polling=true