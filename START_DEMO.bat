@echo off
rem Double-click this file to run the guided demo (needs MSYS2 in C:\msys64; build once with: make keys && make)
title SecureAlloc Demo
set MSYSTEM=MSYS
C:\msys64\usr\bin\bash.exe -c "export PATH=/usr/bin; cd '%~dp0' && bash scripts/demo.sh"
echo.
pause
