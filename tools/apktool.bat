@echo off
setlocal
set BASENAME=apktool
chcp 65001 2>nul >nul
set java_exe=java
%java_exe% -jar -Duser.language=en -Dfile.encoding=UTF8 "%~dp0%BASENAME%.jar" %*
endlocal
