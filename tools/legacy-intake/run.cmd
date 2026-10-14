@echo off
setlocal EnableExtensions DisableDelayedExpansion
if not exist "%SystemRoot%\System32\cscript.exe" goto missing
"%SystemRoot%\System32\cscript.exe" //B //NoLogo //T:60 "%~dp0intake.vbs"
if errorlevel 3 goto failed
if errorlevel 2 goto partial
if errorlevel 1 goto failed
echo Intake finished. Read result\observations.txt before sharing.
echo This is NOT an agent compatibility or license test.
exit /b 0
:partial
echo Partial inventory. Read result\observations.txt for missing fields.
exit /b 2
:missing
echo Windows Script Host is unavailable. Do not change security policy.
exit /b 3
:failed
echo Intake failed, timed out, was blocked, or result already exists.
echo Keep any partial result. Use a fresh local folder for a new run.
exit /b 3
