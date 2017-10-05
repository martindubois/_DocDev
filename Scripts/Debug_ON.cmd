@echo off

rem  Auteur    KMS - Martin Dubois, ing.
rem  Fichier   K:/Scripts/Debug_ON.cmd

echo  Executing  K:\Scripts\Debug_ON.cmd %1 %2 %3 %4  ...

rem  ===== Configuration ====================================================

set BCDEDIT="bcdedit.exe"

rem  ===== Verification =====================================================

if "" == "%1" (
    echo  USER ERROR  Invalid command line
    echo  Usage  Debug_ON.cnd {IP-D} {Port} {Filter} [BusParams]
    pause
    exit /B 1
)

if "" == "%2" (
    echo  USER ERROR  Invalid command line
    echo  Usage  Debug_ON.cnd {IP-D} {Port} {Filter} [BusParams]
    pause
    exit /B 2
)

if "" == "%3" (
    echo  USER ERROR  Invalid command line
    echo  Usage  Debug_ON.cnd {IP-D} {Port} {Filter} [BusParams]
    pause
    exit /B 3
)

echo  Host IP Address      192.168.0.%1
echo  Host Port            5000%2
echo  Bus Parameters       %4
echo  Debug Print Filter   IHVDRIVER=%3
pause

rem  ===== Execution ========================================================

%BCDEDIT% /dbgsettings net hostip:192.168.0.%1 port:5000%2 key:martin.dubois.kms.quebec
if ERRORLEVEL 1 (
    echo  ERROR  %BCDEDIT% /dbgsettings net hostip:192.168.0.%1 port:5000%2 key:...  failed - %ERRORLEVEL%
    pause
    exit /B 4
)

%BCDEDIT% /debug on
if ERRORLEVEL 1 (
    echo  ERROR  %BCDEDIT% /debug on  failed - %ERRORLEVEL%
    pause
    exit /B 5
)

%BCDEDIT% /set testsigning on
if ERRORLEVEL 1 (
    echo  ERROR  %BCDEDIT% /set testsigning on  failed - %ERRORLEVEL%
    pause
    exit /B 6
)

if not "" == "%4" (
    %BCDEDIT% /set "{dbgsettings}" busparams %4
)

if ERRORLEVEL 1 (
    echo  ERROR  %BCDEDIT% /set "{dbgsettings}" busparams %4  failed - %ERRORLEVEL%
    pause
    exit /B 7
)

reg.exe ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d "%3"
if ERRORLEVEL 1 (
    echo  ERROR  reg.exe ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d "%3"  failed - %ERRORLEVEL%
    pause
    exit /B 8
)

shutdown /r /t 1

rem  ===== End ==============================================================

echo  OK
