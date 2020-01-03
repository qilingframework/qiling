@echo off
REM 
REM Example batch script to copy windows required DLLs and registry
REM 

mkdir examples\rootfs\x86_windows\Windows\SysWOW64
mkdir examples\rootfs\x8664_windows\Windows\System32
mkdir Windows\registry

REM 
REM  Registry
REM 
echo f | xcopy /f /y C:\Users\Default\NTUSER.DAT examples\rootfs\x8664_windows\Windows\registry\NTUSER.DAT
reg save hklm\system examples\rootfs\x8664_windows\Windows\registry\SYSTEM
reg save hklm\security examples\rootfs\x8664_windows\Windows\registry\SECURITY
reg save hklm\software examples\rootfs\x8664_windows\Windows\registry\SOFTWARE
reg save hklm\SAM examples\rootfs\x8664_windows\Windows\registry\SAM
xcopy /d /y examples\rootfs\x8664_windows\Windows\registry examples\rootfs\x86_windows\Windows\

REM 
REM  Dlls
REM
if exist %WINDIR%\SysWOW64\advapi32.dll xcopy /f /y %WINDIR%\SysWOW64\advapi32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\crypt32.dll xcopy /f /y %WINDIR%\SysWOW64\crypt32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\iphlpapi.dll xcopy /f /y %WINDIR%\SysWOW64\iphlpapi.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\kernel32.dll xcopy /f /y %WINDIR%\SysWOW64\kernel32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\KernelBase.dll xcopy /f /y %WINDIR%\SysWOW64\KernelBase.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\mpr.dll xcopy /f /y %WINDIR%\SysWOW64\mpr.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\msvcp60.dll xcopy /f /y %WINDIR%\SysWOW64\msvcp60.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\msvcrt.dll xcopy /f /y %WINDIR%\SysWOW64\msvcrt.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\netapi32.dll xcopy /f /y %WINDIR%\SysWOW64\netapi32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\ntdll.dll xcopy /f /y %WINDIR%\SysWOW64\ntdll.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\ole32.dll xcopy /f /y %WINDIR%\SysWOW64\ole32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\urlmon.dll xcopy /f /y %WINDIR%\SysWOW64\urlmon.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\user32.dll xcopy /f /y %WINDIR%\SysWOW64\user32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\vcruntime140.dll xcopy /f /y %WINDIR%\SysWOW64\vcruntime140.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\winhttp.dll xcopy /f /y %WINDIR%\SysWOW64\winhttp.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\wininet.dll xcopy /f /y %WINDIR%\SysWOW64\wininet.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\ws2_32.dll xcopy /f /y %WINDIR%\SysWOW64\ws2_32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\msvcr120_clr0400.dll echo f | xcopy /f /y %WINDIR%\SysWOW64\msvcr120_clr0400.dll "examples\rootfs\x86_windows\Windows\SysWOW64\msvcr110.dll"
if exist %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-stdio-l1-1-0.dll xcopy /f /y %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-stdio-l1-1-0.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-runtime-l1-1-0.dll xcopy /f /y %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-runtime-l1-1-0.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-math-l1-1-0.dll xcopy /f /y %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-math-l1-1-0.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-locale-l1-1-0.dll xcopy /f /y %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-locale-l1-1-0.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-heap-l1-1-0.dll xcopy /f /y %WINDIR%\SysWOW64\downlevel\api-ms-win-crt-heap-l1-1-0.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\System32\advapi32.dll xcopy /f /y %WINDIR%\System32\advapi32.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\kernel32.dll xcopy /f /y %WINDIR%\System32\kernel32.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\KernelBase.dll xcopy /f /y %WINDIR%\System32\KernelBase.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\msvcrt.dll xcopy /f /y %WINDIR%\System32\msvcrt.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\ntdll.dll xcopy /f /y %WINDIR%\System32\ntdll.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\urlmon.dll xcopy /f /y %WINDIR%\System32\urlmon.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\user32.dll xcopy /f /y %WINDIR%\System32\user32.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\ws2_32.dll xcopy /f /y %WINDIR%\System32\ws2_32.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\vcruntime140.dll xcopy /f /y %WINDIR%\System32\vcruntime140.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\downlevel\api-ms-win-crt-stdio-l1-1-0.dll xcopy /f /y %WINDIR%\System32\downlevel\api-ms-win-crt-stdio-l1-1-0.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\downlevel\api-ms-win-crt-runtime-l1-1-0.dll xcopy /f /y %WINDIR%\System32\downlevel\api-ms-win-crt-runtime-l1-1-0.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\downlevel\api-ms-win-crt-math-l1-1-0.dll xcopy /f /y %WINDIR%\System32\downlevel\api-ms-win-crt-math-l1-1-0.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\downlevel\api-ms-win-crt-locale-l1-1-0.dll xcopy /f /y %WINDIR%\System32\downlevel\api-ms-win-crt-locale-l1-1-0.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\downlevel\api-ms-win-crt-heap-l1-1-0.dll xcopy /f /y %WINDIR%\System32\downlevel\api-ms-win-crt-heap-l1-1-0.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\vcruntime140d.dll xcopy /f /y %WINDIR%\System32\vcruntime140d.dll "examples\rootfs\x8664_windows\Windows\System32\"
if exist %WINDIR%\System32\ucrtbased.dll xcopy /f /y %WINDIR%\System32\ucrtbased.dll "examples\rootfs\x8664_windows\Windows\System32\"
exit /b
