@echo off
REM 
REM Example batch script to copy windows required DLLs and registry
REM 

mkdir examples\rootfs\x86_windows\Windows\SysWOW64
mkdir examples\rootfs\x86_windows\Windows\registry
mkdir examples\rootfs\x8664_windows\Windows\System32
mkdir examples\rootfs\x8664_windows\Windows\registry

REM 
REM  Registry
REM 
echo f | xcopy /f /y C:\Users\Default\NTUSER.DAT examples\rootfs\x8664_windows\Windows\registry\NTUSER.DAT
reg save hklm\system examples\rootfs\x8664_windows\Windows\registry\SYSTEM
reg save hklm\security examples\rootfs\x8664_windows\Windows\registry\SECURITY
reg save hklm\software examples\rootfs\x8664_windows\Windows\registry\SOFTWARE
reg save hklm\hardware examples\rootfs\x8664_windows\Windows\registry\HARDWARE
reg save hklm\SAM examples\rootfs\x8664_windows\Windows\registry\SAM
xcopy /d /y examples\rootfs\x8664_windows\Windows\registry\* examples\rootfs\x86_windows\Windows\registry\

REM 
REM  Dlls
REM
if exist %WINDIR%\SysWOW64\advapi32.dll xcopy /f /y %WINDIR%\SysWOW64\advapi32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\rpcrt4.dll xcopy /f /y %WINDIR%\SysWOW64\rpcrt4.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
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
if exist %WINDIR%\SysWOW64\wsock32.dll xcopy /f /y %WINDIR%\SysWOW64\wsock32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\version.dll xcopy /f /y %WINDIR%\SysWOW64\version.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\winmm.dll xcopy /f /y %WINDIR%\SysWOW64\winmm.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\comctl32.dll xcopy /f /y %WINDIR%\SysWOW64\comctl32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\wininet.dll xcopy /f /y %WINDIR%\SysWOW64\wininet.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\psapi.dll xcopy /f /y %WINDIR%\SysWOW64\psapi.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\userenv.dll xcopy /f /y %WINDIR%\SysWOW64\userenv.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\uxtheme.dll xcopy /f /y %WINDIR%\SysWOW64\uxtheme.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\gdi32.dll xcopy /f /y %WINDIR%\SysWOW64\gdi32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\comdlg32.dll xcopy /f /y %WINDIR%\SysWOW64\comdlg32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\shell32.dll xcopy /f /y %WINDIR%\SysWOW64\shell32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\oleaut32.dll xcopy /f /y %WINDIR%\SysWOW64\oleaut32.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
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
if exist %WINDIR%\SysWOW64\downlevel\api-ms-win-core-synch-l1-2-0.dll xcopy /f /y %WINDIR%\SysWOW64\downlevel\api-ms-win-core-synch-l1-2-0.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\downlevel\api-ms-win-core-fibers-l1-1-1.dll xcopy /f /y %WINDIR%\SysWOW64\downlevel\api-ms-win-core-fibers-l1-1-1.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\downlevel\api-ms-win-core-localization-l1-2-1.dll xcopy /f /y %WINDIR%\SysWOW64\downlevel\api-ms-win-core-localization-l1-2-1.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\shlwapi.dll xcopy /f /y %WINDIR%\SysWOW64\shlwapi.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
if exist %WINDIR%\SysWOW64\setupapi.dll xcopy /f /y %WINDIR%\SysWOW64\setupapi.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"
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
if exist %WINDIR%\winsxs\amd64_microsoft-windows-printing-xpsprint_31bf3856ad364e35_10.0.17763.194_none_20349c5a971eb293\XpsPrint.dll xcopy /f /y %WINDIR%\winsxs\amd64_microsoft-windows-printing-xpsprint_31bf3856ad364e35_10.0.17763.194_none_20349c5a971eb293\XpsPrint.dll "examples\rootfs\x86_windows\Windows\SysWOW64\"

exit /b
