@echo off
REM 
REM Cross Platform and Multi Architecture Advanced Binary Emulation Framework
REM Built on top of Unicorn emulator (www.unicorn-engine.org) 

python test_pe_nu.py && python test_windows_stdio.py && python test_peshellcode_nu.py
