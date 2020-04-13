@echo off
REM 
REM Cross Platform and Multi Architecture Advanced Binary Emulation Framework
REM Built on top of Unicorn emulator (www.unicorn-engine.org) 

python3 ./test_pe_nu.py && python3 ./test_windows_stdio.py && python3 ./test_peshellcode_nu.py
