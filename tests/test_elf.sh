#!/bin/bash

# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

python3 ./test_posix.py && python3 ./test_qltool.py && python3 test_android.py && python3 ./test_debugger.py && python3 ./test_uefi.py
