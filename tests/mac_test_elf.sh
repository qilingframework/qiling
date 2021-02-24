#!/bin/bash

# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

python3.9 ./test_posix.py && python3.9 test_android.py && python3.9 ./test_debugger.py && python3.9 ./test_uefi.py && python3.9 ./test_shellcode.py && python3.9 ./test_edl.py
