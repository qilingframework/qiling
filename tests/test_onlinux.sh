#!/bin/bash

# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

python3 ./test_posix.py && 
python3 ./test_elf_multithread.py &&
python3 ./test_elf_ko.py &&
python3 ./test_debugger.py && 
python3 ./test_uefi.py && 
python3 ./test_shellcode.py && 
python3 ./test_edl.py &&
python3 ./test_qnx.py && 
python3 ./test_android.py &&
python3 ./test_mcu.py &&
python3 ./test_evm.py &&
python3 ./test_blob.py &&
python3 ./test_qdb.py &&
echo "Done Test"
