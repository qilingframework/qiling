#!/bin/bash

# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# cd ..
# pip3 install . 

# cd examples

# if [ ! -f "master.zip" ]; then
#     rm -rf rootfs
#     wget https://github.com/qilingframework/rootfs/archive/refs/heads/master.zip
#     unzip master.zip && mv rootfs-master rootfs
# fi    

# cd rootfs/x86_linux/kernel && unzip -P infected m0hamed_rootkit.ko.zip
# cd ../../../../tests

python3 ./test_posix.py && 
python3 ./test_elf_multithread.py &&
python3 ./test_elf_ko.py &&
python3 ./test_android.py && 
python3 ./test_debugger.py && 
python3 ./test_uefi.py && 
python3 ./test_shellcode.py && 
python3 ./test_edl.py &&
python3 ./test_qnx.py 

