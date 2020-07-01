#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
sys.path.append("..")
from qiling import *
from zipfile import ZipFile

def stopatkillerswtich(ql):
    print("killerswtch found")
    ql.emu_stop()


def unzip(zip_path, name, password):
    with ZipFile(zip_path) as zip_reader:
        with zip_reader.open(name, 'r', password) as f:
            return f.read()
    return None


if __name__ == "__main__":
    data = unzip("rootfs/x86_windows/bin/wannacry.bin.zip", "wannacry.bin", b'infected')
    assert data is not None, "Invalid zip file"
    with open("rootfs/x86_windows/bin/wannacry.bin", 'wb') as f:
        f.write(data)

    ql = Qiling(["rootfs/x86_windows/bin/wannacry.bin"], "rootfs/x86_windows", output="debug")
    ql.hook_address(stopatkillerswtich, 0x40819a)
    ql.run()
