#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys

sys.path.append("..")

from qiling import *
from qiling.extensions.report import generate_report


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output="debug")
    ql.run()
    my_json = generate_report(ql)  # do something with the json
    print(generate_report(ql, pretty_print=True))  # or just print it to console


if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/x86_hello.exe"], "rootfs/x86_windows")
