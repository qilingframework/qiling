#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

def dump(ql, *args, **kw):
    ql.save(reg=False, cpu_context=True, snapshot="/tmp/snapshot.bin")
    ql.emu_stop()

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/sleep_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEFAULT)
    # load base address from profile file
    X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
    # take a snapshot
    ql.hook_address(dump, X64BASE + 0x1094)
    ql.run()

    ql = Qiling(["rootfs/x8664_linux/bin/sleep_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
    ql.restore(snapshot="/tmp/snapshot.bin")
    # enable gdbserver to listen at localhost address, port 9999
    ql.debugger = "gdb:0.0.0.0:9999"
    begin_point = X64BASE + 0x109e
    end_point = X64BASE + 0x10bc
    ql.run(begin = begin_point, end = end_point)

'''
Partial Execution: https://docs.qiling.io/en/latest/snapshot/

This example shows how to partially debug an elf file. First let the program run, hook at the main address and take a snapshot. Then resume the snapshot to construct a reasonable call_state (registers, memory mapping, dynamic library loading, etc) for our target piece of code, and directly assign the pc pointer to the beginning of the part you want to simulate.

Run it with:
    $ python3 hello_x8664_linux_part_debug.py 

Then in a new terminal start gdb remote debug:
    $ gdb -q
    (gdb) target remote localhost:9999
        Remote debugging using localhost:9999
        Reading /home/qiling/examples/rootfs/x8664_linux/bin/sleep_hello from remote target...
        warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
        Reading /home/qiling/examples/rootfs/x8664_linux/bin/sleep_hello from remote target...
        Reading symbols from target:/home/qiling/examples/rootfs/x8664_linux/bin/sleep_hello...(no debugging symbols found)...done.
        warning: unable to open /proc file '/proc/42000/task/42000/maps'
        Reading /lib64/ld-linux-x86-64.so.2 from remote target...
        Reading /lib64/ld-linux-x86-64.so.2 from remote target...
        Reading symbols from target:/lib64/ld-linux-x86-64.so.2...Reading /lib64/ld-2.27.so from remote target...
        Reading /lib64/.debug/ld-2.27.so from remote target...
        (no debugging symbols found)...done.
        0x000055555555509e in ?? ()
    (gdb) x/8i $pc
        => 0x55555555509e:      lea    0xf83(%rip),%rdi        # 0x555555556028
        0x5555555550a5:      callq  0x555555555060
        0x5555555550aa:      lea    0xf53(%rip),%rdi        # 0x555555556004
        0x5555555550b1:      callq  0x555555555060
        0x5555555550b6:      xor    %eax,%eax
        0x5555555550b8:      add    $0x8,%rsp
        0x5555555550bc:      retq   
        0x5555555550bd:      nopl   (%rax)

The source code of sleep_hello can be found at qiling/examples/src/linux/sleep_hello.c. As the above gdb output shows, we skipped the sleep function to directly debug the code afterwards.
'''