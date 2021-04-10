#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from itertools import product
import struct
import curses
import sys

sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.disk import QlDisk

verfication_start_ip = 0x850B
petya_2nd_stage_start = 0x8000
accepted_chars = "ABCDEFG123456789abcdefghijkmnopqrstuvwx"

def generate_key(key: bytes):
    return b"".join([struct.pack("BB", (k + 0x7A)%256, k*2%256) for k in key])

def stop(ql: Qiling, addr, data):
    ql.emu_stop()

def one_round(ql: Qiling, key: bytes, key_address):
    gkeys = generate_key(key)
    ql.mem.write(key_address, gkeys)
    ql.run(begin=verfication_start_ip, end=verfication_start_ip+6)
    lba37 = ql.mem.read(ql.reg.sp + 0x220, 0x200)
    for ch in lba37:
        if ch != 0x37:
            return False
    return True

# In this stage, we show that the password is correct.
def third_stage(key):
    def pass_red(ql, addr, data):
        curses.ungetch(ord("\n"))
        curses.ungetch(ord("\r"))
    
    def input_key(ql, addr, data):
        for i in key[::-1]:
            curses.ungetch(i)
        curses.ungetch(ord("\n"))
        curses.ungetch(ord("\r"))

    ql = Qiling(["rootfs/8086/petya/petya.DOS_MBR"], 
                 "rootfs/8086",
                 console=False, 
                 verbose=QL_VERBOSE.DEBUG)
    ql.add_fs_mapper(0x80, QlDisk("rootfs/8086/petya/out_1M.raw", 0x80))
    ql.hook_code(pass_red, begin=0x886d, end=0x886d)
    ql.hook_code(input_key, begin=0x85f0, end=0x85f0)
    ql.hook_code(stop, begin=0x6806, end=0x6806)
    ql.run()

# In this stage, we will crack for the password.
def second_stage(ql: Qiling):
    disk = QlDisk("rootfs/8086/petya/out_1M.raw", 0x80)
    #nonce = get_nonce(disk)
    verfication_data = disk.read_sectors(0x37, 1)
    nonce_data = disk.read_sectors(0x36, 1)
    ql.reg.sp -= 0x200
    verification_data_address = ql.reg.sp
    ql.reg.sp -= 0x200
    nonce_address = ql.reg.sp + 0x21
    ql.reg.sp -= 0x20
    key_address = ql.reg.sp
    ql.mem.write(verification_data_address, verfication_data)
    ql.mem.write(nonce_address - 0x21, nonce_data)
    ql.arch.stack_push(0x200)
    ql.arch.stack_push(verification_data_address)
    ql.arch.stack_push(0)
    ql.arch.stack_push(nonce_address)
    ql.arch.stack_push(key_address)
    for x in product(list(accepted_chars), repeat=2):
        ctx = ql.save()
        # 3xMxjxXxLxoxmxAx
        key = b"3xMxjxXxLxoxmx" + ("".join(x)).encode("utf-8")
        print(f"Trying: {key}")
        if one_round(ql, key, key_address):
            print(f"Key: {key}")
            return key
        else:
            ql.restore(ctx)
    return None

# In this stage, we have to wait for petya being load to the right place.
def first_stage():
    ql = Qiling(["rootfs/8086/petya/petya.DOS_MBR"], 
                 "rootfs/8086",
                 console=False, 
                 verbose=QL_VERBOSE.DEBUG)
    ql.add_fs_mapper(0x80, QlDisk("rootfs/8086/petya/out_1M.raw", 0x80))
    # Workaround for `until` in uc_emu_start not working with dynamic loaded code.
    ql.hook_code(stop, begin=petya_2nd_stage_start, end=petya_2nd_stage_start)
    ql.run()
    return ql

if __name__ == "__main__":
    
    ql = first_stage()
    key = second_stage(ql)
    third_stage(key)