#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys, os
sys.path.append("../../..")

from binascii import hexlify

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407
from qiling.extensions.afl import ql_afl_fuzz_custom
from unicorn import UC_ERR_OK, UcError
from qiling.arch.arm import QlArchARM


def watch(ql:Qiling):
    r0 = hex(ql.arch.regs.read('r0'))
    if r0 != '0x0':
        print(f"R0 == {r0}")
    # hex(ql.arch.regs.read('r0'))
    print(ql.mem.read(0x8003320, 0xd))

def found_passwd(ql:Qiling):
    # print('right')
    os.abort()

def wrong_test(ql:Qiling):
    # print('no')
    ql.emu_stop()

def fuzz_cb(ql:Qiling):
    if isinstance(ql.arch, QlArchARM):
        pc = ql.arch.effective_pc
    else:
        pc = ql.arch.regs.arch_pc
    try:
        ql.hook_address(found_passwd, 0x08003220)
        ql.hook_address(wrong_test, 0x0800326E)
        ql.run(begin=pc, end=0x8003236)
    except UcError as e:
        return e.errno
    return UC_ERR_OK

# Cracking the passwd of lock
def main(input_file: str, enable_trace=False):
    ql = Qiling(["../../../examples/rootfs/mcu/stm32f407/backdoorlock.hex"],                    
                        archtype="cortex_m", env=stm32f407, verbose=QL_VERBOSE.DISABLED)
    
    ql.hw.create('spi2')
    ql.hw.create('gpioe')
    ql.hw.create('gpiof')
    ql.hw.create('usart1')
    ql.hw.create('rcc')

    # ql.hw.show_info()
    # ql.hook_address(watch, 0x08003232)

    ql.patch(0x8000238, b'\x00\xBF' * 4)
    ql.patch(0x80031e4, b'\x00\xBF' * 11)
    ql.patch(0x80032f8, b'\x00\xBF' * 13)
    ql.patch(0x80013b8, b'\x00\xBF' * 10)
    ql.patch(0x8001A9E,b'\x10\xBD')

    # ql.hw.usart1.send(b'618618\x0d')

    ql.hw.systick.set_ratio(10000)

    def place_input_callback(ql: Qiling, input_data: bytes, _: int):
        print(input_data)
        ql.hw.usart1.send(input_data + b'\x0d')

        return True if input_data else False

    # main_addr = 0x0800023c #0x080031DC #0x08000188 #0x0800023c
    # ql.hook_address(callback=start_afl, address=main_addr)
    if enable_trace:
        # The following lines are only for `-t` debug output
        md = ql.arch.disassembler
        count = [0]

        def spaced_hex(data):
            return b' '.join(hexlify(data)[i:i+2] for i in range(0, len(hexlify(data)), 2)).decode('utf-8')

        def disasm(count, ql, address, size):
            buf = ql.mem.read(address, size)
            try:
                for i in md.disasm(buf, address):
                    return "{:08X}\t{:08X}: {:24s} {:10s} {:16s}".format(count[0], i.address, spaced_hex(buf), i.mnemonic,
                                                                        i.op_str)
            except:
                import traceback
                print(traceback.format_exc())

        def trace_cb(ql, address, size, count):
            rtn = '{:100s}'.format(disasm(count, ql, address, size))
            print(rtn)
            count[0] += 1
            # pass
            # os._exit(0)

        ql.hook_code(trace_cb, count)
 
    # ql.run(end=0x8003236, count=-1)
    ql.run(end=0x080031DC)

    exits = [0x08003270, 0x08003222]
    ql.uc.ctl_exits_enabled(True)
    ql.uc.ctl_set_exits(exits)

    ql_afl_fuzz_custom(ql, input_file, place_input_callback, fuzzing_callback=fuzz_cb)

    os._exit(0)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")
    if len(sys.argv) > 2 and sys.argv[1] == "-t":
        main(sys.argv[2], enable_trace=True)
    else:
        main(sys.argv[1])