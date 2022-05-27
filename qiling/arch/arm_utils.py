#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_ENDIAN

def init_linux_traps(ql: Qiling, address_map) -> None:
    # If the compiler for the target does not provides some primitives for some
    # reasons (e.g. target limitations), the kernel is responsible to assist
    # with these operations.
    #
    # The following is some `kuser` helpers, which can be found here:
    # https://elixir.bootlin.com/linux/latest/source/arch/arm/kernel/entry-armv.S#L899

    trap_map = {
        'memory_barrier':
        # @ 0xffff0fa0
        # mcr   p15, 0, r0, c7, c10, 5
        # nop
        # mov   pc, lr
        '''
        ba 0f 07 ee
        00 f0 20 e3
        0e f0 a0 e1
        ''',

        'cmpxchg':
        # @ 0xffff0fc0
        # ldr   r3, [r2]
        # subs  r3, r3, r0
        # streq r1, [r2]
        # rsbs  r0, r3, #0
        # mov   pc, lr
        '''
        00 30 92 e5
        00 30 53 e0
        00 10 82 05
        00 00 73 e2
        0e f0 a0 e1
        ''',

        'get_tls':
        # @ 0xffff0fe0
        # ldr   r0, [pc, #(16 - 8)]
        # mov   pc, lr
        # mrc   p15, 0, r0, c13, c0, 3
        # padding (e7 fd de f1)
        # data:
        #   "\x00\x00\x00\x00"
        #   "\x00\x00\x00\x00"
        #   "\x00\x00\x00\x00"
        '''
        08 00 9f e5
        0e f0 a0 e1
        70 0f 1d ee
        e7 fd de f1
        00 00 00 00
        00 00 00 00
        00 00 00 00
        '''
    }

    if address_map:
        # Find min / max address in address_map
        lower_bound = min(address_map.values())
        # Get max address in address_map and its trap name
        upper_trap = max(address_map, key=address_map.get)
        base = ql.mem.align(lower_bound)
        # size to map = start of upper_trap + len of upper_trap - start of lower_trap
        size = ql.mem.align_up(address_map[upper_trap] - lower_bound + len(trap_map[upper_trap]))

        ql.mem.map(base, size, info="[arm_traps]")

        for trap_name, trap_hex in trap_map.items():
            trap_code = bytes.fromhex(trap_hex)

            if ql.arch.endian == QL_ENDIAN.EB:
                trap_code = swap_endianness(trap_code)

            if trap_name in address_map:
                ql.mem.write(address_map[trap_name], trap_code)

            ql.log.debug(f'Set kernel trap: {trap_name} at {address_map[trap_name]:#x}')

def swap_endianness(s: bytes, blksize: int = 4) -> bytes:
    blocks = (s[i:i + blksize] for i in range(0, len(s), blksize))

    return b''.join(bytes(reversed(b)) for b in blocks)