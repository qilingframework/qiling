#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Mapping

from qiling import Qiling
from qiling.const import QL_ENDIAN


def init_linux_traps(ql: Qiling, address_map: Mapping[str, int]) -> None:
    # If the compiler for the target does not provides some primitives for some
    # reasons (e.g. target limitations), the kernel is responsible to assist
    # with these operations.
    #
    # The following is some `kuser` helpers, which can be found here:
    # https://elixir.bootlin.com/linux/latest/source/arch/arm/kernel/entry-armv.S#L899

    trap_map = {
        # @ 0xffff0fa0
        'memory_barrier': bytes.fromhex(
            'ba 0f 07 ee'   # mcr   p15, 0, r0, c7, c10, 5
            '00 f0 20 e3'   # nop
            '0e f0 a0 e1'   # mov   pc, lr
        ),

        # @ 0xffff0fc0
        'cmpxchg': bytes.fromhex(
            '00 30 92 e5'   # ldr   r3, [r2]
            '00 30 53 e0'   # subs  r3, r3, r0
            '00 10 82 05'   # streq r1, [r2]
            '00 00 73 e2'   # rsbs  r0, r3, #0
            '0e f0 a0 e1'   # mov   pc, lr
        ),

        # @ 0xffff0fe0
        'get_tls': bytes.fromhex(
            '08 00 9f e5'   # ldr   r0, [pc, #(16 - 8)]
            '0e f0 a0 e1'   # mov   pc, lr
            '70 0f 1d ee'   # mrc   p15, 0, r0, c13, c0, 3
            'e7 fd de f1'   # padding (e7 fd de f1)
            '00 00 00 00'   # data
            '00 00 00 00'   # data
            '00 00 00 00'   # data
        )
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

        for trap_name, trap_code in trap_map.items():
            if ql.arch.endian is QL_ENDIAN.EB:
                trap_code = swap_endianness(trap_code)

            if trap_name in address_map:
                ql.mem.write(address_map[trap_name], trap_code)

            ql.log.debug(f'Setting kernel trap {trap_name} at {address_map[trap_name]:#x}')


def swap_endianness(s: bytes, blksize: int = 4) -> bytes:
    blocks = (s[i:i + blksize] for i in range(0, len(s), blksize))

    return b''.join(bytes(reversed(b)) for b in blocks)
