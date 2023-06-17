#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f411


def stm32f411_dma():
    ql = Qiling(["../rootfs/mcu/stm32f411/dma-clock.hex"],
                archtype=QL_ARCH.CORTEX_M, ostype=QL_OS.MCU, env=stm32f411, verbose=QL_VERBOSE.DEBUG)

    ql.hw.create('usart2').watch()
    ql.hw.create('dma1').watch()
    ql.hw.create('rcc')

    ql.run(count=200000)
    buf = ql.hw.usart2.recv()

    # check timestamp
    tick = [int(x) for x in buf.split()]
    for i in range(1, len(tick)):
        assert (4 <= tick[i] - tick[i - 1] <= 6)


if __name__ == "__main__":
    stm32f411_dma()
