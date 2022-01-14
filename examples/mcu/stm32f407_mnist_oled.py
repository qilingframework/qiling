#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407
from qiling.hw.external_device.oled.ssd1306 import PyGameSSD1306Spi


ql = Qiling(["../rootfs/mcu/stm32f407/mnist.bin", 0x8000000],
            archtype="cortex_m", env=stm32f407, verbose=QL_VERBOSE.DEFAULT)

ql.hw.create('rcc')
ql.hw.create('gpiod')
ql.hw.create('spi1')
ql.hw.create('crc')

oled = PyGameSSD1306Spi(dc=(ql.hw.gpiod, 5))
ql.hw.spi1.connect(oled)

ql.hw.systick.ratio = 1000

## a temporary method
def hook_smlabb(ql):
    ql.arch.regs.r3 = ql.arch.regs.r2 + ql.arch.regs.r1 * ql.arch.regs.r3
    ql.arch.regs.pc = (ql.arch.regs.pc + 4) | 1

ql.hook_address(hook_smlabb, 0x8007a12)
ql.hook_address(hook_smlabb, 0x8007b60)

ql.run()
