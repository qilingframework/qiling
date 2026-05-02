#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f411
from qiling.hw.external_device.oled.ssd1306 import PyGameSSD1306Spi


ql = Qiling(['../rootfs/mcu/stm32f411/oled12864.hex'],
            archtype=QL_ARCH.CORTEX_M, ostype=QL_OS.MCU, env=stm32f411, verbose=QL_VERBOSE.DEFAULT)

ql.hw.create('rcc')
ql.hw.create('gpioa')
ql.hw.create('gpiob')
ql.hw.create('gpioc')
ql.hw.create('spi1')

oled = PyGameSSD1306Spi(dc=(ql.hw.gpioc, 7))

ql.hw.systick.ratio = 2000

ql.hw.spi1.connect(oled)
ql.run(count=1000000)
