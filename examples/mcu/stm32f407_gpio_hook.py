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
from qiling.const import QL_ARCH, QL_OS


ql = Qiling(["../rootfs/mcu/stm32f407/ai-sine-test.elf"],
            archtype=QL_ARCH.CORTEX_M, ostype=QL_OS.MCU, env=stm32f407, verbose=QL_VERBOSE.DEFAULT)

ql.hw.create('rcc')
ql.hw.create('pwr')
ql.hw.create('flash interface')
ql.hw.create('gpioa')
ql.hw.create('gpiob')
ql.hw.create('gpiod')
ql.hw.create('spi1')
ql.hw.create('crc')
ql.hw.create('dbgmcu')

oled = PyGameSSD1306Spi(dc=(ql.hw.gpiod, 5))
ql.hw.spi1.connect(oled)

def indicator(ql):
    ql.log.info('PA7 set')

ql.hw.gpioa.hook_set(7, indicator, ql)
ql.hw.systick.ratio = 1000

ql.run(count=800000)
