#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.hw.external_device.lcd.lcd1602 import PyGameLCD1602
from qiling.extensions.mcu.stm32f4 import stm32f411


def create(path, lcd):
    ql = Qiling([path], archtype=QL_ARCH.CORTEX_M, ostype=QL_OS.MCU, env=stm32f411, verbose=QL_VERBOSE.DEBUG)

    ql.hw.create('i2c1')
    ql.hw.create('rcc')
    ql.hw.create('gpioa')
    ql.hw.create('gpiob')

    ql.hw.i2c1.watch()
    ql.hw.i2c1.connect(lcd)

    ql.hw.systick.set_ratio(100)

    return ql


if __name__ == "__main__":
    lcd = PyGameLCD1602()

    # Example 1
    create("../rootfs/mcu/stm32f411/i2c-lcd.hex", lcd).run(count=50000)

    # Example 2
    create("../rootfs/mcu/stm32f411/lcd-plus.hex", lcd).run(count=100000)

    # Example 3
    ql = create("../rootfs/mcu/stm32f411/i2cit-lcd.hex", lcd)

    delay_start = 0x8002936
    delay_end = 0x8002955
    def skip_delay(ql):
        ql.arch.regs.pc = delay_end

    ql.hook_address(skip_delay, delay_start)
    ql.run(count=100000)

    lcd.quit()
