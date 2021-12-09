#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f411


def stm32f411_freertos():
    ql = Qiling(["../rootfs/mcu/stm32f411/os-demo.hex"],                    
        archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEBUG)

    ql.hw.create('usart2').watch()
    ql.hw.create('gpioa').watch()
    ql.hw.create('rcc')    

    ql.hw.systick.set_ratio(100)
    ql.run(count=200000)

if __name__ == "__main__":
    stm32f411_freertos()