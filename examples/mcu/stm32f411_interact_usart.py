#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import time
import threading

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f411


ql = Qiling(["../../examples/rootfs/mcu/stm32f411/md5_server.hex"],
            archtype=QL_ARCH.CORTEX_M, ostype=QL_OS.MCU, env=stm32f411, verbose=QL_VERBOSE.OFF)

ql.hw.create('usart2')
ql.hw.create('rcc')

threading.Thread(target=lambda : ql.run(count=-1)).start()

while True:
    message = input('>> ').encode()

    ql.hw.usart2.send(message + b'\n')

    time.sleep(0.8)
    print(ql.hw.usart2.recv())
