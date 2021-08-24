#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys
sys.path.append("../..")

import time
import threading

from qiling.core import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["../../examples/rootfs/mcu/stm32f411/md5_server.hex"], 
            archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.OFF)

threading.Thread(target=lambda : ql.run(count=-1)).start()

while True:
    message = input('>> ').encode()
    
    ql.hw.usart2.send(message + b'\n')
    
    time.sleep(0.8)
    print(ql.hw.usart2.recv())
