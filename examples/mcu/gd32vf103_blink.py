#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.gd32vf1 import gd32vf103

ql = Qiling(['../rootfs/mcu/gd32vf103/blink.hex'], archtype="riscv64", 
                    env=gd32vf103, verbose=QL_VERBOSE.DEBUG)

ql.hw.create('rcu')
ql.hw.create('gpioa').watch()
ql.hw.create('gpioc').watch()

delay_cycles_begin = 0x800015c
delay_cycles_end = 0x800018c

def skip_delay(ql):
    ql.arch.regs.pc = delay_cycles_end

ql.hook_address(skip_delay, delay_cycles_begin)
ql.hw.gpioc.hook_set(13, lambda : print('Set PC13'))

ql.run(count=20000)
