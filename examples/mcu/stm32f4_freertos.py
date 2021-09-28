import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE


def stm32f411_freertos():
    ql = Qiling(["../rootfs/mcu/stm32f411/os-demo.hex"],                    
        archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

    ql.hw.create('usart2')
    ql.hw.create('rcc')
    ql.hw.create('gpioa')

    count = 0
    def counter():
        nonlocal count
        count += 1

    ql.hw.gpioa.hook_set(5, counter)

    ql.run(count=200000)

    print(count >= 5)
    print(ql.hw.usart2.recv())

if __name__ == "__main__":
    stm32f411_freertos()