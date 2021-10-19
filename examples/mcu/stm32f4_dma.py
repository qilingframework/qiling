import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE


def stm32f411_dma():
    ql = Qiling(["../rootfs/mcu/stm32f411/dma-clock.hex"],                    
        archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

    ql.hw.create('usart2')
    ql.hw.create('dma1')
    ql.hw.create('rcc')

    ql.run(count=200000)
    buf = ql.hw.usart2.recv()

    ## check timestamp
    tick = [int(x) for x in buf.split()]
    for i in range(1, len(tick)):
        assert(4 <= tick[i] - tick[i - 1] <= 6)

if __name__ == "__main__":
    stm32f411_dma()