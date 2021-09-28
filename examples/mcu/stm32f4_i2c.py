import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE


def stm32f411_i2c():
    ql = Qiling(["../rootfs/mcu/stm32f411/i2c-lcd.hex"],
        archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

    ql.hw.create('i2c1')
    ql.hw.create('rcc')
    ql.hw.create('gpioa')
    ql.hw.create('gpiob')

    flag = False
    def indicator():
        nonlocal flag
        flag = True

    ql.hw.gpioa.hook_set(5, indicator)

    ql.hw.i2c1.connect(0x3f << 1)
    ql.run(count=550000)

    print(flag)

if __name__ == "__main__":
    stm32f411_i2c()