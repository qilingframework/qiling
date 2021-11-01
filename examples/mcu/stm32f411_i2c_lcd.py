import sys

sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.hw.external_device.lcd.lcd1602 import PyGameLCD1602


def create(path, lcd):
    ql = Qiling([path], archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

    ql.hw.create('i2c1')
    ql.hw.create('rcc')
    ql.hw.create('gpioa')
    ql.hw.create('gpiob')   

    ql.hw.i2c1.watch()
    ql.hw.i2c1.connect(lcd)    
    
    return ql

if __name__ == "__main__":
    lcd = PyGameLCD1602()    
    
    create("../rootfs/mcu/stm32f411/i2c-lcd.hex", lcd).run(count=700000)
    create("../rootfs/mcu/stm32f411/lcd-plus.hex", lcd).run(count=2000000)

    lcd.quit()
