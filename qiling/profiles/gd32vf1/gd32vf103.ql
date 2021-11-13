[FLASH]
type = memory
size = 0x20000
base = 0x08000000

[SRAM]
type = memory
size = 0x18000
base = 0x20000000

[BOOT]
type = memory
size = 0x5000
base = 0x1fffb000

[PERIP]
type = mmio
size = 0x40000
base = 0x40000000

[USBFS]
type = mmio
size = 0x40000
base = 0x50000000

[ADC0]
type = peripheral
class = GD32VF1xxAdc
base = 0x40012400
intn = 37

[ADC1]
type = peripheral
class = GD32VF1xxAdc
base = 0x40012800
intn = 37

[AFIO]
type = peripheral
class = GD32VF1xxAfio
base = 0x40010000

[BKP]
type = peripheral
class = GD32VF1xxBkp
base = 0x40006c00

[CAN0]
type = peripheral
class = GD32VF1xxCan
base = 0x40006400
tx_intn = 38
rx0_intn = 39
rx1_intn = 40
ewmc_intn = 41

[CAN1]
type = peripheral
class = GD32VF1xxCan
base = 0x40006800
tx_intn = 82
rx0_intn = 83
rx1_intn = 84
ewmc_intn = 85

[CRC]
type = peripheral
class = GD32VF1xxCrc
base = 0x40023000

[DAC]
type = peripheral
class = GD32VF1xxDac
base = 0x40007400

[DBG]
type = peripheral
class = GD32VF1xxDbg
base = 0xe0042000

[DMA0]
type = peripheral
class = GD32VF1xxDma
base = 0x40020000
stream0_intn = 30
stream1_intn = 31
stream2_intn = 32
stream3_intn = 33
stream4_intn = 34
stream5_intn = 35
stream6_intn = 36

[DMA1]
type = peripheral
class = GD32VF1xxDma
base = 0x40020400
stream0_intn = 75
stream1_intn = 76
stream2_intn = 77
stream3_intn = 78
stream4_intn = 79

[EXMC]
type = peripheral
class = GD32VF1xxExmc
base = 0xa0000000

[EXTI]
type = peripheral
class = GD32VF1xxExti
base = 0x40010400
line0_intn = 25
line1_intn = 26
line2_intn = 27
line3_intn = 28
line4_intn = 29
line9_5_intn = 42
line15_10_intn = 59

[FMC]
type = peripheral
class = GD32VF1xxFmc
base = 0x40022000
intn = 23

[FWDGT]
type = peripheral
class = GD32VF1xxFwdgt
base = 0x40003000

[GPIOA]
type = peripheral
class = GD32VF1xxGpio
base = 0x40010800

[GPIOB]
type = peripheral
class = GD32VF1xxGpio
base = 0x40010c00

[GPIOC]
type = peripheral
class = GD32VF1xxGpio
base = 0x40011000

[GPIOD]
type = peripheral
class = GD32VF1xxGpio
base = 0x40011400

[GPIOE]
type = peripheral
class = GD32VF1xxGpio
base = 0x40011800

[I2C0]
type = peripheral
class = GD32VF1xxI2c
base = 0x40005400
ev_intn = 50
er_intn = 51

[I2C1]
type = peripheral
class = GD32VF1xxI2c
base = 0x40005800
ev_intn = 52
er_intn = 53

[ECLIC]
type = core peripheral
class = GD32VF1xxEclic
base = 0xd2000000

[PMU]
type = peripheral
class = GD32VF1xxPmu
base = 0x40007000

[RCU]
type = peripheral
class = GD32VF1xxRcu
base = 0x40021000
intn = 24

[RTC]
type = peripheral
class = GD32VF1xxRtc
base = 0x40002800
intn = 22
alarm_intn = 60

[SPI0]
type = peripheral
class = GD32VF1xxSpi
base = 0x40013000
intn = 54

[SPI1]
type = peripheral
class = GD32VF1xxSpi
base = 0x40003800
intn = 55

[SPI2]
type = peripheral
class = GD32VF1xxSpi
base = 0x40003c00
intn = 70

[TIMER0]
type = peripheral
class = GD32VF1xxTimer
base = 0x40012c00
brk_intn = 43
up_intn = 44
trg_cmt_intn = 45
channel_intn = 46

[TIMER1]
type = peripheral
class = GD32VF1xxTimer
base = 0x40000000
intn = 47

[TIMER2]
type = peripheral
class = GD32VF1xxTimer
base = 0x40000400
intn = 48

[TIMER3]
type = peripheral
class = GD32VF1xxTimer
base = 0x40000800
intn = 49

[TIMER4]
type = peripheral
class = GD32VF1xxTimer
base = 0x40000c00
intn = 69

[TIMER5]
type = peripheral
class = GD32VF1xxTimer
base = 0x40001000
intn = 73

[TIMER6]
type = peripheral
class = GD32VF1xxTimer
base = 0x40001400
intn = 74

[USART0]
type = peripheral
class = GD32VF1xxUsart
base = 0x40013800
intn = 56

[USART1]
type = peripheral
class = GD32VF1xxUsart
base = 0x40004400
intn = 57

[USART2]
type = peripheral
class = GD32VF1xxUsart
base = 0x40004800
intn = 58

[UART3]
type = peripheral
class = GD32VF1xxUart
base = 0x40004c00
intn = 71

[UART4]
type = peripheral
class = GD32VF1xxUart
base = 0x40005000
intn = 72

[USBFS_GLOBAL]
type = peripheral
class = GD32VF1xxUsbfs
base = 0x50000000

[USBFS_HOST]
type = peripheral
class = GD32VF1xxUsbfs
base = 0x50000400

[USBFS_DEVICE]
type = peripheral
class = GD32VF1xxUsbfs
base = 0x50000800

[USBFS_PWRCLK]
type = peripheral
class = GD32VF1xxUsbfs
base = 0x50000e00

[WWDGT]
type = peripheral
class = GD32VF1xxWwdgt
base = 0x40002c00
intn = 0

