[FLASH]
type = memory
size = 0x200000
base = 0x8000000

[FLASH OTP]
type = memory
size = 0x400
base = 0x1fff7800

[SRAM]
type = memory
size = 0x20000
base = 0x20000000

[SYSTEM]
type = memory
size = 0x7800
base = 0x1FFF0000

[SRAM BB]
type = bitband
size = 0x100000
base = 0x20000000
alias = 0x22000000

[PERIP]
type = mmio
size = 0x100000
base = 0x40000000

[PERIP BB]
type = bitband
size = 0x100000
base = 0x40000000
alias = 0x42000000

[PPB]
type = mmio
size = 0x10000
base = 0xE0000000

[SYSTICK]
type = core periperal
base = 0xE000E010
class = CortexM4SysTick

[NVIC]
type = core periperal
base = 0xE000E100
class = CortexM4Nvic

[SCB]
type = core periperal
base = 0xE000ED00
class = CortexM4Scb

[TIM2]
type = periperal
base = 0x40000000
class = STM32F4xxTim
intn = 28

[TIM3]
type = periperal
base = 0x40000400
class = STM32F4xxTim
intn = 29

[TIM4]
type = periperal
base = 0x40000800
class = STM32F4xxTim
intn = 30

[TIM5]
type = periperal
base = 0x40000c00
class = STM32F4xxTim
intn = 50

[TIM6]
type = periperal
base = 0x40001000
class = STM32F4xxTim
dac_intn = 54

[TIM7]
type = periperal
base = 0x40001400
class = STM32F4xxTim
intn = 55

[TIM12]
type = periperal
base = 0x40001800
class = STM32F4xxTim

[TIM13]
type = periperal
base = 0x40001c00
class = STM32F4xxTim

[TIM14]
type = periperal
base = 0x40002000
class = STM32F4xxTim

[RTC]
type = periperal
base = 0x40002800
class = STM32F4xxRtc
wkup_intn = 3
alarm_intn = 41

[WWDG]
type = periperal
base = 0x40002c00
class = STM32F4xxWwdg
intn = 0

[IWDG]
type = periperal
base = 0x40003000
class = STM32F4xxIwdg

[I2S2ext]
type = periperal
base = 0x40003400
class = STM32F4xxSpi

[SPI2]
type = periperal
base = 0x40003800
class = STM32F4xxSpi
intn = 36

[SPI3]
type = periperal
base = 0x40003c00
class = STM32F4xxSpi
intn = 51

[I2S3ext]
type = periperal
base = 0x40004000
class = STM32F4xxSpi

[USART2]
type = periperal
base = 0x40004400
class = STM32F4xxUsart
intn = 38

[USART3]
type = periperal
base = 0x40004800
class = STM32F4xxUsart
intn = 39

[UART4]
type = periperal
base = 0x40004c00
class = STM32F4xxUsart
intn = 52

[UART5]
type = periperal
base = 0x40005000
class = STM32F4xxUsart
intn = 53

[I2C1]
type = periperal
base = 0x40005400
class = STM32F4xxI2c
ev_intn = 31
er_intn = 32

[I2C2]
type = periperal
base = 0x40005800
class = STM32F4xxI2c
ev_intn = 33
er_intn = 34

[I2C3]
type = periperal
base = 0x40005c00
class = STM32F4xxI2c
ev_intn = 72
er_intn = 73

[CAN1]
type = periperal
base = 0x40006400
class = STM32F4xxCan
tx_intn = 19
rx0_intn = 20
rx1_intn = 21
sce_intn = 22

[CAN2]
type = periperal
base = 0x40006800
class = STM32F4xxCan
tx_intn = 63
rx0_intn = 64
rx1_intn = 65
sce_intn = 66

[PWR]
type = periperal
base = 0x40007000
class = STM32F4xxPwr

[DAC1]
type = periperal
base = 0x40007400
class = STM32F4xxDac

[DAC]
type = periperal
base = 0x40007400
class = STM32F4xxDac

[UART7]
type = periperal
base = 0x40007800
class = STM32F4xxUsart
intn = 82

[UART8]
type = periperal
base = 0x40007c00
class = STM32F4xxUsart
intn = 83

[TIM1]
type = periperal
base = 0x40010000
class = STM32F4xxTim
brk_tim9_intn = 24
up_tim10_intn = 25
trg_com_tim11_intn = 26
cc_intn = 27

[TIM8]
type = periperal
base = 0x40010400
class = STM32F4xxTim
brk_tim12_intn = 43
up_tim13_intn = 44
trg_com_tim14_intn = 45
cc_intn = 46

[USART1]
type = periperal
base = 0x40011000
class = STM32F4xxUsart
intn = 37

[USART6]
type = periperal
base = 0x40011400
class = STM32F4xxUsart
intn = 71

[ADC1]
type = periperal
base = 0x40012000
class = STM32F4xxAdc

[ADC2]
type = periperal
base = 0x40012100
class = STM32F4xxAdc

[ADC3]
type = periperal
base = 0x40012200
class = STM32F4xxAdc

[SDIO]
type = periperal
base = 0x40012c00
class = STM32F4xxSdio
intn = 49

[SPI1]
type = periperal
base = 0x40013000
class = STM32F4xxSpi
intn = 35

[SPI4]
type = periperal
base = 0x40013400
class = STM32F4xxSpi
intn = 84

[SYSCFG]
type = periperal
base = 0x40013800
class = STM32F4xxSyscfg

[EXTI]
type = periperal
base = 0x40013c00
class = STM32F4xxExti

[TIM9]
type = periperal
base = 0x40014000
class = STM32F4xxTim

[TIM10]
type = periperal
base = 0x40014400
class = STM32F4xxTim

[TIM11]
type = periperal
base = 0x40014800
class = STM32F4xxTim

[SPI5]
type = periperal
base = 0x40015000
class = STM32F4xxSpi
intn = 85

[SPI6]
type = periperal
base = 0x40015400
class = STM32F4xxSpi
intn = 86

[SAI1]
type = periperal
base = 0x40015800
class = STM32F4xxSai
intn = 87

[LTDC]
type = periperal
base = 0x40016800
class = STM32F4xxLtdc
intn = 88
er_intn = 89

[DSI]
type = periperal
base = 0x40016c00
class = STM32F4xxDsi
intn = 92

[GPIOA]
type = periperal
base = 0x40020000
class = STM32F4xxGpio

[GPIOB]
type = periperal
base = 0x40020400
class = STM32F4xxGpio

[GPIOC]
type = periperal
base = 0x40020800
class = STM32F4xxGpio

[GPIOD]
type = periperal
base = 0x40020c00
class = STM32F4xxGpio

[GPIOE]
type = periperal
base = 0x40021000
class = STM32F4xxGpio

[GPIOF]
type = periperal
base = 0x40021400
class = STM32F4xxGpio

[GPIOG]
type = periperal
base = 0x40021800
class = STM32F4xxGpio

[GPIOH]
type = periperal
base = 0x40021c00
class = STM32F4xxGpio

[GPIOI]
type = periperal
base = 0x40022000
class = STM32F4xxGpio

[GPIOJ]
type = periperal
base = 0x40022400
class = STM32F4xxGpio

[GPIOK]
type = periperal
base = 0x40022800
class = STM32F4xxGpio

[CRC]
type = periperal
base = 0x40023000
class = STM32F4xxCrc

[RCC]
type = periperal
base = 0x40023800
class = STM32F4xxRccV3
intn = 5

[DMA1]
type = periperal
base = 0x40026000
class = STM32F4xxDma
stream0_intn = 11
stream1_intn = 12
stream2_intn = 13
stream3_intn = 14
stream4_intn = 15
stream5_intn = 16
stream6_intn = 17
stream7_intn = 47

[DMA2]
type = periperal
base = 0x40026400
class = STM32F4xxDma
stream0_intn = 56
stream1_intn = 57
stream2_intn = 58
stream3_intn = 59
stream4_intn = 60
stream5_intn = 68
stream6_intn = 69
stream7_intn = 70

[ETH]
type = periperal
base = 0x40028000
class = STM32F4xxEth
intn = 61
wkup_intn = 62

[DMA2D]
type = periperal
base = 0x4002b000
class = STM32F4xxDma2d
intn = 90

[DCMI]
type = periperal
base = 0x50050000
class = STM32F4xxDcmi
intn = 78

[CRYP]
type = periperal
base = 0x50060000
class = STM32F4xxCryp
intn = 79

[HASH]
type = periperal
base = 0x50060400
class = STM32F4xxHash
rng_intn = 80

[RNG]
type = periperal
base = 0x50060800
class = STM32F4xxRng

[QUADSPI]
type = periperal
base = 0xa0001000
class = STM32F4xxQuadspi
intn = 91

[DBGMCU]
type = periperal
base = 0xe0042000
class = STM32F4xxDbgmcu

