#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class RCC_CR(IntEnum):
    HSION   = 1 << 0
    HSIRDY  = 1 << 1
    HSITRIM = 0x1F << 3
    HSICAL  = 0xFF << 8
    
    HSEON  = 1 << 16
    HSERDY = 1 << 17
    HSEBYP = 1 << 18
    CSSON  = 1 << 19

    PLLI2SRDY = 1 << 27
    PLLI2SON  = 1 << 26
    PLLRDY    = 1 << 25
    PLLON     = 1 << 24

    RW_MASK = HSION | HSITRIM | HSEON | HSEBYP | CSSON | PLLON | PLLI2SON
    RO_MASK = HSIRDY | HSICAL | HSERDY | PLLRDY | PLLI2SRDY


class RCC_PLLCFGR(IntEnum):
	PLLM       = 0x3f << 0
	PLLN       = 0x1ff << 6
	PLLP       = 0x3 << 16
	PLLSRC     = 1 << 22
	PLLSRC_HSE = 1 << 22
	PLLQ       = 0xf << 24


class RCC_CFGR(IntEnum):
    SW      = 0x3 << 0
    SW_0    = 1 << 0
    SW_1    = 1 << 1
    SWS     = 0x3 << 2
    SWS_0   = 1 << 2
    SWS_1   = 1 << 3
    HPRE    = 0xF << 4
    PPRE1   = 0x7 << 10
    PPRE2   = 0x7 << 13
    RTCPRE  = 0x1F << 16
    MCO1    = 0x3 << 21
    I2SSCR  = 1 << 23
    MCO1PRE = 0x3 << 24
    MCO2PRE = 0x3 << 27
    MCO2    = 0x3 << 30

    RO_MASK = SWS
    RW_MASK = SW | HPRE | PPRE1 | PPRE2 | MCO1 | I2SSCR | MCO1PRE | MCO2PRE | MCO2

class RCC_CIR(IntEnum):
	LSIRDYF     = 1 << 0
	LSERDYF     = 1 << 1
	HSIRDYF     = 1 << 2
	HSERDYF     = 1 << 3
	PLLRDYF     = 1 << 4
	PLLI2SRDYF  = 1 << 5
	CSSF        = 1 << 7
	LSIRDYIE    = 1 << 8
	LSERDYIE    = 1 << 9
	HSIRDYIE    = 1 << 10
	HSERDYIE    = 1 << 11
	PLLRDYIE    = 1 << 12
	PLLI2SRDYIE = 1 << 13
	LSIRDYC     = 1 << 16
	LSERDYC     = 1 << 17
	HSIRDYC     = 1 << 18
	HSERDYC     = 1 << 19
	PLLRDYC     = 1 << 20
	PLLI2SRDYC  = 1 << 21
	CSSC        = 1 << 23

class RCC_AHB1RSTR(IntEnum):
	GPIOARST = 1 << 0
	GPIOBRST = 1 << 1
	GPIOCRST = 1 << 2
	GPIODRST = 1 << 3
	GPIOERST = 1 << 4
	GPIOHRST = 1 << 7
	CRCRST   = 1 << 12
	DMA1RST  = 1 << 21
	DMA2RST  = 1 << 22

class RCC_AHB2RSTR(IntEnum):
	OTGFSRST = 1 << 7

class RCC_APB1RSTR(IntEnum):
	TIM2RST   = 1 << 0
	TIM3RST   = 1 << 1
	TIM4RST   = 1 << 2
	TIM5RST   = 1 << 3
	WWDGRST   = 1 << 11
	SPI2RST   = 1 << 14
	SPI3RST   = 1 << 15
	USART2RST = 1 << 17
	I2C1RST   = 1 << 21
	I2C2RST   = 1 << 22
	I2C3RST   = 1 << 23
	PWRRST    = 1 << 28

class RCC_APB2RSTR(IntEnum):
	TIM1RST   = 1 << 0
	USART1RST = 1 << 4
	USART6RST = 1 << 5
	ADCRST    = 1 << 8
	SDIORST   = 1 << 11
	SPI1RST   = 1 << 12
	SPI4RST   = 1 << 13
	SYSCFGRST = 1 << 14
	TIM9RST   = 1 << 16
	TIM10RST  = 1 << 17
	TIM11RST  = 1 << 18
	SPI5RST   = 1 << 20

class RCC_AHB1ENR(IntEnum):
	GPIOAEN = 1 << 0
	GPIOBEN = 1 << 1
	GPIOCEN = 1 << 2
	GPIODEN = 1 << 3
	GPIOEEN = 1 << 4
	GPIOHEN = 1 << 7
	CRCEN   = 1 << 12
	DMA1EN  = 1 << 21
	DMA2EN  = 1 << 22

class RCC_AHB2ENR(IntEnum):
	OTGFSEN = 1 << 7

class RCC_APB1ENR(IntEnum):
	TIM2EN   = 1 << 0
	TIM3EN   = 1 << 1
	TIM4EN   = 1 << 2
	TIM5EN   = 1 << 3
	WWDGEN   = 1 << 11
	SPI2EN   = 1 << 14
	SPI3EN   = 1 << 15
	USART2EN = 1 << 17
	I2C1EN   = 1 << 21
	I2C2EN   = 1 << 22
	I2C3EN   = 1 << 23
	PWREN    = 1 << 28

class RCC_APB2ENR(IntEnum):
	TIM1EN   = 1 << 0
	USART1EN = 1 << 4
	USART6EN = 1 << 5
	ADC1EN   = 1 << 8
	SDIOEN   = 1 << 11
	SPI1EN   = 1 << 12
	SPI4EN   = 1 << 13
	SYSCFGEN = 1 << 14
	TIM9EN   = 1 << 16
	TIM10EN  = 1 << 17
	TIM11EN  = 1 << 18
	SPI5EN   = 1 << 20

class RCC_AHB1LPENR(IntEnum):
	GPIOALPEN = 1 << 0
	GPIOBLPEN = 1 << 1
	GPIOCLPEN = 1 << 2
	GPIODLPEN = 1 << 3
	GPIOELPEN = 1 << 4
	GPIOHLPEN = 1 << 7
	CRCLPEN   = 1 << 12
	FLITFLPEN = 1 << 15
	SRAM1LPEN = 1 << 16
	DMA1LPEN  = 1 << 21
	DMA2LPEN  = 1 << 22

class RCC_AHB2LPENR(IntEnum):
	OTGFSLPEN = 1 << 7

class RCC_APB1LPENR(IntEnum):
	TIM2LPEN   = 1 << 0
	TIM3LPEN   = 1 << 1
	TIM4LPEN   = 1 << 2
	TIM5LPEN   = 1 << 3
	WWDGLPEN   = 1 << 11
	SPI2LPEN   = 1 << 14
	SPI3LPEN   = 1 << 15
	USART2LPEN = 1 << 17
	I2C1LPEN   = 1 << 21
	I2C2LPEN   = 1 << 22
	I2C3LPEN   = 1 << 23
	PWRLPEN    = 1 << 28

class RCC_APB2LPENR(IntEnum):
	TIM1LPEN   = 1 << 0
	USART1LPEN = 1 << 4
	USART6LPEN = 1 << 5
	ADC1LPEN   = 1 << 8
	SDIOLPEN   = 1 << 11
	SPI1LPEN   = 1 << 12
	SPI4LPEN   = 1 << 13
	SYSCFGLPEN = 1 << 14
	TIM9LPEN   = 1 << 16
	TIM10LPEN  = 1 << 17
	TIM11LPEN  = 1 << 18
	SPI5LPEN   = 1 << 20

class RCC_BDCR(IntEnum):
	LSEON  = 1 << 0
	LSERDY = 1 << 1
	LSEBYP = 1 << 2
	LSEMOD = 1 << 3
	RTCSEL = 0x3 << 8
	RTCEN  = 1 << 15
	BDRST  = 1 << 16

class RCC_CSR(IntEnum):
	LSION    = 1 << 0
	LSIRDY   = 1 << 1
	RMVF     = 1 << 24
	BORRSTF  = 1 << 25
	PINRSTF  = 1 << 26
	PORRSTF  = 1 << 27
	SFTRSTF  = 1 << 28
	IWDGRSTF = 1 << 29
	WWDGRSTF = 1 << 30
	LPWRRSTF = 1 << 31

class RCC_SSCGR(IntEnum):
	MODPER    = 0x1fff << 0
	INCSTEP   = 0x7fff << 13
	SPREADSEL = 1 << 30
	SSCGEN    = 1 << 31

class RCC_PLLI2SCFGR(IntEnum):
	PLLI2SM = 0x3f << 0
	PLLI2SN = 0x1ff << 6
	PLLI2SR = 0x7 << 28

class RCC_DCKCFGR(IntEnum):
	TIMPRE = 1 << 24
