#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from enum import IntEnum


class CTL(IntEnum):
    IRC8MEN    = 0x1 << 0    # Internal 8MHz RC oscillator Enable
    IRC8MSTB   = 0x1 << 1    # IRC8M Internal 8MHz RC Oscillator stabilization Flag
    IRC8MADJ   = 0x1f << 3   # Internal 8MHz RC Oscillator clock trim adjust value
    IRC8MCALIB = 0xff << 8   # Internal 8MHz RC Oscillator calibration value register
    HXTALEN    = 0x1 << 16   # External High Speed oscillator Enable
    HXTALSTB   = 0x1 << 17   # External crystal oscillator (HXTAL) clock stabilization flag
    HXTALBPS   = 0x1 << 18   # External crystal oscillator (HXTAL) clock bypass mode enable
    CKMEN      = 0x1 << 19   # HXTAL Clock Monitor Enable
    PLLEN      = 0x1 << 24   # PLL enable
    PLLSTB     = 0x1 << 25   # PLL Clock Stabilization Flag
    PLL1EN     = 0x1 << 26   # PLL1 enable
    PLL1STB    = 0x1 << 27   # PLL1 Clock Stabilization Flag
    PLL2EN     = 0x1 << 28   # PLL2 enable
    PLL2STB    = 0x1 << 29   # PLL2 Clock Stabilization Flag

class CFG0(IntEnum):
    SCS        = 0x3 << 0    # System clock switch
    SCSS       = 0x3 << 2    # System clock switch status
    AHBPSC     = 0xf << 4    # AHB prescaler selection
    APB1PSC    = 0x7 << 8    # APB1 prescaler selection
    APB2PSC    = 0x7 << 11   # APB2 prescaler selection
    ADCPSC_1_0 = 0x3 << 14   # ADC clock prescaler selection
    PLLSEL     = 0x1 << 16   # PLL Clock Source Selection
    PREDV0_LSB = 0x1 << 17   # The LSB of PREDV0 division factor
    PLLMF_3_0  = 0xf << 18   # The PLL clock multiplication factor
    USBFSPSC   = 0x3 << 22   # USBFS clock prescaler selection
    CKOUT0SEL  = 0xf << 24   # CKOUT0 Clock Source Selection
    ADCPSC_2   = 0x1 << 28   # Bit 2 of ADCPSC
    PLLMF_4    = 0x1 << 29   # Bit 4 of PLLMF

class INT(IntEnum):
    IRC40KSTBIF = 0x1 << 0    # IRC40K stabilization interrupt flag
    LXTALSTBIF  = 0x1 << 1    # LXTAL stabilization interrupt flag
    IRC8MSTBIF  = 0x1 << 2    # IRC8M stabilization interrupt flag
    HXTALSTBIF  = 0x1 << 3    # HXTAL stabilization interrupt flag
    PLLSTBIF    = 0x1 << 4    # PLL stabilization interrupt flag
    PLL1STBIF   = 0x1 << 5    # PLL1 stabilization interrupt flag
    PLL2STBIF   = 0x1 << 6    # PLL2 stabilization interrupt flag
    CKMIF       = 0x1 << 7    # HXTAL Clock Stuck Interrupt Flag
    IRC40KSTBIE = 0x1 << 8    # IRC40K Stabilization interrupt enable
    LXTALSTBIE  = 0x1 << 9    # LXTAL Stabilization Interrupt Enable
    IRC8MSTBIE  = 0x1 << 10   # IRC8M Stabilization Interrupt Enable
    HXTALSTBIE  = 0x1 << 11   # HXTAL Stabilization Interrupt Enable
    PLLSTBIE    = 0x1 << 12   # PLL Stabilization Interrupt Enable
    PLL1STBIE   = 0x1 << 13   # PLL1 Stabilization Interrupt Enable
    PLL2STBIE   = 0x1 << 14   # PLL2 Stabilization Interrupt Enable
    IRC40KSTBIC = 0x1 << 16   # IRC40K Stabilization Interrupt Clear
    LXTALSTBIC  = 0x1 << 17   # LXTAL Stabilization Interrupt Clear
    IRC8MSTBIC  = 0x1 << 18   # IRC8M Stabilization Interrupt Clear
    HXTALSTBIC  = 0x1 << 19   # HXTAL Stabilization Interrupt Clear
    PLLSTBIC    = 0x1 << 20   # PLL stabilization Interrupt Clear
    PLL1STBIC   = 0x1 << 21   # PLL1 stabilization Interrupt Clear
    PLL2STBIC   = 0x1 << 22   # PLL2 stabilization Interrupt Clear
    CKMIC       = 0x1 << 23   # HXTAL Clock Stuck Interrupt Clear

class APB2RST(IntEnum):
    AFRST     = 0x1 << 0    # Alternate function I/O reset
    PARST     = 0x1 << 2    # GPIO port A reset
    PBRST     = 0x1 << 3    # GPIO port B reset
    PCRST     = 0x1 << 4    # GPIO port C reset
    PDRST     = 0x1 << 5    # GPIO port D reset
    PERST     = 0x1 << 6    # GPIO port E reset
    ADC0RST   = 0x1 << 9    # ADC0 reset
    ADC1RST   = 0x1 << 10   # ADC1 reset
    TIMER0RST = 0x1 << 11   # Timer 0 reset
    SPI0RST   = 0x1 << 12   # SPI0 reset
    USART0RST = 0x1 << 14   # USART0 Reset

class APB1RST(IntEnum):
    TIMER1RST = 0x1 << 0    # TIMER1 timer reset
    TIMER2RST = 0x1 << 1    # TIMER2 timer reset
    TIMER3RST = 0x1 << 2    # TIMER3 timer reset
    TIMER4RST = 0x1 << 3    # TIMER4 timer reset
    TIMER5RST = 0x1 << 4    # TIMER5 timer reset
    TIMER6RST = 0x1 << 5    # TIMER6 timer reset
    WWDGTRST  = 0x1 << 11   # Window watchdog timer reset
    SPI1RST   = 0x1 << 14   # SPI1 reset
    SPI2RST   = 0x1 << 15   # SPI2 reset
    USART1RST = 0x1 << 17   # USART1 reset
    USART2RST = 0x1 << 18   # USART2 reset
    UART3RST  = 0x1 << 19   # UART3 reset
    UART4RST  = 0x1 << 20   # UART4 reset
    I2C0RST   = 0x1 << 21   # I2C0 reset
    I2C1RST   = 0x1 << 22   # I2C1 reset
    CAN0RST   = 0x1 << 25   # CAN0 reset
    CAN1RST   = 0x1 << 26   # CAN1 reset
    BKPIRST   = 0x1 << 27   # Backup interface reset
    PMURST    = 0x1 << 28   # Power control reset
    DACRST    = 0x1 << 29   # DAC reset

class AHBEN(IntEnum):
    DMA0EN   = 0x1 << 0    # DMA0 clock enable
    DMA1EN   = 0x1 << 1    # DMA1 clock enable
    SRAMSPEN = 0x1 << 2    # SRAM interface clock enable when sleep mode
    FMCSPEN  = 0x1 << 4    # FMC clock enable when sleep mode
    CRCEN    = 0x1 << 6    # CRC clock enable
    EXMCEN   = 0x1 << 8    # EXMC clock enable
    USBFSEN  = 0x1 << 12   # USBFS clock enable

class APB2EN(IntEnum):
    AFEN     = 0x1 << 0    # Alternate function IO clock enable
    PAEN     = 0x1 << 2    # GPIO port A clock enable
    PBEN     = 0x1 << 3    # GPIO port B clock enable
    PCEN     = 0x1 << 4    # GPIO port C clock enable
    PDEN     = 0x1 << 5    # GPIO port D clock enable
    PEEN     = 0x1 << 6    # GPIO port E clock enable
    ADC0EN   = 0x1 << 9    # ADC0 clock enable
    ADC1EN   = 0x1 << 10   # ADC1 clock enable
    TIMER0EN = 0x1 << 11   # TIMER0 clock enable
    SPI0EN   = 0x1 << 12   # SPI0 clock enable
    USART0EN = 0x1 << 14   # USART0 clock enable

class APB1EN(IntEnum):
    TIMER1EN = 0x1 << 0    # TIMER1 timer clock enable
    TIMER2EN = 0x1 << 1    # TIMER2 timer clock enable
    TIMER3EN = 0x1 << 2    # TIMER3 timer clock enable
    TIMER4EN = 0x1 << 3    # TIMER4 timer clock enable
    TIMER5EN = 0x1 << 4    # TIMER5 timer clock enable
    TIMER6EN = 0x1 << 5    # TIMER6 timer clock enable
    WWDGTEN  = 0x1 << 11   # Window watchdog timer clock enable
    SPI1EN   = 0x1 << 14   # SPI1 clock enable
    SPI2EN   = 0x1 << 15   # SPI2 clock enable
    USART1EN = 0x1 << 17   # USART1 clock enable
    USART2EN = 0x1 << 18   # USART2 clock enable
    UART3EN  = 0x1 << 19   # UART3 clock enable
    UART4EN  = 0x1 << 20   # UART4 clock enable
    I2C0EN   = 0x1 << 21   # I2C0 clock enable
    I2C1EN   = 0x1 << 22   # I2C1 clock enable
    CAN0EN   = 0x1 << 25   # CAN0 clock enable
    CAN1EN   = 0x1 << 26   # CAN1 clock enable
    BKPIEN   = 0x1 << 27   # Backup interface clock enable
    PMUEN    = 0x1 << 28   # Power control clock enable
    DACEN    = 0x1 << 29   # DAC clock enable

class BDCTL(IntEnum):
    LXTALEN  = 0x1 << 0    # LXTAL enable
    LXTALSTB = 0x1 << 1    # External low-speed oscillator stabilization
    LXTALBPS = 0x1 << 2    # LXTAL bypass mode enable
    RTCSRC   = 0x3 << 8    # RTC clock entry selection
    RTCEN    = 0x1 << 15   # RTC clock enable
    BKPRST   = 0x1 << 16   # Backup domain reset

class RSTSCK(IntEnum):
    IRC40KEN  = 0x1 << 0    # IRC40K enable
    IRC40KSTB = 0x1 << 1    # IRC40K stabilization
    RSTFC     = 0x1 << 24   # Reset flag clear
    EPRSTF    = 0x1 << 26   # External PIN reset flag
    PORRSTF   = 0x1 << 27   # Power reset flag
    SWRSTF    = 0x1 << 28   # Software reset flag
    FWDGTRSTF = 0x1 << 29   # Free Watchdog timer reset flag
    WWDGTRSTF = 0x1 << 30   # Window watchdog timer reset flag
    LPRSTF    = 0x1 << 31   # Low-power reset flag

class AHBRST(IntEnum):
    USBFSRST = 0x1 << 12   # USBFS reset

class CFG1(IntEnum):
    PREDV0    = 0xf << 0    # PREDV0 division factor
    PREDV1    = 0xf << 4    # PREDV1 division factor
    PLL1MF    = 0xf << 8    # The PLL1 clock multiplication factor
    PLL2MF    = 0xf << 12   # The PLL2 clock multiplication factor
    PREDV0SEL = 0x1 << 16   # PREDV0 input Clock Source Selection
    I2S1SEL   = 0x1 << 17   # I2S1 Clock Source Selection
    I2S2SEL   = 0x1 << 18   # I2S2 Clock Source Selection

class DSV(IntEnum):
    DSLPVS = 0x3 << 0   # Deep-sleep mode voltage select

