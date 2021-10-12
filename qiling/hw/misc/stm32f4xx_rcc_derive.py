#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from .stm32f4xx_rcc import STM32F4xxRcc


class STM32F4xxRccV1(STM32F4xxRcc):
    class Type(ctypes.Structure):
        """ the structure available in :
			stm32f413xx.h
			stm32f412vx.h
			stm32f412rx.h
			stm32f423xx.h
			stm32f412zx.h 
		"""

        _fields_ = [
			('CR'        , ctypes.c_uint32),      # RCC clock control register,                                  Address offset: 0x00
			('PLLCFGR'   , ctypes.c_uint32),      # RCC PLL configuration register,                              Address offset: 0x04
			('CFGR'      , ctypes.c_uint32),      # RCC clock configuration register,                            Address offset: 0x08
			('CIR'       , ctypes.c_uint32),      # RCC clock interrupt register,                                Address offset: 0x0C
			('AHB1RSTR'  , ctypes.c_uint32),      # RCC AHB1 peripheral reset register,                          Address offset: 0x10
			('AHB2RSTR'  , ctypes.c_uint32),      # RCC AHB2 peripheral reset register,                          Address offset: 0x14
			('AHB3RSTR'  , ctypes.c_uint32),      # RCC AHB3 peripheral reset register,                          Address offset: 0x18
			('RESERVED0' , ctypes.c_uint32),      # Reserved, 0x1C
			('APB1RSTR'  , ctypes.c_uint32),      # RCC APB1 peripheral reset register,                          Address offset: 0x20
			('APB2RSTR'  , ctypes.c_uint32),      # RCC APB2 peripheral reset register,                          Address offset: 0x24
			('RESERVED1' , ctypes.c_uint32 * 2),  # Reserved, 0x28-0x2C
			('AHB1ENR'   , ctypes.c_uint32),      # RCC AHB1 peripheral clock register,                          Address offset: 0x30
			('AHB2ENR'   , ctypes.c_uint32),      # RCC AHB2 peripheral clock register,                          Address offset: 0x34
			('AHB3ENR'   , ctypes.c_uint32),      # RCC AHB3 peripheral clock register,                          Address offset: 0x38
			('RESERVED2' , ctypes.c_uint32),      # Reserved, 0x3C
			('APB1ENR'   , ctypes.c_uint32),      # RCC APB1 peripheral clock enable register,                   Address offset: 0x40
			('APB2ENR'   , ctypes.c_uint32),      # RCC APB2 peripheral clock enable register,                   Address offset: 0x44
			('RESERVED3' , ctypes.c_uint32 * 2),  # Reserved, 0x48-0x4C
			('AHB1LPENR' , ctypes.c_uint32),      # RCC AHB1 peripheral clock enable in low power mode register, Address offset: 0x50
			('AHB2LPENR' , ctypes.c_uint32),      # RCC AHB2 peripheral clock enable in low power mode register, Address offset: 0x54
			('AHB3LPENR' , ctypes.c_uint32),      # RCC AHB3 peripheral clock enable in low power mode register, Address offset: 0x58
			('RESERVED4' , ctypes.c_uint32),      # Reserved, 0x5C
			('APB1LPENR' , ctypes.c_uint32),      # RCC APB1 peripheral clock enable in low power mode register, Address offset: 0x60
			('APB2LPENR' , ctypes.c_uint32),      # RCC APB2 peripheral clock enable in low power mode register, Address offset: 0x64
			('RESERVED5' , ctypes.c_uint32 * 2),  # Reserved, 0x68-0x6C
			('BDCR'      , ctypes.c_uint32),      # RCC Backup domain control register,                          Address offset: 0x70
			('CSR'       , ctypes.c_uint32),      # RCC clock control & status register,                         Address offset: 0x74
			('RESERVED6' , ctypes.c_uint32 * 2),  # Reserved, 0x78-0x7C
			('SSCGR'     , ctypes.c_uint32),      # RCC spread spectrum clock generation register,               Address offset: 0x80
			('PLLI2SCFGR', ctypes.c_uint32),      # RCC PLLI2S configuration register,                           Address offset: 0x84
			('RESERVED7' , ctypes.c_uint32),      # Reserved, 0x84
			('DCKCFGR'   , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register,                 Address offset: 0x8C
			('CKGATENR'  , ctypes.c_uint32),      # RCC Clocks Gated ENable Register,                            Address offset: 0x90
			('DCKCFGR2'  , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register 2,               Address offset: 0x94
		]

class STM32F4xxRccV2(STM32F4xxRcc):
    class Type(ctypes.Structure):
        """ the structure available in :
			stm32f407xx.h
			stm32f415xx.h
			stm32f417xx.h
			stm32f405xx.h 
		"""

        _fields_ = [
			('CR'        , ctypes.c_uint32),      # RCC clock control register,                                  Address offset: 0x00
			('PLLCFGR'   , ctypes.c_uint32),      # RCC PLL configuration register,                              Address offset: 0x04
			('CFGR'      , ctypes.c_uint32),      # RCC clock configuration register,                            Address offset: 0x08
			('CIR'       , ctypes.c_uint32),      # RCC clock interrupt register,                                Address offset: 0x0C
			('AHB1RSTR'  , ctypes.c_uint32),      # RCC AHB1 peripheral reset register,                          Address offset: 0x10
			('AHB2RSTR'  , ctypes.c_uint32),      # RCC AHB2 peripheral reset register,                          Address offset: 0x14
			('AHB3RSTR'  , ctypes.c_uint32),      # RCC AHB3 peripheral reset register,                          Address offset: 0x18
			('RESERVED0' , ctypes.c_uint32),      # Reserved, 0x1C
			('APB1RSTR'  , ctypes.c_uint32),      # RCC APB1 peripheral reset register,                          Address offset: 0x20
			('APB2RSTR'  , ctypes.c_uint32),      # RCC APB2 peripheral reset register,                          Address offset: 0x24
			('RESERVED1' , ctypes.c_uint32 * 2),  # Reserved, 0x28-0x2C
			('AHB1ENR'   , ctypes.c_uint32),      # RCC AHB1 peripheral clock register,                          Address offset: 0x30
			('AHB2ENR'   , ctypes.c_uint32),      # RCC AHB2 peripheral clock register,                          Address offset: 0x34
			('AHB3ENR'   , ctypes.c_uint32),      # RCC AHB3 peripheral clock register,                          Address offset: 0x38
			('RESERVED2' , ctypes.c_uint32),      # Reserved, 0x3C
			('APB1ENR'   , ctypes.c_uint32),      # RCC APB1 peripheral clock enable register,                   Address offset: 0x40
			('APB2ENR'   , ctypes.c_uint32),      # RCC APB2 peripheral clock enable register,                   Address offset: 0x44
			('RESERVED3' , ctypes.c_uint32 * 2),  # Reserved, 0x48-0x4C
			('AHB1LPENR' , ctypes.c_uint32),      # RCC AHB1 peripheral clock enable in low power mode register, Address offset: 0x50
			('AHB2LPENR' , ctypes.c_uint32),      # RCC AHB2 peripheral clock enable in low power mode register, Address offset: 0x54
			('AHB3LPENR' , ctypes.c_uint32),      # RCC AHB3 peripheral clock enable in low power mode register, Address offset: 0x58
			('RESERVED4' , ctypes.c_uint32),      # Reserved, 0x5C
			('APB1LPENR' , ctypes.c_uint32),      # RCC APB1 peripheral clock enable in low power mode register, Address offset: 0x60
			('APB2LPENR' , ctypes.c_uint32),      # RCC APB2 peripheral clock enable in low power mode register, Address offset: 0x64
			('RESERVED5' , ctypes.c_uint32 * 2),  # Reserved, 0x68-0x6C
			('BDCR'      , ctypes.c_uint32),      # RCC Backup domain control register,                          Address offset: 0x70
			('CSR'       , ctypes.c_uint32),      # RCC clock control & status register,                         Address offset: 0x74
			('RESERVED6' , ctypes.c_uint32 * 2),  # Reserved, 0x78-0x7C
			('SSCGR'     , ctypes.c_uint32),      # RCC spread spectrum clock generation register,               Address offset: 0x80
			('PLLI2SCFGR', ctypes.c_uint32),      # RCC PLLI2S configuration register,                           Address offset: 0x84
		]

class STM32F4xxRccV3(STM32F4xxRcc):
    class Type(ctypes.Structure):
        """ the structure available in :
			stm32f469xx.h
			stm32f427xx.h
			stm32f439xx.h
			stm32f479xx.h
			stm32f429xx.h
			stm32f437xx.h 
		"""

        _fields_ = [
			('CR'        , ctypes.c_uint32),      # RCC clock control register,                                  Address offset: 0x00
			('PLLCFGR'   , ctypes.c_uint32),      # RCC PLL configuration register,                              Address offset: 0x04
			('CFGR'      , ctypes.c_uint32),      # RCC clock configuration register,                            Address offset: 0x08
			('CIR'       , ctypes.c_uint32),      # RCC clock interrupt register,                                Address offset: 0x0C
			('AHB1RSTR'  , ctypes.c_uint32),      # RCC AHB1 peripheral reset register,                          Address offset: 0x10
			('AHB2RSTR'  , ctypes.c_uint32),      # RCC AHB2 peripheral reset register,                          Address offset: 0x14
			('AHB3RSTR'  , ctypes.c_uint32),      # RCC AHB3 peripheral reset register,                          Address offset: 0x18
			('RESERVED0' , ctypes.c_uint32),      # Reserved, 0x1C
			('APB1RSTR'  , ctypes.c_uint32),      # RCC APB1 peripheral reset register,                          Address offset: 0x20
			('APB2RSTR'  , ctypes.c_uint32),      # RCC APB2 peripheral reset register,                          Address offset: 0x24
			('RESERVED1' , ctypes.c_uint32 * 2),  # Reserved, 0x28-0x2C
			('AHB1ENR'   , ctypes.c_uint32),      # RCC AHB1 peripheral clock register,                          Address offset: 0x30
			('AHB2ENR'   , ctypes.c_uint32),      # RCC AHB2 peripheral clock register,                          Address offset: 0x34
			('AHB3ENR'   , ctypes.c_uint32),      # RCC AHB3 peripheral clock register,                          Address offset: 0x38
			('RESERVED2' , ctypes.c_uint32),      # Reserved, 0x3C
			('APB1ENR'   , ctypes.c_uint32),      # RCC APB1 peripheral clock enable register,                   Address offset: 0x40
			('APB2ENR'   , ctypes.c_uint32),      # RCC APB2 peripheral clock enable register,                   Address offset: 0x44
			('RESERVED3' , ctypes.c_uint32 * 2),  # Reserved, 0x48-0x4C
			('AHB1LPENR' , ctypes.c_uint32),      # RCC AHB1 peripheral clock enable in low power mode register, Address offset: 0x50
			('AHB2LPENR' , ctypes.c_uint32),      # RCC AHB2 peripheral clock enable in low power mode register, Address offset: 0x54
			('AHB3LPENR' , ctypes.c_uint32),      # RCC AHB3 peripheral clock enable in low power mode register, Address offset: 0x58
			('RESERVED4' , ctypes.c_uint32),      # Reserved, 0x5C
			('APB1LPENR' , ctypes.c_uint32),      # RCC APB1 peripheral clock enable in low power mode register, Address offset: 0x60
			('APB2LPENR' , ctypes.c_uint32),      # RCC APB2 peripheral clock enable in low power mode register, Address offset: 0x64
			('RESERVED5' , ctypes.c_uint32 * 2),  # Reserved, 0x68-0x6C
			('BDCR'      , ctypes.c_uint32),      # RCC Backup domain control register,                          Address offset: 0x70
			('CSR'       , ctypes.c_uint32),      # RCC clock control & status register,                         Address offset: 0x74
			('RESERVED6' , ctypes.c_uint32 * 2),  # Reserved, 0x78-0x7C
			('SSCGR'     , ctypes.c_uint32),      # RCC spread spectrum clock generation register,               Address offset: 0x80
			('PLLI2SCFGR', ctypes.c_uint32),      # RCC PLLI2S configuration register,                           Address offset: 0x84
			('PLLSAICFGR', ctypes.c_uint32),      # RCC PLLSAI configuration register,                           Address offset: 0x88
			('DCKCFGR'   , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register,                 Address offset: 0x8C
		]

class STM32F446Rcc(STM32F4xxRcc):
    class Type(ctypes.Structure):
        """ the structure available in :
			stm32f446xx.h 
		"""

        _fields_ = [
			('CR'        , ctypes.c_uint32),      # RCC clock control register,                                  Address offset: 0x00
			('PLLCFGR'   , ctypes.c_uint32),      # RCC PLL configuration register,                              Address offset: 0x04
			('CFGR'      , ctypes.c_uint32),      # RCC clock configuration register,                            Address offset: 0x08
			('CIR'       , ctypes.c_uint32),      # RCC clock interrupt register,                                Address offset: 0x0C
			('AHB1RSTR'  , ctypes.c_uint32),      # RCC AHB1 peripheral reset register,                          Address offset: 0x10
			('AHB2RSTR'  , ctypes.c_uint32),      # RCC AHB2 peripheral reset register,                          Address offset: 0x14
			('AHB3RSTR'  , ctypes.c_uint32),      # RCC AHB3 peripheral reset register,                          Address offset: 0x18
			('RESERVED0' , ctypes.c_uint32),      # Reserved, 0x1C
			('APB1RSTR'  , ctypes.c_uint32),      # RCC APB1 peripheral reset register,                          Address offset: 0x20
			('APB2RSTR'  , ctypes.c_uint32),      # RCC APB2 peripheral reset register,                          Address offset: 0x24
			('RESERVED1' , ctypes.c_uint32 * 2),  # Reserved, 0x28-0x2C
			('AHB1ENR'   , ctypes.c_uint32),      # RCC AHB1 peripheral clock register,                          Address offset: 0x30
			('AHB2ENR'   , ctypes.c_uint32),      # RCC AHB2 peripheral clock register,                          Address offset: 0x34
			('AHB3ENR'   , ctypes.c_uint32),      # RCC AHB3 peripheral clock register,                          Address offset: 0x38
			('RESERVED2' , ctypes.c_uint32),      # Reserved, 0x3C
			('APB1ENR'   , ctypes.c_uint32),      # RCC APB1 peripheral clock enable register,                   Address offset: 0x40
			('APB2ENR'   , ctypes.c_uint32),      # RCC APB2 peripheral clock enable register,                   Address offset: 0x44
			('RESERVED3' , ctypes.c_uint32 * 2),  # Reserved, 0x48-0x4C
			('AHB1LPENR' , ctypes.c_uint32),      # RCC AHB1 peripheral clock enable in low power mode register, Address offset: 0x50
			('AHB2LPENR' , ctypes.c_uint32),      # RCC AHB2 peripheral clock enable in low power mode register, Address offset: 0x54
			('AHB3LPENR' , ctypes.c_uint32),      # RCC AHB3 peripheral clock enable in low power mode register, Address offset: 0x58
			('RESERVED4' , ctypes.c_uint32),      # Reserved, 0x5C
			('APB1LPENR' , ctypes.c_uint32),      # RCC APB1 peripheral clock enable in low power mode register, Address offset: 0x60
			('APB2LPENR' , ctypes.c_uint32),      # RCC APB2 peripheral clock enable in low power mode register, Address offset: 0x64
			('RESERVED5' , ctypes.c_uint32 * 2),  # Reserved, 0x68-0x6C
			('BDCR'      , ctypes.c_uint32),      # RCC Backup domain control register,                          Address offset: 0x70
			('CSR'       , ctypes.c_uint32),      # RCC clock control & status register,                         Address offset: 0x74
			('RESERVED6' , ctypes.c_uint32 * 2),  # Reserved, 0x78-0x7C
			('SSCGR'     , ctypes.c_uint32),      # RCC spread spectrum clock generation register,               Address offset: 0x80
			('PLLI2SCFGR', ctypes.c_uint32),      # RCC PLLI2S configuration register,                           Address offset: 0x84
			('PLLSAICFGR', ctypes.c_uint32),      # RCC PLLSAI configuration register,                           Address offset: 0x88
			('DCKCFGR'   , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register,                 Address offset: 0x8C
			('CKGATENR'  , ctypes.c_uint32),      # RCC Clocks Gated ENable Register,                            Address offset: 0x90
			('DCKCFGR2'  , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register 2,               Address offset: 0x94
		]

    class Type(ctypes.Structure):
        """ the structure available in :
			stm32f469xx.h
			stm32f427xx.h
			stm32f439xx.h
			stm32f479xx.h
			stm32f429xx.h
			stm32f437xx.h 
		"""

        _fields_ = [
			('CR'        , ctypes.c_uint32),      # RCC clock control register,                                  Address offset: 0x00
			('PLLCFGR'   , ctypes.c_uint32),      # RCC PLL configuration register,                              Address offset: 0x04
			('CFGR'      , ctypes.c_uint32),      # RCC clock configuration register,                            Address offset: 0x08
			('CIR'       , ctypes.c_uint32),      # RCC clock interrupt register,                                Address offset: 0x0C
			('AHB1RSTR'  , ctypes.c_uint32),      # RCC AHB1 peripheral reset register,                          Address offset: 0x10
			('AHB2RSTR'  , ctypes.c_uint32),      # RCC AHB2 peripheral reset register,                          Address offset: 0x14
			('AHB3RSTR'  , ctypes.c_uint32),      # RCC AHB3 peripheral reset register,                          Address offset: 0x18
			('RESERVED0' , ctypes.c_uint32),      # Reserved, 0x1C
			('APB1RSTR'  , ctypes.c_uint32),      # RCC APB1 peripheral reset register,                          Address offset: 0x20
			('APB2RSTR'  , ctypes.c_uint32),      # RCC APB2 peripheral reset register,                          Address offset: 0x24
			('RESERVED1' , ctypes.c_uint32 * 2),  # Reserved, 0x28-0x2C
			('AHB1ENR'   , ctypes.c_uint32),      # RCC AHB1 peripheral clock register,                          Address offset: 0x30
			('AHB2ENR'   , ctypes.c_uint32),      # RCC AHB2 peripheral clock register,                          Address offset: 0x34
			('AHB3ENR'   , ctypes.c_uint32),      # RCC AHB3 peripheral clock register,                          Address offset: 0x38
			('RESERVED2' , ctypes.c_uint32),      # Reserved, 0x3C
			('APB1ENR'   , ctypes.c_uint32),      # RCC APB1 peripheral clock enable register,                   Address offset: 0x40
			('APB2ENR'   , ctypes.c_uint32),      # RCC APB2 peripheral clock enable register,                   Address offset: 0x44
			('RESERVED3' , ctypes.c_uint32 * 2),  # Reserved, 0x48-0x4C
			('AHB1LPENR' , ctypes.c_uint32),      # RCC AHB1 peripheral clock enable in low power mode register, Address offset: 0x50
			('AHB2LPENR' , ctypes.c_uint32),      # RCC AHB2 peripheral clock enable in low power mode register, Address offset: 0x54
			('AHB3LPENR' , ctypes.c_uint32),      # RCC AHB3 peripheral clock enable in low power mode register, Address offset: 0x58
			('RESERVED4' , ctypes.c_uint32),      # Reserved, 0x5C
			('APB1LPENR' , ctypes.c_uint32),      # RCC APB1 peripheral clock enable in low power mode register, Address offset: 0x60
			('APB2LPENR' , ctypes.c_uint32),      # RCC APB2 peripheral clock enable in low power mode register, Address offset: 0x64
			('RESERVED5' , ctypes.c_uint32 * 2),  # Reserved, 0x68-0x6C
			('BDCR'      , ctypes.c_uint32),      # RCC Backup domain control register,                          Address offset: 0x70
			('CSR'       , ctypes.c_uint32),      # RCC clock control & status register,                         Address offset: 0x74
			('RESERVED6' , ctypes.c_uint32 * 2),  # Reserved, 0x78-0x7C
			('SSCGR'     , ctypes.c_uint32),      # RCC spread spectrum clock generation register,               Address offset: 0x80
			('PLLI2SCFGR', ctypes.c_uint32),      # RCC PLLI2S configuration register,                           Address offset: 0x84
			('PLLSAICFGR', ctypes.c_uint32),      # RCC PLLSAI configuration register,                           Address offset: 0x88
			('DCKCFGR'   , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register,                 Address offset: 0x8C
		]

class STM32F412Rcc(STM32F4xxRcc):
    class Type(ctypes.Structure):
        """ the structure available in :
			stm32f412cx.h 
		"""

        _fields_ = [
			('CR'        , ctypes.c_uint32),      # RCC clock control register,                                  Address offset: 0x00
			('PLLCFGR'   , ctypes.c_uint32),      # RCC PLL configuration register,                              Address offset: 0x04
			('CFGR'      , ctypes.c_uint32),      # RCC clock configuration register,                            Address offset: 0x08
			('CIR'       , ctypes.c_uint32),      # RCC clock interrupt register,                                Address offset: 0x0C
			('AHB1RSTR'  , ctypes.c_uint32),      # RCC AHB1 peripheral reset register,                          Address offset: 0x10
			('AHB2RSTR'  , ctypes.c_uint32),      # RCC AHB2 peripheral reset register,                          Address offset: 0x14
			('RESERVED0' , ctypes.c_uint32 * 2),  # Reserved, 0x18-0x1C
			('APB1RSTR'  , ctypes.c_uint32),      # RCC APB1 peripheral reset register,                          Address offset: 0x20
			('APB2RSTR'  , ctypes.c_uint32),      # RCC APB2 peripheral reset register,                          Address offset: 0x24
			('RESERVED1' , ctypes.c_uint32 * 2),  # Reserved, 0x28-0x2C
			('AHB1ENR'   , ctypes.c_uint32),      # RCC AHB1 peripheral clock register,                          Address offset: 0x30
			('AHB2ENR'   , ctypes.c_uint32),      # RCC AHB2 peripheral clock register,                          Address offset: 0x34
			('RESERVED2' , ctypes.c_uint32 * 2),  # Reserved, 0x38-0x3C
			('APB1ENR'   , ctypes.c_uint32),      # RCC APB1 peripheral clock enable register,                   Address offset: 0x40
			('APB2ENR'   , ctypes.c_uint32),      # RCC APB2 peripheral clock enable register,                   Address offset: 0x44
			('RESERVED3' , ctypes.c_uint32 * 2),  # Reserved, 0x48-0x4C
			('AHB1LPENR' , ctypes.c_uint32),      # RCC AHB1 peripheral clock enable in low power mode register, Address offset: 0x50
			('AHB2LPENR' , ctypes.c_uint32),      # RCC AHB2 peripheral clock enable in low power mode register, Address offset: 0x54
			('RESERVED4' , ctypes.c_uint32 * 2),  # Reserved, 0x58-0x5C
			('APB1LPENR' , ctypes.c_uint32),      # RCC APB1 peripheral clock enable in low power mode register, Address offset: 0x60
			('APB2LPENR' , ctypes.c_uint32),      # RCC APB2 peripheral clock enable in low power mode register, Address offset: 0x64
			('RESERVED5' , ctypes.c_uint32 * 2),  # Reserved, 0x68-0x6C
			('BDCR'      , ctypes.c_uint32),      # RCC Backup domain control register,                          Address offset: 0x70
			('CSR'       , ctypes.c_uint32),      # RCC clock control & status register,                         Address offset: 0x74
			('RESERVED6' , ctypes.c_uint32 * 2),  # Reserved, 0x78-0x7C
			('SSCGR'     , ctypes.c_uint32),      # RCC spread spectrum clock generation register,               Address offset: 0x80
			('PLLI2SCFGR', ctypes.c_uint32),      # RCC PLLI2S configuration register,                           Address offset: 0x84
			('RESERVED7' , ctypes.c_uint32),      # Reserved, 0x88
			('DCKCFGR'   , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register,                 Address offset: 0x8C
			('CKGATENR'  , ctypes.c_uint32),      # RCC Clocks Gated ENable Register,                           Address offset: 0x90
			('DCKCFGR2'  , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register 2,               Address offset: 0x94
		]
