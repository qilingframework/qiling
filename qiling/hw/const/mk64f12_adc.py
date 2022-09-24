#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class SC1(IntEnum):
    ADCH = 0x1f << 0   # Input channel select
    DIFF = 0x1 << 5    # Differential Mode Enable
    AIEN = 0x1 << 6    # Interrupt Enable
    COCO = 0x1 << 7    # Conversion Complete Flag

class CFG1(IntEnum):
    ADICLK = 0x3 << 0   # Input Clock Select
    MODE   = 0x3 << 2   # Conversion mode selection
    ADLSMP = 0x1 << 4   # Sample Time Configuration
    ADIV   = 0x3 << 5   # Clock Divide Select
    ADLPC  = 0x1 << 7   # Low-Power Configuration

class CFG2(IntEnum):
    ADLSTS  = 0x3 << 0   # Long Sample Time Select
    ADHSC   = 0x1 << 2   # High-Speed Configuration
    ADACKEN = 0x1 << 3   # Asynchronous Clock Output Enable
    MUXSEL  = 0x1 << 4   # ADC Mux Select

class SC2(IntEnum):
    REFSEL = 0x3 << 0   # Voltage Reference Selection
    DMAEN  = 0x1 << 2   # DMA Enable
    ACREN  = 0x1 << 3   # Compare Function Range Enable
    ACFGT  = 0x1 << 4   # Compare Function Greater Than Enable
    ACFE   = 0x1 << 5   # Compare Function Enable
    ADTRG  = 0x1 << 6   # Conversion Trigger Select
    ADACT  = 0x1 << 7   # Conversion Active

class SC3(IntEnum):
    AVGS = 0x3 << 0   # Hardware Average Select
    AVGE = 0x1 << 2   # Hardware Average Enable
    ADCO = 0x1 << 3   # Continuous Conversion Enable
    CALF = 0x1 << 6   # Calibration Failed Flag
    CAL  = 0x1 << 7   # Calibration
