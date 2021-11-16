#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from enum import IntEnum


class CTL0(IntEnum):
    CKDIV = 0x3 << 8   # Clock division
    ARSE  = 0x1 << 7   # Auto-reload shadow enable
    CAM   = 0x3 << 5   # Counter aligns mode selection
    DIR   = 0x1 << 4   # Direction
    SPM   = 0x1 << 3   # Single pulse mode
    UPS   = 0x1 << 2   # Update source
    UPDIS = 0x1 << 1   # Update disable
    CEN   = 0x1 << 0   # Counter enable

class CTL1(IntEnum):
    ISO3  = 0x1 << 14   # Idle state of channel 3 output
    ISO2N = 0x1 << 13   # Idle state of channel 2 complementary output
    ISO2  = 0x1 << 12   # Idle state of channel 2 output
    ISO1N = 0x1 << 11   # Idle state of channel 1 complementary output
    ISO1  = 0x1 << 10   # Idle state of channel 1 output
    ISO0N = 0x1 << 9    # Idle state of channel 0 complementary output
    ISO0  = 0x1 << 8    # Idle state of channel 0 output
    TI0S  = 0x1 << 7    # Channel 0 trigger input selection
    MMC   = 0x7 << 4    # Master mode control
    DMAS  = 0x1 << 3    # DMA request source selection
    CCUC  = 0x1 << 2    # Commutation control shadow register update control
    CCSE  = 0x1 << 0    # Commutation control shadow enable

class SMCFG(IntEnum):
    ETP   = 0x1 << 15   # External trigger polarity
    SMC1  = 0x1 << 14   # Part of SMC for enable External clock mode1
    ETPSC = 0x3 << 12   # External trigger prescaler
    ETFC  = 0xf << 8    # External trigger filter control
    MSM   = 0x1 << 7    # Master/Slave mode
    TRGS  = 0x7 << 4    # Trigger selection
    SMC   = 0x7 << 0    # Slave mode selection

class DMAINTEN(IntEnum):
    TRGDEN = 0x1 << 14   # Trigger DMA request enable
    CMTDEN = 0x1 << 13   # Commutation DMA request enable
    CH3DEN = 0x1 << 12   # Channel 3 capture/compare DMA request enable
    CH2DEN = 0x1 << 11   # Channel 2 capture/compare DMA request enable
    CH1DEN = 0x1 << 10   # Channel 1 capture/compare DMA request enable
    CH0DEN = 0x1 << 9    # Channel 0 capture/compare DMA request enable
    UPDEN  = 0x1 << 8    # Update DMA request enable
    BRKIE  = 0x1 << 7    # Break interrupt enable
    TRGIE  = 0x1 << 6    # Trigger interrupt enable
    CMTIE  = 0x1 << 5    # commutation interrupt enable
    CH3IE  = 0x1 << 4    # Channel 3 capture/compare interrupt enable
    CH2IE  = 0x1 << 3    # Channel 2 capture/compare interrupt enable
    CH1IE  = 0x1 << 2    # Channel 1 capture/compare interrupt enable
    CH0IE  = 0x1 << 1    # Channel 0 capture/compare interrupt enable
    UPIE   = 0x1 << 0    # Update interrupt enable

class INTF(IntEnum):
    CH3OF = 0x1 << 12   # Channel 3 over capture flag
    CH2OF = 0x1 << 11   # Channel 2 over capture flag
    CH1OF = 0x1 << 10   # Channel 1 over capture flag
    CH0OF = 0x1 << 9    # Channel 0 over capture flag
    BRKIF = 0x1 << 7    # Break interrupt flag
    TRGIF = 0x1 << 6    # Trigger interrupt flag
    CMTIF = 0x1 << 5    # Channel commutation interrupt flag
    CH3IF = 0x1 << 4    # Channel 3 capture/compare interrupt flag
    CH2IF = 0x1 << 3    # Channel 2 capture/compare interrupt flag
    CH1IF = 0x1 << 2    # Channel 1 capture/compare interrupt flag
    CH0IF = 0x1 << 1    # Channel 0 capture/compare interrupt flag
    UPIF  = 0x1 << 0    # Update interrupt flag

class SWEVG(IntEnum):
    BRKG = 0x1 << 7   # Break event generation
    TRGG = 0x1 << 6   # Trigger event generation
    CMTG = 0x1 << 5   # Channel commutation event generation
    CH3G = 0x1 << 4   # Channel 3 capture or compare event generation
    CH2G = 0x1 << 3   # Channel 2 capture or compare event generation
    CH1G = 0x1 << 2   # Channel 1 capture or compare event generation
    CH0G = 0x1 << 1   # Channel 0 capture or compare event generation
    UPG  = 0x1 << 0   # Update event generation

class CHCTL0_Output(IntEnum):
    CH1COMCEN = 0x1 << 15   # Channel 1 output compare clear enable
    CH1COMCTL = 0x7 << 12   # Channel 1 compare output control
    CH1COMSEN = 0x1 << 11   # Channel 1 output compare shadow enable
    CH1COMFEN = 0x1 << 10   # Channel 1 output compare fast enable
    CH1MS     = 0x3 << 8    # Channel 1 mode selection
    CH0COMCEN = 0x1 << 7    # Channel 0 output compare clear enable
    CH0COMCTL = 0x7 << 4    # Channel 0 compare output control
    CH0COMSEN = 0x1 << 3    # Channel 0 compare output shadow enable
    CH0COMFEN = 0x1 << 2    # Channel 0 output compare fast enable
    CH0MS     = 0x3 << 0    # Channel 0 I/O mode selection

class CHCTL0_Input(IntEnum):
    CH1CAPFLT = 0xf << 12   # Channel 1 input capture filter control
    CH1CAPPSC = 0x3 << 10   # Channel 1 input capture prescaler
    CH1MS     = 0x3 << 8    # Channel 1 mode selection
    CH0CAPFLT = 0xf << 4    # Channel 0 input capture filter control
    CH0CAPPSC = 0x3 << 2    # Channel 0 input capture prescaler
    CH0MS     = 0x3 << 0    # Channel 0 mode selection

class CHCTL1_Output(IntEnum):
    CH3COMCEN = 0x1 << 15   # Channel 3 output compare clear enable
    CH3COMCTL = 0x7 << 12   # Channel 3 compare output control
    CH3COMSEN = 0x1 << 11   # Channel 3 output compare shadow enable
    CH3COMFEN = 0x1 << 10   # Channel 3 output compare fast enable
    CH3MS     = 0x3 << 8    # Channel 3 mode selection
    CH2COMCEN = 0x1 << 7    # Channel 2 output compare clear enable
    CH2COMCTL = 0x7 << 4    # Channel 2 compare output control
    CH2COMSEN = 0x1 << 3    # Channel 2 compare output shadow enable
    CH2COMFEN = 0x1 << 2    # Channel 2 output compare fast enable
    CH2MS     = 0x3 << 0    # Channel 2 I/O mode selection

class CHCTL1_Input(IntEnum):
    CH3CAPFLT = 0xf << 12   # Channel 3 input capture filter control
    CH3CAPPSC = 0x3 << 10   # Channel 3 input capture prescaler
    CH3MS     = 0x3 << 8    # Channel 3 mode selection
    CH2CAPFLT = 0xf << 4    # Channel 2 input capture filter control
    CH2CAPPSC = 0x3 << 2    # Channel 2 input capture prescaler
    CH2MS     = 0x3 << 0    # Channel 2 mode selection

class CHCTL2(IntEnum):
    CH3P   = 0x1 << 13   # Channel 3 capture/compare function polarity
    CH3EN  = 0x1 << 12   # Channel 3 capture/compare function enable
    CH2NP  = 0x1 << 11   # Channel 2 complementary output polarity
    CH2NEN = 0x1 << 10   # Channel 2 complementary output enable
    CH2P   = 0x1 << 9    # Channel 2 capture/compare function polarity
    CH2EN  = 0x1 << 8    # Channel 2 capture/compare function enable
    CH1NP  = 0x1 << 7    # Channel 1 complementary output polarity
    CH1NEN = 0x1 << 6    # Channel 1 complementary output enable
    CH1P   = 0x1 << 5    # Channel 1 capture/compare function polarity
    CH1EN  = 0x1 << 4    # Channel 1 capture/compare function enable
    CH0NP  = 0x1 << 3    # Channel 0 complementary output polarity
    CH0NEN = 0x1 << 2    # Channel 0 complementary output enable
    CH0P   = 0x1 << 1    # Channel 0 capture/compare function polarity
    CH0EN  = 0x1 << 0    # Channel 0 capture/compare function enable

class CNT(IntEnum):
    CNT = 0xffff << 0   # current counter value

class PSC(IntEnum):
    PSC = 0xffff << 0   # Prescaler value of the counter clock

class CAR(IntEnum):
    CARL = 0xffff << 0   # Counter auto reload value

class CREP(IntEnum):
    CREP = 0xff << 0   # Counter repetition value

class CH0CV(IntEnum):
    CH0VAL = 0xffff << 0   # Capture or compare value of channel0

class CH1CV(IntEnum):
    CH1VAL = 0xffff << 0   # Capture or compare value of channel1

class CH2CV(IntEnum):
    CH2VAL = 0xffff << 0   # Capture or compare value of channel 2

class CH3CV(IntEnum):
    CH3VAL = 0xffff << 0   # Capture or compare value of channel 3

class CCHP(IntEnum):
    POEN  = 0x1 << 15   # Primary output enable
    OAEN  = 0x1 << 14   # Output automatic enable
    BRKP  = 0x1 << 13   # Break polarity
    BRKEN = 0x1 << 12   # Break enable
    ROS   = 0x1 << 11   # Run mode off-state configure
    IOS   = 0x1 << 10   # Idle mode off-state configure
    PROT  = 0x3 << 8    # Complementary register protect control
    DTCFG = 0xff << 0   # Dead time configure

class DMACFG(IntEnum):
    DMATC = 0x1f << 8   # DMA transfer count
    DMATA = 0x1f << 0   # DMA transfer access start address

class DMATB(IntEnum):
    DMATB = 0xffff << 0   # DMA transfer buffer

