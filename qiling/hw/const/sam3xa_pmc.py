#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class SCER(IntEnum):
    UOTGCLK = 0x1 << 5    # Enable USB OTG Clock (48 MHz, USB_48M) for UTMI
    PCK0    = 0x1 << 8    # Programmable Clock 0 Output Enable
    PCK1    = 0x1 << 9    # Programmable Clock 1 Output Enable
    PCK2    = 0x1 << 10   # Programmable Clock 2 Output Enable

class SCDR(IntEnum):
    UOTGCLK = 0x1 << 5    # Disable USB OTG Clock (48 MHz, USB_48M) for UTMI
    PCK0    = 0x1 << 8    # Programmable Clock 0 Output Disable
    PCK1    = 0x1 << 9    # Programmable Clock 1 Output Disable
    PCK2    = 0x1 << 10   # Programmable Clock 2 Output Disable

class SCSR(IntEnum):
    UOTGCLK = 0x1 << 5    # USB OTG Clock (48 MHz, USB_48M) Clock Status
    PCK0    = 0x1 << 8    # Programmable Clock 0 Output Status
    PCK1    = 0x1 << 9    # Programmable Clock 1 Output Status
    PCK2    = 0x1 << 10   # Programmable Clock 2 Output Status

class PCER0(IntEnum):
    PID2  = 0x1 << 2    # Peripheral Clock 2 Enable
    PID3  = 0x1 << 3    # Peripheral Clock 3 Enable
    PID4  = 0x1 << 4    # Peripheral Clock 4 Enable
    PID5  = 0x1 << 5    # Peripheral Clock 5 Enable
    PID6  = 0x1 << 6    # Peripheral Clock 6 Enable
    PID7  = 0x1 << 7    # Peripheral Clock 7 Enable
    PID8  = 0x1 << 8    # Peripheral Clock 8 Enable
    PID9  = 0x1 << 9    # Peripheral Clock 9 Enable
    PID10 = 0x1 << 10   # Peripheral Clock 10 Enable
    PID11 = 0x1 << 11   # Peripheral Clock 11 Enable
    PID12 = 0x1 << 12   # Peripheral Clock 12 Enable
    PID13 = 0x1 << 13   # Peripheral Clock 13 Enable
    PID14 = 0x1 << 14   # Peripheral Clock 14 Enable
    PID15 = 0x1 << 15   # Peripheral Clock 15 Enable
    PID16 = 0x1 << 16   # Peripheral Clock 16 Enable
    PID17 = 0x1 << 17   # Peripheral Clock 17 Enable
    PID18 = 0x1 << 18   # Peripheral Clock 18 Enable
    PID19 = 0x1 << 19   # Peripheral Clock 19 Enable
    PID20 = 0x1 << 20   # Peripheral Clock 20 Enable
    PID21 = 0x1 << 21   # Peripheral Clock 21 Enable
    PID22 = 0x1 << 22   # Peripheral Clock 22 Enable
    PID23 = 0x1 << 23   # Peripheral Clock 23 Enable
    PID24 = 0x1 << 24   # Peripheral Clock 24 Enable
    PID25 = 0x1 << 25   # Peripheral Clock 25 Enable
    PID26 = 0x1 << 26   # Peripheral Clock 26 Enable
    PID27 = 0x1 << 27   # Peripheral Clock 27 Enable
    PID28 = 0x1 << 28   # Peripheral Clock 28 Enable
    PID29 = 0x1 << 29   # Peripheral Clock 29 Enable
    PID30 = 0x1 << 30   # Peripheral Clock 30 Enable
    PID31 = 0x1 << 31   # Peripheral Clock 31 Enable

class PCDR0(IntEnum):
    PID2  = 0x1 << 2    # Peripheral Clock 2 Disable
    PID3  = 0x1 << 3    # Peripheral Clock 3 Disable
    PID4  = 0x1 << 4    # Peripheral Clock 4 Disable
    PID5  = 0x1 << 5    # Peripheral Clock 5 Disable
    PID6  = 0x1 << 6    # Peripheral Clock 6 Disable
    PID7  = 0x1 << 7    # Peripheral Clock 7 Disable
    PID8  = 0x1 << 8    # Peripheral Clock 8 Disable
    PID9  = 0x1 << 9    # Peripheral Clock 9 Disable
    PID10 = 0x1 << 10   # Peripheral Clock 10 Disable
    PID11 = 0x1 << 11   # Peripheral Clock 11 Disable
    PID12 = 0x1 << 12   # Peripheral Clock 12 Disable
    PID13 = 0x1 << 13   # Peripheral Clock 13 Disable
    PID14 = 0x1 << 14   # Peripheral Clock 14 Disable
    PID15 = 0x1 << 15   # Peripheral Clock 15 Disable
    PID16 = 0x1 << 16   # Peripheral Clock 16 Disable
    PID17 = 0x1 << 17   # Peripheral Clock 17 Disable
    PID18 = 0x1 << 18   # Peripheral Clock 18 Disable
    PID19 = 0x1 << 19   # Peripheral Clock 19 Disable
    PID20 = 0x1 << 20   # Peripheral Clock 20 Disable
    PID21 = 0x1 << 21   # Peripheral Clock 21 Disable
    PID22 = 0x1 << 22   # Peripheral Clock 22 Disable
    PID23 = 0x1 << 23   # Peripheral Clock 23 Disable
    PID24 = 0x1 << 24   # Peripheral Clock 24 Disable
    PID25 = 0x1 << 25   # Peripheral Clock 25 Disable
    PID26 = 0x1 << 26   # Peripheral Clock 26 Disable
    PID27 = 0x1 << 27   # Peripheral Clock 27 Disable
    PID28 = 0x1 << 28   # Peripheral Clock 28 Disable
    PID29 = 0x1 << 29   # Peripheral Clock 29 Disable
    PID30 = 0x1 << 30   # Peripheral Clock 30 Disable
    PID31 = 0x1 << 31   # Peripheral Clock 31 Disable

class PCSR0(IntEnum):
    PID2  = 0x1 << 2    # Peripheral Clock 2 Status
    PID3  = 0x1 << 3    # Peripheral Clock 3 Status
    PID4  = 0x1 << 4    # Peripheral Clock 4 Status
    PID5  = 0x1 << 5    # Peripheral Clock 5 Status
    PID6  = 0x1 << 6    # Peripheral Clock 6 Status
    PID7  = 0x1 << 7    # Peripheral Clock 7 Status
    PID8  = 0x1 << 8    # Peripheral Clock 8 Status
    PID9  = 0x1 << 9    # Peripheral Clock 9 Status
    PID10 = 0x1 << 10   # Peripheral Clock 10 Status
    PID11 = 0x1 << 11   # Peripheral Clock 11 Status
    PID12 = 0x1 << 12   # Peripheral Clock 12 Status
    PID13 = 0x1 << 13   # Peripheral Clock 13 Status
    PID14 = 0x1 << 14   # Peripheral Clock 14 Status
    PID15 = 0x1 << 15   # Peripheral Clock 15 Status
    PID16 = 0x1 << 16   # Peripheral Clock 16 Status
    PID17 = 0x1 << 17   # Peripheral Clock 17 Status
    PID18 = 0x1 << 18   # Peripheral Clock 18 Status
    PID19 = 0x1 << 19   # Peripheral Clock 19 Status
    PID20 = 0x1 << 20   # Peripheral Clock 20 Status
    PID21 = 0x1 << 21   # Peripheral Clock 21 Status
    PID22 = 0x1 << 22   # Peripheral Clock 22 Status
    PID23 = 0x1 << 23   # Peripheral Clock 23 Status
    PID24 = 0x1 << 24   # Peripheral Clock 24 Status
    PID25 = 0x1 << 25   # Peripheral Clock 25 Status
    PID26 = 0x1 << 26   # Peripheral Clock 26 Status
    PID27 = 0x1 << 27   # Peripheral Clock 27 Status
    PID28 = 0x1 << 28   # Peripheral Clock 28 Status
    PID29 = 0x1 << 29   # Peripheral Clock 29 Status
    PID30 = 0x1 << 30   # Peripheral Clock 30 Status
    PID31 = 0x1 << 31   # Peripheral Clock 31 Status

class CKGR_UCKR(IntEnum):
    UPLLEN    = 0x1 << 16   # UTMI PLL Enable
    UPLLCOUNT = 0xf << 20   # UTMI PLL Start-up Time

class CKGR_MOR(IntEnum):
    MOSCXTEN = 0x1 << 0     # Main Crystal Oscillator Enable
    MOSCXTBY = 0x1 << 1     # Main Crystal Oscillator Bypass
    MOSCRCEN = 0x1 << 3     # Main On-Chip RC Oscillator Enable
    MOSCRCF  = 0x7 << 4     # Main On-Chip RC Oscillator Frequency Selection
    MOSCXTST = 0xff << 8    # Main Crystal Oscillator Start-up Time
    KEY      = 0xff << 16   # Password
    MOSCSEL  = 0x1 << 24    # Main Oscillator Selection
    CFDEN    = 0x1 << 25    # Clock Failure Detector Enable

class CKGR_MCFR(IntEnum):
    MAINF    = 0xffff << 0   # Main Clock Frequency
    MAINFRDY = 0x1 << 16     # Main Clock Ready

class CKGR_PLLAR(IntEnum):
    DIVA      = 0xff << 0     # Divider
    PLLACOUNT = 0x3f << 8     # PLLA Counter
    MULA      = 0x7ff << 16   # PLLA Multiplier
    ONE       = 0x1 << 29     # Must Be Set to 1

class MCKR(IntEnum):
    CSS      = 0x3 << 0    # Master Clock Source Selection
    PRES     = 0x7 << 4    # Processor Clock Prescaler
    PLLADIV2 = 0x1 << 12   # PLLA Divisor by 2
    UPLLDIV2 = 0x1 << 13   # 

class USB(IntEnum):
    USBS   = 0x1 << 0   # USB Input Clock Selection
    USBDIV = 0xf << 8   # Divider for USB Clock.

class PCK(IntEnum):
    CSS  = 0x7 << 0   # Master Clock Source Selection
    PRES = 0x7 << 4   # Programmable Clock Prescaler

class IER(IntEnum):
    MOSCXTS  = 0x1 << 0    # Main Crystal Oscillator Status Interrupt Enable
    LOCKA    = 0x1 << 1    # PLLA Lock Interrupt Enable
    MCKRDY   = 0x1 << 3    # Master Clock Ready Interrupt Enable
    LOCKU    = 0x1 << 6    # UTMI PLL Lock Interrupt Enable
    PCKRDY0  = 0x1 << 8    # Programmable Clock Ready 0 Interrupt Enable
    PCKRDY1  = 0x1 << 9    # Programmable Clock Ready 1 Interrupt Enable
    PCKRDY2  = 0x1 << 10   # Programmable Clock Ready 2 Interrupt Enable
    MOSCSELS = 0x1 << 16   # Main Oscillator Selection Status Interrupt Enable
    MOSCRCS  = 0x1 << 17   # Main On-Chip RC Status Interrupt Enable
    CFDEV    = 0x1 << 18   # Clock Failure Detector Event Interrupt Enable

class IDR(IntEnum):
    MOSCXTS  = 0x1 << 0    # Main Crystal Oscillator Status Interrupt Disable
    LOCKA    = 0x1 << 1    # PLLA Lock Interrupt Disable
    MCKRDY   = 0x1 << 3    # Master Clock Ready Interrupt Disable
    LOCKU    = 0x1 << 6    # UTMI PLL Lock Interrupt Disable
    PCKRDY0  = 0x1 << 8    # Programmable Clock Ready 0 Interrupt Disable
    PCKRDY1  = 0x1 << 9    # Programmable Clock Ready 1 Interrupt Disable
    PCKRDY2  = 0x1 << 10   # Programmable Clock Ready 2 Interrupt Disable
    MOSCSELS = 0x1 << 16   # Main Oscillator Selection Status Interrupt Disable
    MOSCRCS  = 0x1 << 17   # Main On-Chip RC Status Interrupt Disable
    CFDEV    = 0x1 << 18   # Clock Failure Detector Event Interrupt Disable

class SR(IntEnum):
    MOSCXTS  = 0x1 << 0    # Main XTAL Oscillator Status
    LOCKA    = 0x1 << 1    # PLLA Lock Status
    MCKRDY   = 0x1 << 3    # Master Clock Status
    LOCKU    = 0x1 << 6    # UTMI PLL Lock Status
    OSCSELS  = 0x1 << 7    # Slow Clock Oscillator Selection
    PCKRDY0  = 0x1 << 8    # Programmable Clock Ready Status
    PCKRDY1  = 0x1 << 9    # Programmable Clock Ready Status
    PCKRDY2  = 0x1 << 10   # Programmable Clock Ready Status
    MOSCSELS = 0x1 << 16   # Main Oscillator Selection Status
    MOSCRCS  = 0x1 << 17   # Main On-Chip RC Oscillator Status
    CFDEV    = 0x1 << 18   # Clock Failure Detector Event
    CFDS     = 0x1 << 19   # Clock Failure Detector Status
    FOS      = 0x1 << 20   # Clock Failure Detector Fault Output Status

class IMR(IntEnum):
    MOSCXTS  = 0x1 << 0    # Main Crystal Oscillator Status Interrupt Mask
    LOCKA    = 0x1 << 1    # PLLA Lock Interrupt Mask
    MCKRDY   = 0x1 << 3    # Master Clock Ready Interrupt Mask
    LOCKU    = 0x1 << 6    # UTMI PLL Lock Interrupt Mask
    PCKRDY0  = 0x1 << 8    # Programmable Clock Ready 0 Interrupt Mask
    PCKRDY1  = 0x1 << 9    # Programmable Clock Ready 1 Interrupt Mask
    PCKRDY2  = 0x1 << 10   # Programmable Clock Ready 2 Interrupt Mask
    MOSCSELS = 0x1 << 16   # Main Oscillator Selection Status Interrupt Mask
    MOSCRCS  = 0x1 << 17   # Main On-Chip RC Status Interrupt Mask
    CFDEV    = 0x1 << 18   # Clock Failure Detector Event Interrupt Mask

class FSMR(IntEnum):
    FSTT0  = 0x1 << 0    # Fast Startup Input Enable 0
    FSTT1  = 0x1 << 1    # Fast Startup Input Enable 1
    FSTT2  = 0x1 << 2    # Fast Startup Input Enable 2
    FSTT3  = 0x1 << 3    # Fast Startup Input Enable 3
    FSTT4  = 0x1 << 4    # Fast Startup Input Enable 4
    FSTT5  = 0x1 << 5    # Fast Startup Input Enable 5
    FSTT6  = 0x1 << 6    # Fast Startup Input Enable 6
    FSTT7  = 0x1 << 7    # Fast Startup Input Enable 7
    FSTT8  = 0x1 << 8    # Fast Startup Input Enable 8
    FSTT9  = 0x1 << 9    # Fast Startup Input Enable 9
    FSTT10 = 0x1 << 10   # Fast Startup Input Enable 10
    FSTT11 = 0x1 << 11   # Fast Startup Input Enable 11
    FSTT12 = 0x1 << 12   # Fast Startup Input Enable 12
    FSTT13 = 0x1 << 13   # Fast Startup Input Enable 13
    FSTT14 = 0x1 << 14   # Fast Startup Input Enable 14
    FSTT15 = 0x1 << 15   # Fast Startup Input Enable 15
    RTTAL  = 0x1 << 16   # RTT Alarm Enable
    RTCAL  = 0x1 << 17   # RTC Alarm Enable
    USBAL  = 0x1 << 18   # USB Alarm Enable
    LPM    = 0x1 << 20   # Low Power Mode

class FSPR(IntEnum):
    FSTP0  = 0x1 << 0    # Fast Startup Input Polarityx
    FSTP1  = 0x1 << 1    # Fast Startup Input Polarityx
    FSTP2  = 0x1 << 2    # Fast Startup Input Polarityx
    FSTP3  = 0x1 << 3    # Fast Startup Input Polarityx
    FSTP4  = 0x1 << 4    # Fast Startup Input Polarityx
    FSTP5  = 0x1 << 5    # Fast Startup Input Polarityx
    FSTP6  = 0x1 << 6    # Fast Startup Input Polarityx
    FSTP7  = 0x1 << 7    # Fast Startup Input Polarityx
    FSTP8  = 0x1 << 8    # Fast Startup Input Polarityx
    FSTP9  = 0x1 << 9    # Fast Startup Input Polarityx
    FSTP10 = 0x1 << 10   # Fast Startup Input Polarityx
    FSTP11 = 0x1 << 11   # Fast Startup Input Polarityx
    FSTP12 = 0x1 << 12   # Fast Startup Input Polarityx
    FSTP13 = 0x1 << 13   # Fast Startup Input Polarityx
    FSTP14 = 0x1 << 14   # Fast Startup Input Polarityx
    FSTP15 = 0x1 << 15   # Fast Startup Input Polarityx

class FOCR(IntEnum):
    FOCLR = 0x1 << 0   # Fault Output Clear

class WPMR(IntEnum):
    WPEN  = 0x1 << 0        # Write Protect Enable
    WPKEY = 0xffffff << 8   # Write Protect KEY

class WPSR(IntEnum):
    WPVS   = 0x1 << 0      # Write Protect Violation Status
    WPVSRC = 0xffff << 8   # Write Protect Violation Source

class PCER1(IntEnum):
    PID32 = 0x1 << 0    # Peripheral Clock 32 Enable
    PID33 = 0x1 << 1    # Peripheral Clock 33 Enable
    PID34 = 0x1 << 2    # Peripheral Clock 34 Enable
    PID35 = 0x1 << 3    # Peripheral Clock 35 Enable
    PID36 = 0x1 << 4    # Peripheral Clock 36 Enable
    PID37 = 0x1 << 5    # Peripheral Clock 37 Enable
    PID38 = 0x1 << 6    # Peripheral Clock 38 Enable
    PID39 = 0x1 << 7    # Peripheral Clock 39 Enable
    PID40 = 0x1 << 8    # Peripheral Clock 40 Enable
    PID41 = 0x1 << 9    # Peripheral Clock 41 Enable
    PID42 = 0x1 << 10   # Peripheral Clock 42 Enable
    PID43 = 0x1 << 11   # Peripheral Clock 43 Enable
    PID44 = 0x1 << 12   # Peripheral Clock 44 Enable

class PCDR1(IntEnum):
    PID32 = 0x1 << 0    # Peripheral Clock 32 Disable
    PID33 = 0x1 << 1    # Peripheral Clock 33 Disable
    PID34 = 0x1 << 2    # Peripheral Clock 34 Disable
    PID35 = 0x1 << 3    # Peripheral Clock 35 Disable
    PID36 = 0x1 << 4    # Peripheral Clock 36 Disable
    PID37 = 0x1 << 5    # Peripheral Clock 37 Disable
    PID38 = 0x1 << 6    # Peripheral Clock 38 Disable
    PID39 = 0x1 << 7    # Peripheral Clock 39 Disable
    PID40 = 0x1 << 8    # Peripheral Clock 40 Disable
    PID41 = 0x1 << 9    # Peripheral Clock 41 Disable
    PID42 = 0x1 << 10   # Peripheral Clock 42 Disable
    PID43 = 0x1 << 11   # Peripheral Clock 43 Disable
    PID44 = 0x1 << 12   # Peripheral Clock 44 Disable

class PCSR1(IntEnum):
    PID32 = 0x1 << 0    # Peripheral Clock 32 Status
    PID33 = 0x1 << 1    # Peripheral Clock 33 Status
    PID34 = 0x1 << 2    # Peripheral Clock 34 Status
    PID35 = 0x1 << 3    # Peripheral Clock 35 Status
    PID36 = 0x1 << 4    # Peripheral Clock 36 Status
    PID37 = 0x1 << 5    # Peripheral Clock 37 Status
    PID38 = 0x1 << 6    # Peripheral Clock 38 Status
    PID39 = 0x1 << 7    # Peripheral Clock 39 Status
    PID40 = 0x1 << 8    # Peripheral Clock 40 Status
    PID41 = 0x1 << 9    # Peripheral Clock 41 Status
    PID42 = 0x1 << 10   # Peripheral Clock 42 Status
    PID43 = 0x1 << 11   # Peripheral Clock 43 Status
    PID44 = 0x1 << 12   # Peripheral Clock 44 Status

class PCR(IntEnum):
    PID = 0x3f << 0   # Peripheral ID
    CMD = 0x1 << 12   # Command
    DIV = 0x3 << 16   # Divisor Value
    EN  = 0x1 << 28   # Enable

