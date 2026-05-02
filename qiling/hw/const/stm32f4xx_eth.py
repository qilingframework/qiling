from enum import IntEnum


class ETH_MACCR(IntEnum):
    WD   = 1 << 23
    JD   = 1 << 22
    IFG  = 0x7 << 17
    CSD  = 1 << 16
    FES  = 1 << 14
    ROD  = 1 << 13
    LM   = 1 << 12
    DM   = 1 << 11
    IPCO = 1 << 10
    RD   = 1 << 9
    APCS = 1 << 7
    BL   = 0x3 << 5
    DC   = 1 << 4
    TE   = 1 << 3
    RE   = 1 << 2

class ETH_MACFFR(IntEnum):
    RA                          = 1 << 31
    HPF                         = 1 << 10
    SAF                         = 1 << 9
    SAIF                        = 1 << 8
    PCF                         = 0x3 << 6
    PCF_BlockAll                = 1 << 6
    PCF_ForwardAll              = 1 << 7
    PCF_ForwardPassedAddrFilter = 0x3 << 6
    BFD                         = 1 << 5
    PAM                         = 1 << 4
    DAIF                        = 1 << 3
    HM                          = 1 << 2
    HU                          = 1 << 1
    PM                          = 1 << 0

class ETH_MACMIIAR(IntEnum):
    PA        = 0x1f << 11
    MR        = 0x1f << 6
    CR        = 0x7 << 2
    CR_Div62  = 1 << 2
    CR_Div16  = 1 << 3
    CR_Div26  = 0x3 << 2
    CR_Div102 = 1 << 4
    MW        = 1 << 1
    MB        = 1 << 0

class ETH_MACFCR(IntEnum):
    PT           = 0xffff << 16
    ZQPD         = 1 << 7
    PLT          = 0x3 << 4
    PLT_Minus28  = 1 << 4
    PLT_Minus144 = 1 << 5
    PLT_Minus256 = 0x3 << 4
    UPFD         = 1 << 3
    RFCE         = 1 << 2
    TFCE         = 1 << 1
    FCBBPA       = 1 << 0

class ETH_MACVLANTR(IntEnum):
    VLANTC = 1 << 16
    VLANTI = 0xffff << 0

class ETH_MACPMTCSR(IntEnum):
    WFFRPR = 1 << 31
    GU     = 1 << 9
    WFR    = 1 << 6
    MPR    = 1 << 5
    WFE    = 1 << 2
    MPE    = 1 << 1
    PD     = 1 << 0

class ETH_MACDBGR(IntEnum):
    TFF                 = 1 << 25
    TFNE                = 1 << 24
    TFWA                = 1 << 22
    TFRS                = 0x3 << 20
    TFRS_WRITING        = 0x3 << 20
    TFRS_WAITING        = 1 << 21
    TFRS_READ           = 1 << 20
    MTP                 = 1 << 19
    MTFCS               = 0x3 << 17
    MTFCS_TRANSFERRING  = 0x3 << 17
    MTFCS_GENERATINGPCF = 1 << 18
    MTFCS_WAITING       = 1 << 17
    MMTEA               = 1 << 16
    RFFL                = 0x3 << 8
    RFFL_FL             = 0x3 << 8
    RFFL_ABOVEFCT       = 1 << 9
    RFFL_BELOWFCT       = 1 << 8
    RFRCS               = 0x3 << 5
    RFRCS_FLUSHING      = 0x3 << 5
    RFRCS_STATUSREADING = 1 << 6
    RFRCS_DATAREADING   = 1 << 5
    RFWRA               = 1 << 4
    MSFRWCS             = 0x3 << 1
    MMRPEA              = 1 << 0

class ETH_MACSR(IntEnum):
    TSTS   = 1 << 9
    MMCTS  = 1 << 6
    MMMCRS = 1 << 5
    MMCS   = 1 << 4
    PMTS   = 1 << 3

class ETH_MACIMR(IntEnum):
    TSTIM = 1 << 9
    PMTIM = 1 << 3

class ETH_MACA1HR(IntEnum):
    AE     = 1 << 31
    SA     = 1 << 30
    MBC    = 0x3f << 24
    MACA1H = 0xffff << 0

class ETH_MACA2HR(IntEnum):
    AE     = 1 << 31
    SA     = 1 << 30
    MBC    = 0x3f << 24
    MACA2H = 0xffff << 0

class ETH_MACA3HR(IntEnum):
    AE     = 1 << 31
    SA     = 1 << 30
    MBC    = 0x3f << 24
    MACA3H = 0xffff << 0

class ETH_MMCCR(IntEnum):
    MCFHP = 1 << 5
    MCP   = 1 << 4
    MCF   = 1 << 3
    ROR   = 1 << 2
    CSR   = 1 << 1
    CR    = 1 << 0

class ETH_MMCRIR(IntEnum):
    RGUFS = 1 << 17
    RFAES = 1 << 6
    RFCES = 1 << 5

class ETH_MMCTIR(IntEnum):
    TGFS    = 1 << 21
    TGFMSCS = 1 << 15
    TGFSCS  = 1 << 14

class ETH_MMCRIMR(IntEnum):
    RGUFM = 1 << 17
    RFAEM = 1 << 6
    RFCEM = 1 << 5

class ETH_MMCTIMR(IntEnum):
    TGFM    = 1 << 21
    TGFMSCM = 1 << 15
    TGFSCM  = 1 << 14

class ETH_PTPTSCR(IntEnum):
    TSCNT = 0x3 << 16
    TSARU = 1 << 5
    TSITE = 1 << 4
    TSSTU = 1 << 3
    TSSTI = 1 << 2
    TSFCU = 1 << 1
    TSE   = 1 << 0

class ETH_PTPTSSR(IntEnum):
    TSSMRME    = 1 << 15
    TSSEME     = 1 << 14
    TSSIPV4FE  = 1 << 13
    TSSIPV6FE  = 1 << 12
    TSSPTPOEFE = 1 << 11
    TSPTPPSV2E = 1 << 10
    TSSSR      = 1 << 9
    TSSARFE    = 1 << 8
    TSTTR      = 1 << 5
    TSSO       = 1 << 4

class ETH_PTPSSIR(IntEnum):
    STSSI = 0xff << 0

class ETH_PTPTSLR(IntEnum):
    STPNS = 1 << 31
    STSS  = 0x7fffffff << 0

class ETH_PTPTSLUR(IntEnum):
    TSUPNS = 1 << 31
    TSUSS  = 0x7fffffff << 0

class ETH_DMABMR(IntEnum):
    AAB  = 1 << 25
    FPM  = 1 << 24
    USP  = 1 << 23
    RDP  = 0x3f << 17
    FB   = 1 << 16
    RTPR = 0x3 << 14
    PBL  = 0x3f << 8
    EDE  = 1 << 7
    DSL  = 0x1f << 2
    DA   = 1 << 1
    SR   = 1 << 0

class ETH_DMASR(IntEnum):
    TSTS             = 1 << 29
    PMTS             = 1 << 28
    MMCS             = 1 << 27
    EBS              = 0x7 << 23
    EBS_DescAccess   = 1 << 25
    EBS_ReadTransf   = 1 << 24
    EBS_DataTransfTx = 1 << 23
    TPS              = 0x7 << 20
    TPS_Fetching     = 1 << 20
    TPS_Waiting      = 1 << 21
    TPS_Reading      = 0x3 << 20
    TPS_Suspended    = 0x3 << 21
    TPS_Closing      = 0x7 << 20
    RPS              = 0x7 << 17
    RPS_Fetching     = 1 << 17
    RPS_Waiting      = 0x3 << 17
    RPS_Suspended    = 1 << 19
    RPS_Closing      = 0x5 << 17
    RPS_Queuing      = 0x7 << 17
    NIS              = 1 << 16
    AIS              = 1 << 15
    ERS              = 1 << 14
    FBES             = 1 << 13
    ETS              = 1 << 10
    RWTS             = 1 << 9
    RPSS             = 1 << 8
    RBUS             = 1 << 7
    RS               = 1 << 6
    TUS              = 1 << 5
    ROS              = 1 << 4
    TJTS             = 1 << 3
    TBUS             = 1 << 2
    TPSS             = 1 << 1
    TS               = 1 << 0

class ETH_DMAOMR(IntEnum):
    DTCEFD = 1 << 26
    RSF    = 1 << 25
    DFRF   = 1 << 24
    TSF    = 1 << 21
    FTF    = 1 << 20
    TTC    = 0x7 << 14
    ST     = 1 << 13
    FEF    = 1 << 7
    FGF    = 1 << 6
    RTC    = 0x3 << 3
    OSF    = 1 << 2
    SR     = 1 << 1

class ETH_DMAIER(IntEnum):
    NISE  = 1 << 16
    AISE  = 1 << 15
    ERIE  = 1 << 14
    FBEIE = 1 << 13
    ETIE  = 1 << 10
    RWTIE = 1 << 9
    RPSIE = 1 << 8
    RBUIE = 1 << 7
    RIE   = 1 << 6
    TUIE  = 1 << 5
    ROIE  = 1 << 4
    TJTIE = 1 << 3
    TBUIE = 1 << 2
    TPSIE = 1 << 1
    TIE   = 1 << 0

class ETH_DMAMFBOCR(IntEnum):
    OFOC = 1 << 28
    MFA  = 0x7ff << 17
    OMFC = 1 << 16
    MFC  = 0xffff << 0
