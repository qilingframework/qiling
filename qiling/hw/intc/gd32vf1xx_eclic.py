#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class GD32VF1xxEclic(QlPeripheral):
    class Type(ctypes.Structure):
        """ Enhanced Core Local Interrupt Controller 
        """

        _fields_ = [
            ("CLICCFG"       , ctypes.c_uint8),  # Address offset: 0x0, cliccfg Register
            ("CLICINFO"      , ctypes.c_uint32), # Address offset: 0x04, clicinfo Register
            ("MTH"           , ctypes.c_uint8),  # Address offset: 0x0b, MTH Register
            ("CLICINTIP_0"   , ctypes.c_uint8),  # Address offset: 0x1000, clicintip Register
            ("CLICINTIP_1"   , ctypes.c_uint8),  # Address offset: 0x1004, clicintip Register
            ("CLICINTIP_2"   , ctypes.c_uint8),  # Address offset: 0x1008, clicintip Register
            ("CLICINTIP_3"   , ctypes.c_uint8),  # Address offset: 0x100C, clicintip Register
            ("CLICINTIP_4"   , ctypes.c_uint8),  # Address offset: 0x1010, clicintip Register
            ("CLICINTIP_5"   , ctypes.c_uint8),  # Address offset: 0x1014, clicintip Register
            ("CLICINTIP_6"   , ctypes.c_uint8),  # Address offset: 0x1018, clicintip Register
            ("CLICINTIP_7"   , ctypes.c_uint8),  # Address offset: 0x101C, clicintip Register
            ("CLICINTIP_8"   , ctypes.c_uint8),  # Address offset: 0x1020, clicintip Register
            ("CLICINTIP_9"   , ctypes.c_uint8),  # Address offset: 0x1024, clicintip Register
            ("CLICINTIP_10"  , ctypes.c_uint8),  # Address offset: 0x1028, clicintip Register
            ("CLICINTIP_11"  , ctypes.c_uint8),  # Address offset: 0x102C, clicintip Register
            ("CLICINTIP_12"  , ctypes.c_uint8),  # Address offset: 0x1030, clicintip Register
            ("CLICINTIP_13"  , ctypes.c_uint8),  # Address offset: 0x1034, clicintip Register
            ("CLICINTIP_14"  , ctypes.c_uint8),  # Address offset: 0x1038, clicintip Register
            ("CLICINTIP_15"  , ctypes.c_uint8),  # Address offset: 0x103C, clicintip Register
            ("CLICINTIP_16"  , ctypes.c_uint8),  # Address offset: 0x1040, clicintip Register
            ("CLICINTIP_17"  , ctypes.c_uint8),  # Address offset: 0x1044, clicintip Register
            ("CLICINTIP_18"  , ctypes.c_uint8),  # Address offset: 0x1048, clicintip Register
            ("CLICINTIP_19"  , ctypes.c_uint8),  # Address offset: 0x104C, clicintip Register
            ("CLICINTIP_20"  , ctypes.c_uint8),  # Address offset: 0x1050, clicintip Register
            ("CLICINTIP_21"  , ctypes.c_uint8),  # Address offset: 0x1054, clicintip Register
            ("CLICINTIP_22"  , ctypes.c_uint8),  # Address offset: 0x1058, clicintip Register
            ("CLICINTIP_23"  , ctypes.c_uint8),  # Address offset: 0x105C, clicintip Register
            ("CLICINTIP_24"  , ctypes.c_uint8),  # Address offset: 0x1060, clicintip Register
            ("CLICINTIP_25"  , ctypes.c_uint8),  # Address offset: 0x1064, clicintip Register
            ("CLICINTIP_26"  , ctypes.c_uint8),  # Address offset: 0x1068, clicintip Register
            ("CLICINTIP_27"  , ctypes.c_uint8),  # Address offset: 0x106C, clicintip Register
            ("CLICINTIP_28"  , ctypes.c_uint8),  # Address offset: 0x1070, clicintip Register
            ("CLICINTIP_29"  , ctypes.c_uint8),  # Address offset: 0x1074, clicintip Register
            ("CLICINTIP_30"  , ctypes.c_uint8),  # Address offset: 0x1078, clicintip Register
            ("CLICINTIP_31"  , ctypes.c_uint8),  # Address offset: 0x107C, clicintip Register
            ("CLICINTIP_32"  , ctypes.c_uint8),  # Address offset: 0x1080, clicintip Register
            ("CLICINTIP_33"  , ctypes.c_uint8),  # Address offset: 0x1084, clicintip Register
            ("CLICINTIP_34"  , ctypes.c_uint8),  # Address offset: 0x1088, clicintip Register
            ("CLICINTIP_35"  , ctypes.c_uint8),  # Address offset: 0x108C, clicintip Register
            ("CLICINTIP_36"  , ctypes.c_uint8),  # Address offset: 0x1090, clicintip Register
            ("CLICINTIP_37"  , ctypes.c_uint8),  # Address offset: 0x1094, clicintip Register
            ("CLICINTIP_38"  , ctypes.c_uint8),  # Address offset: 0x1098, clicintip Register
            ("CLICINTIP_39"  , ctypes.c_uint8),  # Address offset: 0x109C, clicintip Register
            ("CLICINTIP_40"  , ctypes.c_uint8),  # Address offset: 0x10A0, clicintip Register
            ("CLICINTIP_41"  , ctypes.c_uint8),  # Address offset: 0x10A4, clicintip Register
            ("CLICINTIP_42"  , ctypes.c_uint8),  # Address offset: 0x10A8, clicintip Register
            ("CLICINTIP_43"  , ctypes.c_uint8),  # Address offset: 0x10AC, clicintip Register
            ("CLICINTIP_44"  , ctypes.c_uint8),  # Address offset: 0x10B0, clicintip Register
            ("CLICINTIP_45"  , ctypes.c_uint8),  # Address offset: 0x10B4, clicintip Register
            ("CLICINTIP_46"  , ctypes.c_uint8),  # Address offset: 0x10B8, clicintip Register
            ("CLICINTIP_47"  , ctypes.c_uint8),  # Address offset: 0x10BC, clicintip Register
            ("CLICINTIP_48"  , ctypes.c_uint8),  # Address offset: 0x10C0, clicintip Register
            ("CLICINTIP_49"  , ctypes.c_uint8),  # Address offset: 0x10C4, clicintip Register
            ("CLICINTIP_50"  , ctypes.c_uint8),  # Address offset: 0x10C8, clicintip Register
            ("CLICINTIP_51"  , ctypes.c_uint8),  # Address offset: 0x10CC, clicintip Register
            ("CLICINTIP_52"  , ctypes.c_uint8),  # Address offset: 0x10D0, clicintip Register
            ("CLICINTIP_53"  , ctypes.c_uint8),  # Address offset: 0x10D4, clicintip Register
            ("CLICINTIP_54"  , ctypes.c_uint8),  # Address offset: 0x10D8, clicintip Register
            ("CLICINTIP_55"  , ctypes.c_uint8),  # Address offset: 0x10DC, clicintip Register
            ("CLICINTIP_56"  , ctypes.c_uint8),  # Address offset: 0x10E0, clicintip Register
            ("CLICINTIP_57"  , ctypes.c_uint8),  # Address offset: 0x10E4, clicintip Register
            ("CLICINTIP_58"  , ctypes.c_uint8),  # Address offset: 0x10E8, clicintip Register
            ("CLICINTIP_59"  , ctypes.c_uint8),  # Address offset: 0x10EC, clicintip Register
            ("CLICINTIP_60"  , ctypes.c_uint8),  # Address offset: 0x10F0, clicintip Register
            ("CLICINTIP_61"  , ctypes.c_uint8),  # Address offset: 0x10F4, clicintip Register
            ("CLICINTIP_62"  , ctypes.c_uint8),  # Address offset: 0x10F8, clicintip Register
            ("CLICINTIP_63"  , ctypes.c_uint8),  # Address offset: 0x10FC, clicintip Register
            ("CLICINTIP_64"  , ctypes.c_uint8),  # Address offset: 0x1100, clicintip Register
            ("CLICINTIP_65"  , ctypes.c_uint8),  # Address offset: 0x1104, clicintip Register
            ("CLICINTIP_66"  , ctypes.c_uint8),  # Address offset: 0x1108, clicintip Register
            ("CLICINTIP_67"  , ctypes.c_uint8),  # Address offset: 0x110C, clicintip Register
            ("CLICINTIP_68"  , ctypes.c_uint8),  # Address offset: 0x1110, clicintip Register
            ("CLICINTIP_69"  , ctypes.c_uint8),  # Address offset: 0x1114, clicintip Register
            ("CLICINTIP_70"  , ctypes.c_uint8),  # Address offset: 0x1118, clicintip Register
            ("CLICINTIP_71"  , ctypes.c_uint8),  # Address offset: 0x111C, clicintip Register
            ("CLICINTIP_72"  , ctypes.c_uint8),  # Address offset: 0x1120, clicintip Register
            ("CLICINTIP_73"  , ctypes.c_uint8),  # Address offset: 0x1124, clicintip Register
            ("CLICINTIP_74"  , ctypes.c_uint8),  # Address offset: 0x1128, clicintip Register
            ("CLICINTIP_75"  , ctypes.c_uint8),  # Address offset: 0x112C, clicintip Register
            ("CLICINTIP_76"  , ctypes.c_uint8),  # Address offset: 0x1130, clicintip Register
            ("CLICINTIP_77"  , ctypes.c_uint8),  # Address offset: 0x1134, clicintip Register
            ("CLICINTIP_78"  , ctypes.c_uint8),  # Address offset: 0x1138, clicintip Register
            ("CLICINTIP_79"  , ctypes.c_uint8),  # Address offset: 0x113C, clicintip Register
            ("CLICINTIP_80"  , ctypes.c_uint8),  # Address offset: 0x1140, clicintip Register
            ("CLICINTIP_81"  , ctypes.c_uint8),  # Address offset: 0x1144, clicintip Register
            ("CLICINTIP_82"  , ctypes.c_uint8),  # Address offset: 0x1148, clicintip Register
            ("CLICINTIP_83"  , ctypes.c_uint8),  # Address offset: 0x114C, clicintip Register
            ("CLICINTIP_84"  , ctypes.c_uint8),  # Address offset: 0x1150, clicintip Register
            ("CLICINTIP_85"  , ctypes.c_uint8),  # Address offset: 0x1158, clicintip Register
            ("CLICINTIP_86"  , ctypes.c_uint8),  # Address offset: 0x115C, clicintip Register
            ("CLICINTIE_0"   , ctypes.c_uint8),  # Address offset: 0x1001, clicintie Register
            ("CLICINTIE_1"   , ctypes.c_uint8),  # Address offset: 0x1005, clicintie Register
            ("CLICINTIE_2"   , ctypes.c_uint8),  # Address offset: 0x1009, clicintie Register
            ("CLICINTIE_3"   , ctypes.c_uint8),  # Address offset: 0x100D, clicintie Register
            ("CLICINTIE_4"   , ctypes.c_uint8),  # Address offset: 0x1011, clicintie Register
            ("CLICINTIE_5"   , ctypes.c_uint8),  # Address offset: 0x1015, clicintie Register
            ("CLICINTIE_6"   , ctypes.c_uint8),  # Address offset: 0x1019, clicintie Register
            ("CLICINTIE_7"   , ctypes.c_uint8),  # Address offset: 0x101D, clicintie Register
            ("CLICINTIE_8"   , ctypes.c_uint8),  # Address offset: 0x1021, clicintie Register
            ("CLICINTIE_9"   , ctypes.c_uint8),  # Address offset: 0x1025, clicintie Register
            ("CLICINTIE_10"  , ctypes.c_uint8),  # Address offset: 0x1029, clicintie Register
            ("CLICINTIE_11"  , ctypes.c_uint8),  # Address offset: 0x102D, clicintie Register
            ("CLICINTIE_12"  , ctypes.c_uint8),  # Address offset: 0x1031, clicintie Register
            ("CLICINTIE_13"  , ctypes.c_uint8),  # Address offset: 0x1035, clicintie Register
            ("CLICINTIE_14"  , ctypes.c_uint8),  # Address offset: 0x1039, clicintie Register
            ("CLICINTIE_15"  , ctypes.c_uint8),  # Address offset: 0x103D, clicintie Register
            ("CLICINTIE_16"  , ctypes.c_uint8),  # Address offset: 0x1041, clicintie Register
            ("CLICINTIE_17"  , ctypes.c_uint8),  # Address offset: 0x1045, clicintie Register
            ("CLICINTIE_18"  , ctypes.c_uint8),  # Address offset: 0x1049, clicintie Register
            ("CLICINTIE_19"  , ctypes.c_uint8),  # Address offset: 0x104D, clicintie Register
            ("CLICINTIE_20"  , ctypes.c_uint8),  # Address offset: 0x1051, clicintie Register
            ("CLICINTIE_21"  , ctypes.c_uint8),  # Address offset: 0x1055, clicintie Register
            ("CLICINTIE_22"  , ctypes.c_uint8),  # Address offset: 0x1059, clicintie Register
            ("CLICINTIE_23"  , ctypes.c_uint8),  # Address offset: 0x105D, clicintie Register
            ("CLICINTIE_24"  , ctypes.c_uint8),  # Address offset: 0x1061, clicintie Register
            ("CLICINTIE_25"  , ctypes.c_uint8),  # Address offset: 0x1065, clicintie Register
            ("CLICINTIE_26"  , ctypes.c_uint8),  # Address offset: 0x1069, clicintie Register
            ("CLICINTIE_27"  , ctypes.c_uint8),  # Address offset: 0x106D, clicintie Register
            ("CLICINTIE_28"  , ctypes.c_uint8),  # Address offset: 0x1071, clicintie Register
            ("CLICINTIE_29"  , ctypes.c_uint8),  # Address offset: 0x1075, clicintie Register
            ("CLICINTIE_30"  , ctypes.c_uint8),  # Address offset: 0x1079, clicintie Register
            ("CLICINTIE_31"  , ctypes.c_uint8),  # Address offset: 0x107D, clicintie Register
            ("CLICINTIE_32"  , ctypes.c_uint8),  # Address offset: 0x1081, clicintie Register
            ("CLICINTIE_33"  , ctypes.c_uint8),  # Address offset: 0x1085, clicintie Register
            ("CLICINTIE_34"  , ctypes.c_uint8),  # Address offset: 0x1089, clicintie Register
            ("CLICINTIE_35"  , ctypes.c_uint8),  # Address offset: 0x108D, clicintie Register
            ("CLICINTIE_36"  , ctypes.c_uint8),  # Address offset: 0x1091, clicintie Register
            ("CLICINTIE_37"  , ctypes.c_uint8),  # Address offset: 0x1095, clicintie Register
            ("CLICINTIE_38"  , ctypes.c_uint8),  # Address offset: 0x1099, clicintie Register
            ("CLICINTIE_39"  , ctypes.c_uint8),  # Address offset: 0x109D, clicintie Register
            ("CLICINTIE_40"  , ctypes.c_uint8),  # Address offset: 0x10A1, clicintie Register
            ("CLICINTIE_41"  , ctypes.c_uint8),  # Address offset: 0x10A5, clicintie Register
            ("CLICINTIE_42"  , ctypes.c_uint8),  # Address offset: 0x10A9, clicintie Register
            ("CLICINTIE_43"  , ctypes.c_uint8),  # Address offset: 0x10AD, clicintie Register
            ("CLICINTIE_44"  , ctypes.c_uint8),  # Address offset: 0x10B1, clicintie Register
            ("CLICINTIE_45"  , ctypes.c_uint8),  # Address offset: 0x10B5, clicintie Register
            ("CLICINTIE_46"  , ctypes.c_uint8),  # Address offset: 0x10B9, clicintie Register
            ("CLICINTIE_47"  , ctypes.c_uint8),  # Address offset: 0x10BD, clicintie Register
            ("CLICINTIE_48"  , ctypes.c_uint8),  # Address offset: 0x10C1, clicintie Register
            ("CLICINTIE_49"  , ctypes.c_uint8),  # Address offset: 0x10C5, clicintie Register
            ("CLICINTIE_50"  , ctypes.c_uint8),  # Address offset: 0x10C9, clicintie Register
            ("CLICINTIE_51"  , ctypes.c_uint8),  # Address offset: 0x10CD, clicintie Register
            ("CLICINTIE_52"  , ctypes.c_uint8),  # Address offset: 0x10D1, clicintie Register
            ("CLICINTIE_53"  , ctypes.c_uint8),  # Address offset: 0x10D5, clicintie Register
            ("CLICINTIE_54"  , ctypes.c_uint8),  # Address offset: 0x10D9, clicintie Register
            ("CLICINTIE_55"  , ctypes.c_uint8),  # Address offset: 0x10DD, clicintie Register
            ("CLICINTIE_56"  , ctypes.c_uint8),  # Address offset: 0x10E1, clicintie Register
            ("CLICINTIE_57"  , ctypes.c_uint8),  # Address offset: 0x10E5, clicintie Register
            ("CLICINTIE_58"  , ctypes.c_uint8),  # Address offset: 0x10E9, clicintie Register
            ("CLICINTIE_59"  , ctypes.c_uint8),  # Address offset: 0x10ED, clicintie Register
            ("CLICINTIE_60"  , ctypes.c_uint8),  # Address offset: 0x10F1, clicintie Register
            ("CLICINTIE_61"  , ctypes.c_uint8),  # Address offset: 0x10F5, clicintie Register
            ("CLICINTIE_62"  , ctypes.c_uint8),  # Address offset: 0x10F9, clicintie Register
            ("CLICINTIE_63"  , ctypes.c_uint8),  # Address offset: 0x10FD, clicintie Register
            ("CLICINTIE_64"  , ctypes.c_uint8),  # Address offset: 0x1101, clicintie Register
            ("CLICINTIE_65"  , ctypes.c_uint8),  # Address offset: 0x1105, clicintie Register
            ("CLICINTIE_66"  , ctypes.c_uint8),  # Address offset: 0x1109, clicintie Register
            ("CLICINTIE_67"  , ctypes.c_uint8),  # Address offset: 0x110D, clicintie Register
            ("CLICINTIE_68"  , ctypes.c_uint8),  # Address offset: 0x1111, clicintie Register
            ("CLICINTIE_69"  , ctypes.c_uint8),  # Address offset: 0x1115, clicintie Register
            ("CLICINTIE_70"  , ctypes.c_uint8),  # Address offset: 0x1119, clicintie Register
            ("CLICINTIE_71"  , ctypes.c_uint8),  # Address offset: 0x111D, clicintie Register
            ("CLICINTIE_72"  , ctypes.c_uint8),  # Address offset: 0x1121, clicintie Register
            ("CLICINTIE_73"  , ctypes.c_uint8),  # Address offset: 0x1125, clicintie Register
            ("CLICINTIE_74"  , ctypes.c_uint8),  # Address offset: 0x1129, clicintie Register
            ("CLICINTIE_75"  , ctypes.c_uint8),  # Address offset: 0x112D, clicintie Register
            ("CLICINTIE_76"  , ctypes.c_uint8),  # Address offset: 0x1131, clicintie Register
            ("CLICINTIE_77"  , ctypes.c_uint8),  # Address offset: 0x1135, clicintie Register
            ("CLICINTIE_78"  , ctypes.c_uint8),  # Address offset: 0x1139, clicintie Register
            ("CLICINTIE_79"  , ctypes.c_uint8),  # Address offset: 0x113D, clicintie Register
            ("CLICINTIE_80"  , ctypes.c_uint8),  # Address offset: 0x1141, clicintie Register
            ("CLICINTIE_81"  , ctypes.c_uint8),  # Address offset: 0x1145, clicintie Register
            ("CLICINTIE_82"  , ctypes.c_uint8),  # Address offset: 0x1149, clicintie Register
            ("CLICINTIE_83"  , ctypes.c_uint8),  # Address offset: 0x114D, clicintie Register
            ("CLICINTIE_84"  , ctypes.c_uint8),  # Address offset: 0x1151, clicintie Register
            ("CLICINTIE_85"  , ctypes.c_uint8),  # Address offset: 0x1155, clicintie Register
            ("CLICINTIE_86"  , ctypes.c_uint8),  # Address offset: 0x1159, clicintie Register
            ("CLICINTATTR_0" , ctypes.c_uint8),  # Address offset: 0x1002, clicintattr Register
            ("CLICINTATTR_1" , ctypes.c_uint8),  # Address offset: 0x1006, clicintattr Register
            ("CLICINTATTR_2" , ctypes.c_uint8),  # Address offset: 0x100A, clicintattr Register
            ("CLICINTATTR_3" , ctypes.c_uint8),  # Address offset: 0x100E, clicintattr Register
            ("CLICINTATTR_4" , ctypes.c_uint8),  # Address offset: 0x1012, clicintattr Register
            ("CLICINTATTR_5" , ctypes.c_uint8),  # Address offset: 0x1016, clicintattr Register
            ("CLICINTATTR_6" , ctypes.c_uint8),  # Address offset: 0x101A, clicintattr Register
            ("CLICINTATTR_7" , ctypes.c_uint8),  # Address offset: 0x101E, clicintattr Register
            ("CLICINTATTR_8" , ctypes.c_uint8),  # Address offset: 0x1022, clicintattr Register
            ("CLICINTATTR_9" , ctypes.c_uint8),  # Address offset: 0x1026, clicintattr Register
            ("CLICINTATTR_10", ctypes.c_uint8),  # Address offset: 0x102A, clicintattr Register
            ("CLICINTATTR_11", ctypes.c_uint8),  # Address offset: 0x102E, clicintattr Register
            ("CLICINTATTR_12", ctypes.c_uint8),  # Address offset: 0x1032, clicintattr Register
            ("CLICINTATTR_13", ctypes.c_uint8),  # Address offset: 0x1036, clicintattr Register
            ("CLICINTATTR_14", ctypes.c_uint8),  # Address offset: 0x103A, clicintattr Register
            ("CLICINTATTR_15", ctypes.c_uint8),  # Address offset: 0x103E, clicintattr Register
            ("CLICINTATTR_16", ctypes.c_uint8),  # Address offset: 0x1042, clicintattr Register
            ("CLICINTATTR_17", ctypes.c_uint8),  # Address offset: 0x1046, clicintattr Register
            ("CLICINTATTR_18", ctypes.c_uint8),  # Address offset: 0x104A, clicintattr Register
            ("CLICINTATTR_19", ctypes.c_uint8),  # Address offset: 0x104E, clicintattr Register
            ("CLICINTATTR_20", ctypes.c_uint8),  # Address offset: 0x1052, clicintattr Register
            ("CLICINTATTR_21", ctypes.c_uint8),  # Address offset: 0x1056, clicintattr Register
            ("CLICINTATTR_22", ctypes.c_uint8),  # Address offset: 0x105A, clicintattr Register
            ("CLICINTATTR_23", ctypes.c_uint8),  # Address offset: 0x105E, clicintattr Register
            ("CLICINTATTR_24", ctypes.c_uint8),  # Address offset: 0x1062, clicintattr Register
            ("CLICINTATTR_25", ctypes.c_uint8),  # Address offset: 0x1066, clicintattr Register
            ("CLICINTATTR_26", ctypes.c_uint8),  # Address offset: 0x106A, clicintattr Register
            ("CLICINTATTR_27", ctypes.c_uint8),  # Address offset: 0x106E, clicintattr Register
            ("CLICINTATTR_28", ctypes.c_uint8),  # Address offset: 0x1072, clicintattr Register
            ("CLICINTATTR_29", ctypes.c_uint8),  # Address offset: 0x1076, clicintattr Register
            ("CLICINTATTR_30", ctypes.c_uint8),  # Address offset: 0x107A, clicintattr Register
            ("CLICINTATTR_31", ctypes.c_uint8),  # Address offset: 0x107E, clicintattr Register
            ("CLICINTATTR_32", ctypes.c_uint8),  # Address offset: 0x1082, clicintattr Register
            ("CLICINTATTR_33", ctypes.c_uint8),  # Address offset: 0x1086, clicintattr Register
            ("CLICINTATTR_34", ctypes.c_uint8),  # Address offset: 0x108A, clicintattr Register
            ("CLICINTATTR_35", ctypes.c_uint8),  # Address offset: 0x108E, clicintattr Register
            ("CLICINTATTR_36", ctypes.c_uint8),  # Address offset: 0x1092, clicintattr Register
            ("CLICINTATTR_37", ctypes.c_uint8),  # Address offset: 0x1096, clicintattr Register
            ("CLICINTATTR_38", ctypes.c_uint8),  # Address offset: 0x109A, clicintattr Register
            ("CLICINTATTR_39", ctypes.c_uint8),  # Address offset: 0x109E, clicintattr Register
            ("CLICINTATTR_40", ctypes.c_uint8),  # Address offset: 0x10A2, clicintattr Register
            ("CLICINTATTR_41", ctypes.c_uint8),  # Address offset: 0x10A6, clicintattr Register
            ("CLICINTATTR_42", ctypes.c_uint8),  # Address offset: 0x10AA, clicintattr Register
            ("CLICINTATTR_43", ctypes.c_uint8),  # Address offset: 0x10AE, clicintattr Register
            ("CLICINTATTR_44", ctypes.c_uint8),  # Address offset: 0x10B2, clicintattr Register
            ("CLICINTATTR_45", ctypes.c_uint8),  # Address offset: 0x10B6, clicintattr Register
            ("CLICINTATTR_46", ctypes.c_uint8),  # Address offset: 0x10BA, clicintattr Register
            ("CLICINTATTR_47", ctypes.c_uint8),  # Address offset: 0x10BE, clicintattr Register
            ("CLICINTATTR_48", ctypes.c_uint8),  # Address offset: 0x10C2, clicintattr Register
            ("CLICINTATTR_49", ctypes.c_uint8),  # Address offset: 0x10C6, clicintattr Register
            ("CLICINTATTR_50", ctypes.c_uint8),  # Address offset: 0x10CA, clicintattr Register
            ("CLICINTATTR_51", ctypes.c_uint8),  # Address offset: 0x10CE, clicintattr Register
            ("CLICINTATTR_52", ctypes.c_uint8),  # Address offset: 0x10D2, clicintattr Register
            ("CLICINTATTR_53", ctypes.c_uint8),  # Address offset: 0x10D6, clicintattr Register
            ("CLICINTATTR_54", ctypes.c_uint8),  # Address offset: 0x10DA, clicintattr Register
            ("CLICINTATTR_55", ctypes.c_uint8),  # Address offset: 0x10DE, clicintattr Register
            ("CLICINTATTR_56", ctypes.c_uint8),  # Address offset: 0x10E2, clicintattr Register
            ("CLICINTATTR_57", ctypes.c_uint8),  # Address offset: 0x10E6, clicintattr Register
            ("CLICINTATTR_58", ctypes.c_uint8),  # Address offset: 0x10EA, clicintattr Register
            ("CLICINTATTR_59", ctypes.c_uint8),  # Address offset: 0x10EE, clicintattr Register
            ("CLICINTATTR_60", ctypes.c_uint8),  # Address offset: 0x10F2, clicintattr Register
            ("CLICINTATTR_61", ctypes.c_uint8),  # Address offset: 0x10F6, clicintattr Register
            ("CLICINTATTR_62", ctypes.c_uint8),  # Address offset: 0x10FA, clicintattr Register
            ("CLICINTATTR_63", ctypes.c_uint8),  # Address offset: 0x10FE, clicintattr Register
            ("CLICINTATTR_64", ctypes.c_uint8),  # Address offset: 0x1102, clicintattr Register
            ("CLICINTATTR_65", ctypes.c_uint8),  # Address offset: 0x1106, clicintattr Register
            ("CLICINTATTR_66", ctypes.c_uint8),  # Address offset: 0x110A, clicintattr Register
            ("CLICINTATTR_67", ctypes.c_uint8),  # Address offset: 0x110E, clicintattr Register
            ("CLICINTATTR_68", ctypes.c_uint8),  # Address offset: 0x1112, clicintattr Register
            ("CLICINTATTR_69", ctypes.c_uint8),  # Address offset: 0x1116, clicintattr Register
            ("CLICINTATTR_70", ctypes.c_uint8),  # Address offset: 0x111A, clicintattr Register
            ("CLICINTATTR_71", ctypes.c_uint8),  # Address offset: 0x111E, clicintattr Register
            ("CLICINTATTR_72", ctypes.c_uint8),  # Address offset: 0x1122, clicintattr Register
            ("CLICINTATTR_73", ctypes.c_uint8),  # Address offset: 0x1126, clicintattr Register
            ("CLICINTATTR_74", ctypes.c_uint8),  # Address offset: 0x112A, clicintattr Register
            ("CLICINTATTR_75", ctypes.c_uint8),  # Address offset: 0x112E, clicintattr Register
            ("CLICINTATTR_76", ctypes.c_uint8),  # Address offset: 0x1132, clicintattr Register
            ("CLICINTATTR_77", ctypes.c_uint8),  # Address offset: 0x1136, clicintattr Register
            ("CLICINTATTR_78", ctypes.c_uint8),  # Address offset: 0x113A, clicintattr Register
            ("CLICINTATTR_79", ctypes.c_uint8),  # Address offset: 0x113E, clicintattr Register
            ("CLICINTATTR_80", ctypes.c_uint8),  # Address offset: 0x1142, clicintattr Register
            ("CLICINTATTR_81", ctypes.c_uint8),  # Address offset: 0x1146, clicintattr Register
            ("CLICINTATTR_82", ctypes.c_uint8),  # Address offset: 0x114A, clicintattr Register
            ("CLICINTATTR_83", ctypes.c_uint8),  # Address offset: 0x114E, clicintattr Register
            ("CLICINTATTR_84", ctypes.c_uint8),  # Address offset: 0x1152, clicintattr Register
            ("CLICINTATTR_85", ctypes.c_uint8),  # Address offset: 0x1156, clicintattr Register
            ("CLICINTATTR_86", ctypes.c_uint8),  # Address offset: 0x115A, clicintattr Register
            ("CLICINTCTL_0"  , ctypes.c_uint8),  # Address offset: 0x1003, clicintctl Register
            ("CLICINTCTL_1"  , ctypes.c_uint8),  # Address offset: 0x1007, clicintctl Register
            ("CLICINTCTL_2"  , ctypes.c_uint8),  # Address offset: 0x100B, clicintctl Register
            ("CLICINTCTL_3"  , ctypes.c_uint8),  # Address offset: 0x100F, clicintctl Register
            ("CLICINTCTL_4"  , ctypes.c_uint8),  # Address offset: 0x1013, clicintctl Register
            ("CLICINTCTL_5"  , ctypes.c_uint8),  # Address offset: 0x1017, clicintctl Register
            ("CLICINTCTL_6"  , ctypes.c_uint8),  # Address offset: 0x101B, clicintctl Register
            ("CLICINTCTL_7"  , ctypes.c_uint8),  # Address offset: 0x101F, clicintctl Register
            ("CLICINTCTL_8"  , ctypes.c_uint8),  # Address offset: 0x1023, clicintctl Register
            ("CLICINTCTL_9"  , ctypes.c_uint8),  # Address offset: 0x1027, clicintctl Register
            ("CLICINTCTL_10" , ctypes.c_uint8),  # Address offset: 0x102B, clicintctl Register
            ("CLICINTCTL_11" , ctypes.c_uint8),  # Address offset: 0x102F, clicintctl Register
            ("CLICINTCTL_12" , ctypes.c_uint8),  # Address offset: 0x1033, clicintctl Register
            ("CLICINTCTL_13" , ctypes.c_uint8),  # Address offset: 0x1037, clicintctl Register
            ("CLICINTCTL_14" , ctypes.c_uint8),  # Address offset: 0x103B, clicintctl Register
            ("CLICINTCTL_15" , ctypes.c_uint8),  # Address offset: 0x103F, clicintctl Register
            ("CLICINTCTL_16" , ctypes.c_uint8),  # Address offset: 0x1043, clicintctl Register
            ("CLICINTCTL_17" , ctypes.c_uint8),  # Address offset: 0x1047, clicintctl Register
            ("CLICINTCTL_18" , ctypes.c_uint8),  # Address offset: 0x104B, clicintctl Register
            ("CLICINTCTL_19" , ctypes.c_uint8),  # Address offset: 0x104F, clicintctl Register
            ("CLICINTCTL_20" , ctypes.c_uint8),  # Address offset: 0x1053, clicintctl Register
            ("CLICINTCTL_21" , ctypes.c_uint8),  # Address offset: 0x1057, clicintctl Register
            ("CLICINTCTL_22" , ctypes.c_uint8),  # Address offset: 0x105B, clicintctl Register
            ("CLICINTCTL_23" , ctypes.c_uint8),  # Address offset: 0x105F, clicintctl Register
            ("CLICINTCTL_24" , ctypes.c_uint8),  # Address offset: 0x1063, clicintctl Register
            ("CLICINTCTL_25" , ctypes.c_uint8),  # Address offset: 0x1067, clicintctl Register
            ("CLICINTCTL_26" , ctypes.c_uint8),  # Address offset: 0x106B, clicintctl Register
            ("CLICINTCTL_27" , ctypes.c_uint8),  # Address offset: 0x106F, clicintctl Register
            ("CLICINTCTL_28" , ctypes.c_uint8),  # Address offset: 0x1073, clicintctl Register
            ("CLICINTCTL_29" , ctypes.c_uint8),  # Address offset: 0x1077, clicintctl Register
            ("CLICINTCTL_30" , ctypes.c_uint8),  # Address offset: 0x107B, clicintctl Register
            ("CLICINTCTL_31" , ctypes.c_uint8),  # Address offset: 0x107F, clicintctl Register
            ("CLICINTCTL_32" , ctypes.c_uint8),  # Address offset: 0x1083, clicintctl Register
            ("CLICINTCTL_33" , ctypes.c_uint8),  # Address offset: 0x1087, clicintctl Register
            ("CLICINTCTL_34" , ctypes.c_uint8),  # Address offset: 0x108B, clicintctl Register
            ("CLICINTCTL_35" , ctypes.c_uint8),  # Address offset: 0x108F, clicintctl Register
            ("CLICINTCTL_36" , ctypes.c_uint8),  # Address offset: 0x1093, clicintctl Register
            ("CLICINTCTL_37" , ctypes.c_uint8),  # Address offset: 0x1097, clicintctl Register
            ("CLICINTCTL_38" , ctypes.c_uint8),  # Address offset: 0x109B, clicintctl Register
            ("CLICINTCTL_39" , ctypes.c_uint8),  # Address offset: 0x109F, clicintctl Register
            ("CLICINTCTL_40" , ctypes.c_uint8),  # Address offset: 0x10A3, clicintctl Register
            ("CLICINTCTL_41" , ctypes.c_uint8),  # Address offset: 0x10A7, clicintctl Register
            ("CLICINTCTL_42" , ctypes.c_uint8),  # Address offset: 0x10AB, clicintctl Register
            ("CLICINTCTL_43" , ctypes.c_uint8),  # Address offset: 0x10AF, clicintctl Register
            ("CLICINTCTL_44" , ctypes.c_uint8),  # Address offset: 0x10B3, clicintctl Register
            ("CLICINTCTL_45" , ctypes.c_uint8),  # Address offset: 0x10B7, clicintctl Register
            ("CLICINTCTL_46" , ctypes.c_uint8),  # Address offset: 0x10BB, clicintctl Register
            ("CLICINTCTL_47" , ctypes.c_uint8),  # Address offset: 0x10BF, clicintctl Register
            ("CLICINTCTL_48" , ctypes.c_uint8),  # Address offset: 0x10C3, clicintctl Register
            ("CLICINTCTL_49" , ctypes.c_uint8),  # Address offset: 0x10C7, clicintctl Register
            ("CLICINTCTL_50" , ctypes.c_uint8),  # Address offset: 0x10CB, clicintctl Register
            ("CLICINTCTL_51" , ctypes.c_uint8),  # Address offset: 0x10CF, clicintctl Register
            ("CLICINTCTL_52" , ctypes.c_uint8),  # Address offset: 0x10D3, clicintctl Register
            ("CLICINTCTL_53" , ctypes.c_uint8),  # Address offset: 0x10D7, clicintctl Register
            ("CLICINTCTL_54" , ctypes.c_uint8),  # Address offset: 0x10DB, clicintctl Register
            ("CLICINTCTL_55" , ctypes.c_uint8),  # Address offset: 0x10DF, clicintctl Register
            ("CLICINTCTL_56" , ctypes.c_uint8),  # Address offset: 0x10E3, clicintctl Register
            ("CLICINTCTL_57" , ctypes.c_uint8),  # Address offset: 0x10E7, clicintctl Register
            ("CLICINTCTL_58" , ctypes.c_uint8),  # Address offset: 0x10EB, clicintctl Register
            ("CLICINTCTL_59" , ctypes.c_uint8),  # Address offset: 0x10EF, clicintctl Register
            ("CLICINTCTL_60" , ctypes.c_uint8),  # Address offset: 0x10F3, clicintctl Register
            ("CLICINTCTL_61" , ctypes.c_uint8),  # Address offset: 0x10F7, clicintctl Register
            ("CLICINTCTL_62" , ctypes.c_uint8),  # Address offset: 0x10FB, clicintctl Register
            ("CLICINTCTL_63" , ctypes.c_uint8),  # Address offset: 0x10FF, clicintctl Register
            ("CLICINTCTL_64" , ctypes.c_uint8),  # Address offset: 0x1103, clicintctl Register
            ("CLICINTCTL_65" , ctypes.c_uint8),  # Address offset: 0x1107, clicintctl Register
            ("CLICINTCTL_66" , ctypes.c_uint8),  # Address offset: 0x110B, clicintctl Register
            ("CLICINTCTL_67" , ctypes.c_uint8),  # Address offset: 0x110F, clicintctl Register
            ("CLICINTCTL_68" , ctypes.c_uint8),  # Address offset: 0x1113, clicintctl Register
            ("CLICINTCTL_69" , ctypes.c_uint8),  # Address offset: 0x1117, clicintctl Register
            ("CLICINTCTL_70" , ctypes.c_uint8),  # Address offset: 0x111B, clicintctl Register
            ("CLICINTCTL_71" , ctypes.c_uint8),  # Address offset: 0x111F, clicintctl Register
            ("CLICINTCTL_72" , ctypes.c_uint8),  # Address offset: 0x1123, clicintctl Register
            ("CLICINTCTL_73" , ctypes.c_uint8),  # Address offset: 0x1127, clicintctl Register
            ("CLICINTCTL_74" , ctypes.c_uint8),  # Address offset: 0x112B, clicintctl Register
            ("CLICINTCTL_75" , ctypes.c_uint8),  # Address offset: 0x112F, clicintctl Register
            ("CLICINTCTL_76" , ctypes.c_uint8),  # Address offset: 0x1133, clicintctl Register
            ("CLICINTCTL_77" , ctypes.c_uint8),  # Address offset: 0x1137, clicintctl Register
            ("CLICINTCTL_78" , ctypes.c_uint8),  # Address offset: 0x113B, clicintctl Register
            ("CLICINTCTL_79" , ctypes.c_uint8),  # Address offset: 0x113F, clicintctl Register
            ("CLICINTCTL_80" , ctypes.c_uint8),  # Address offset: 0x1143, clicintctl Register
            ("CLICINTCTL_81" , ctypes.c_uint8),  # Address offset: 0x1147, clicintctl Register
            ("CLICINTCTL_82" , ctypes.c_uint8),  # Address offset: 0x114B, clicintctl Register
            ("CLICINTCTL_83" , ctypes.c_uint8),  # Address offset: 0x114F, clicintctl Register
            ("CLICINTCTL_84" , ctypes.c_uint8),  # Address offset: 0x1153, clicintctl Register
            ("CLICINTCTL_85" , ctypes.c_uint8),  # Address offset: 0x1157, clicintctl Register
            ("CLICINTCTL_86" , ctypes.c_uint8),  # Address offset: 0x115B, clicintctl Register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.eclic = self.struct(
            CLICCFG        =  0x00000000,
            CLICINFO       =  0x00000000,
            MTH            =  0x00000000,
            CLICINTIP_0    =  0x00000000,
            CLICINTIP_1    =  0x00000000,
            CLICINTIP_2    =  0x00000000,
            CLICINTIP_3    =  0x00000000,
            CLICINTIP_4    =  0x00000000,
            CLICINTIP_5    =  0x00000000,
            CLICINTIP_6    =  0x00000000,
            CLICINTIP_7    =  0x00000000,
            CLICINTIP_8    =  0x00000000,
            CLICINTIP_9    =  0x00000000,
            CLICINTIP_10   =  0x00000000,
            CLICINTIP_11   =  0x00000000,
            CLICINTIP_12   =  0x00000000,
            CLICINTIP_13   =  0x00000000,
            CLICINTIP_14   =  0x00000000,
            CLICINTIP_15   =  0x00000000,
            CLICINTIP_16   =  0x00000000,
            CLICINTIP_17   =  0x00000000,
            CLICINTIP_18   =  0x00000000,
            CLICINTIP_19   =  0x00000000,
            CLICINTIP_20   =  0x00000000,
            CLICINTIP_21   =  0x00000000,
            CLICINTIP_22   =  0x00000000,
            CLICINTIP_23   =  0x00000000,
            CLICINTIP_24   =  0x00000000,
            CLICINTIP_25   =  0x00000000,
            CLICINTIP_26   =  0x00000000,
            CLICINTIP_27   =  0x00000000,
            CLICINTIP_28   =  0x00000000,
            CLICINTIP_29   =  0x00000000,
            CLICINTIP_30   =  0x00000000,
            CLICINTIP_31   =  0x00000000,
            CLICINTIP_32   =  0x00000000,
            CLICINTIP_33   =  0x00000000,
            CLICINTIP_34   =  0x00000000,
            CLICINTIP_35   =  0x00000000,
            CLICINTIP_36   =  0x00000000,
            CLICINTIP_37   =  0x00000000,
            CLICINTIP_38   =  0x00000000,
            CLICINTIP_39   =  0x00000000,
            CLICINTIP_40   =  0x00000000,
            CLICINTIP_41   =  0x00000000,
            CLICINTIP_42   =  0x00000000,
            CLICINTIP_43   =  0x00000000,
            CLICINTIP_44   =  0x00000000,
            CLICINTIP_45   =  0x00000000,
            CLICINTIP_46   =  0x00000000,
            CLICINTIP_47   =  0x00000000,
            CLICINTIP_48   =  0x00000000,
            CLICINTIP_49   =  0x00000000,
            CLICINTIP_50   =  0x00000000,
            CLICINTIP_51   =  0x00000000,
            CLICINTIP_52   =  0x00000000,
            CLICINTIP_53   =  0x00000000,
            CLICINTIP_54   =  0x00000000,
            CLICINTIP_55   =  0x00000000,
            CLICINTIP_56   =  0x00000000,
            CLICINTIP_57   =  0x00000000,
            CLICINTIP_58   =  0x00000000,
            CLICINTIP_59   =  0x00000000,
            CLICINTIP_60   =  0x00000000,
            CLICINTIP_61   =  0x00000000,
            CLICINTIP_62   =  0x00000000,
            CLICINTIP_63   =  0x00000000,
            CLICINTIP_64   =  0x00000000,
            CLICINTIP_65   =  0x00000000,
            CLICINTIP_66   =  0x00000000,
            CLICINTIP_67   =  0x00000000,
            CLICINTIP_68   =  0x00000000,
            CLICINTIP_69   =  0x00000000,
            CLICINTIP_70   =  0x00000000,
            CLICINTIP_71   =  0x00000000,
            CLICINTIP_72   =  0x00000000,
            CLICINTIP_73   =  0x00000000,
            CLICINTIP_74   =  0x00000000,
            CLICINTIP_75   =  0x00000000,
            CLICINTIP_76   =  0x00000000,
            CLICINTIP_77   =  0x00000000,
            CLICINTIP_78   =  0x00000000,
            CLICINTIP_79   =  0x00000000,
            CLICINTIP_80   =  0x00000000,
            CLICINTIP_81   =  0x00000000,
            CLICINTIP_82   =  0x00000000,
            CLICINTIP_83   =  0x00000000,
            CLICINTIP_84   =  0x00000000,
            CLICINTIP_85   =  0x00000000,
            CLICINTIP_86   =  0x00000000,
            CLICINTIE_0    =  0x00000000,
            CLICINTIE_1    =  0x00000000,
            CLICINTIE_2    =  0x00000000,
            CLICINTIE_3    =  0x00000000,
            CLICINTIE_4    =  0x00000000,
            CLICINTIE_5    =  0x00000000,
            CLICINTIE_6    =  0x00000000,
            CLICINTIE_7    =  0x00000000,
            CLICINTIE_8    =  0x00000000,
            CLICINTIE_9    =  0x00000000,
            CLICINTIE_10   =  0x00000000,
            CLICINTIE_11   =  0x00000000,
            CLICINTIE_12   =  0x00000000,
            CLICINTIE_13   =  0x00000000,
            CLICINTIE_14   =  0x00000000,
            CLICINTIE_15   =  0x00000000,
            CLICINTIE_16   =  0x00000000,
            CLICINTIE_17   =  0x00000000,
            CLICINTIE_18   =  0x00000000,
            CLICINTIE_19   =  0x00000000,
            CLICINTIE_20   =  0x00000000,
            CLICINTIE_21   =  0x00000000,
            CLICINTIE_22   =  0x00000000,
            CLICINTIE_23   =  0x00000000,
            CLICINTIE_24   =  0x00000000,
            CLICINTIE_25   =  0x00000000,
            CLICINTIE_26   =  0x00000000,
            CLICINTIE_27   =  0x00000000,
            CLICINTIE_28   =  0x00000000,
            CLICINTIE_29   =  0x00000000,
            CLICINTIE_30   =  0x00000000,
            CLICINTIE_31   =  0x00000000,
            CLICINTIE_32   =  0x00000000,
            CLICINTIE_33   =  0x00000000,
            CLICINTIE_34   =  0x00000000,
            CLICINTIE_35   =  0x00000000,
            CLICINTIE_36   =  0x00000000,
            CLICINTIE_37   =  0x00000000,
            CLICINTIE_38   =  0x00000000,
            CLICINTIE_39   =  0x00000000,
            CLICINTIE_40   =  0x00000000,
            CLICINTIE_41   =  0x00000000,
            CLICINTIE_42   =  0x00000000,
            CLICINTIE_43   =  0x00000000,
            CLICINTIE_44   =  0x00000000,
            CLICINTIE_45   =  0x00000000,
            CLICINTIE_46   =  0x00000000,
            CLICINTIE_47   =  0x00000000,
            CLICINTIE_48   =  0x00000000,
            CLICINTIE_49   =  0x00000000,
            CLICINTIE_50   =  0x00000000,
            CLICINTIE_51   =  0x00000000,
            CLICINTIE_52   =  0x00000000,
            CLICINTIE_53   =  0x00000000,
            CLICINTIE_54   =  0x00000000,
            CLICINTIE_55   =  0x00000000,
            CLICINTIE_56   =  0x00000000,
            CLICINTIE_57   =  0x00000000,
            CLICINTIE_58   =  0x00000000,
            CLICINTIE_59   =  0x00000000,
            CLICINTIE_60   =  0x00000000,
            CLICINTIE_61   =  0x00000000,
            CLICINTIE_62   =  0x00000000,
            CLICINTIE_63   =  0x00000000,
            CLICINTIE_64   =  0x00000000,
            CLICINTIE_65   =  0x00000000,
            CLICINTIE_66   =  0x00000000,
            CLICINTIE_67   =  0x00000000,
            CLICINTIE_68   =  0x00000000,
            CLICINTIE_69   =  0x00000000,
            CLICINTIE_70   =  0x00000000,
            CLICINTIE_71   =  0x00000000,
            CLICINTIE_72   =  0x00000000,
            CLICINTIE_73   =  0x00000000,
            CLICINTIE_74   =  0x00000000,
            CLICINTIE_75   =  0x00000000,
            CLICINTIE_76   =  0x00000000,
            CLICINTIE_77   =  0x00000000,
            CLICINTIE_78   =  0x00000000,
            CLICINTIE_79   =  0x00000000,
            CLICINTIE_80   =  0x00000000,
            CLICINTIE_81   =  0x00000000,
            CLICINTIE_82   =  0x00000000,
            CLICINTIE_83   =  0x00000000,
            CLICINTIE_84   =  0x00000000,
            CLICINTIE_85   =  0x00000000,
            CLICINTIE_86   =  0x00000000,
            CLICINTATTR_0  =  0x00000000,
            CLICINTATTR_1  =  0x00000000,
            CLICINTATTR_2  =  0x00000000,
            CLICINTATTR_3  =  0x00000000,
            CLICINTATTR_4  =  0x00000000,
            CLICINTATTR_5  =  0x00000000,
            CLICINTATTR_6  =  0x00000000,
            CLICINTATTR_7  =  0x00000000,
            CLICINTATTR_8  =  0x00000000,
            CLICINTATTR_9  =  0x00000000,
            CLICINTATTR_10 =  0x00000000,
            CLICINTATTR_11 =  0x00000000,
            CLICINTATTR_12 =  0x00000000,
            CLICINTATTR_13 =  0x00000000,
            CLICINTATTR_14 =  0x00000000,
            CLICINTATTR_15 =  0x00000000,
            CLICINTATTR_16 =  0x00000000,
            CLICINTATTR_17 =  0x00000000,
            CLICINTATTR_18 =  0x00000000,
            CLICINTATTR_19 =  0x00000000,
            CLICINTATTR_20 =  0x00000000,
            CLICINTATTR_21 =  0x00000000,
            CLICINTATTR_22 =  0x00000000,
            CLICINTATTR_23 =  0x00000000,
            CLICINTATTR_24 =  0x00000000,
            CLICINTATTR_25 =  0x00000000,
            CLICINTATTR_26 =  0x00000000,
            CLICINTATTR_27 =  0x00000000,
            CLICINTATTR_28 =  0x00000000,
            CLICINTATTR_29 =  0x00000000,
            CLICINTATTR_30 =  0x00000000,
            CLICINTATTR_31 =  0x00000000,
            CLICINTATTR_32 =  0x00000000,
            CLICINTATTR_33 =  0x00000000,
            CLICINTATTR_34 =  0x00000000,
            CLICINTATTR_35 =  0x00000000,
            CLICINTATTR_36 =  0x00000000,
            CLICINTATTR_37 =  0x00000000,
            CLICINTATTR_38 =  0x00000000,
            CLICINTATTR_39 =  0x00000000,
            CLICINTATTR_40 =  0x00000000,
            CLICINTATTR_41 =  0x00000000,
            CLICINTATTR_42 =  0x00000000,
            CLICINTATTR_43 =  0x00000000,
            CLICINTATTR_44 =  0x00000000,
            CLICINTATTR_45 =  0x00000000,
            CLICINTATTR_46 =  0x00000000,
            CLICINTATTR_47 =  0x00000000,
            CLICINTATTR_48 =  0x00000000,
            CLICINTATTR_49 =  0x00000000,
            CLICINTATTR_50 =  0x00000000,
            CLICINTATTR_51 =  0x00000000,
            CLICINTATTR_52 =  0x00000000,
            CLICINTATTR_53 =  0x00000000,
            CLICINTATTR_54 =  0x00000000,
            CLICINTATTR_55 =  0x00000000,
            CLICINTATTR_56 =  0x00000000,
            CLICINTATTR_57 =  0x00000000,
            CLICINTATTR_58 =  0x00000000,
            CLICINTATTR_59 =  0x00000000,
            CLICINTATTR_60 =  0x00000000,
            CLICINTATTR_61 =  0x00000000,
            CLICINTATTR_62 =  0x00000000,
            CLICINTATTR_63 =  0x00000000,
            CLICINTATTR_64 =  0x00000000,
            CLICINTATTR_65 =  0x00000000,
            CLICINTATTR_66 =  0x00000000,
            CLICINTATTR_67 =  0x00000000,
            CLICINTATTR_68 =  0x00000000,
            CLICINTATTR_69 =  0x00000000,
            CLICINTATTR_70 =  0x00000000,
            CLICINTATTR_71 =  0x00000000,
            CLICINTATTR_72 =  0x00000000,
            CLICINTATTR_73 =  0x00000000,
            CLICINTATTR_74 =  0x00000000,
            CLICINTATTR_75 =  0x00000000,
            CLICINTATTR_76 =  0x00000000,
            CLICINTATTR_77 =  0x00000000,
            CLICINTATTR_78 =  0x00000000,
            CLICINTATTR_79 =  0x00000000,
            CLICINTATTR_80 =  0x00000000,
            CLICINTATTR_81 =  0x00000000,
            CLICINTATTR_82 =  0x00000000,
            CLICINTATTR_83 =  0x00000000,
            CLICINTATTR_84 =  0x00000000,
            CLICINTATTR_85 =  0x00000000,
            CLICINTATTR_86 =  0x00000000,
            CLICINTCTL_0   =  0x00000000,
            CLICINTCTL_1   =  0x00000000,
            CLICINTCTL_2   =  0x00000000,
            CLICINTCTL_3   =  0x00000000,
            CLICINTCTL_4   =  0x00000000,
            CLICINTCTL_5   =  0x00000000,
            CLICINTCTL_6   =  0x00000000,
            CLICINTCTL_7   =  0x00000000,
            CLICINTCTL_8   =  0x00000000,
            CLICINTCTL_9   =  0x00000000,
            CLICINTCTL_10  =  0x00000000,
            CLICINTCTL_11  =  0x00000000,
            CLICINTCTL_12  =  0x00000000,
            CLICINTCTL_13  =  0x00000000,
            CLICINTCTL_14  =  0x00000000,
            CLICINTCTL_15  =  0x00000000,
            CLICINTCTL_16  =  0x00000000,
            CLICINTCTL_17  =  0x00000000,
            CLICINTCTL_18  =  0x00000000,
            CLICINTCTL_19  =  0x00000000,
            CLICINTCTL_20  =  0x00000000,
            CLICINTCTL_21  =  0x00000000,
            CLICINTCTL_22  =  0x00000000,
            CLICINTCTL_23  =  0x00000000,
            CLICINTCTL_24  =  0x00000000,
            CLICINTCTL_25  =  0x00000000,
            CLICINTCTL_26  =  0x00000000,
            CLICINTCTL_27  =  0x00000000,
            CLICINTCTL_28  =  0x00000000,
            CLICINTCTL_29  =  0x00000000,
            CLICINTCTL_30  =  0x00000000,
            CLICINTCTL_31  =  0x00000000,
            CLICINTCTL_32  =  0x00000000,
            CLICINTCTL_33  =  0x00000000,
            CLICINTCTL_34  =  0x00000000,
            CLICINTCTL_35  =  0x00000000,
            CLICINTCTL_36  =  0x00000000,
            CLICINTCTL_37  =  0x00000000,
            CLICINTCTL_38  =  0x00000000,
            CLICINTCTL_39  =  0x00000000,
            CLICINTCTL_40  =  0x00000000,
            CLICINTCTL_41  =  0x00000000,
            CLICINTCTL_42  =  0x00000000,
            CLICINTCTL_43  =  0x00000000,
            CLICINTCTL_44  =  0x00000000,
            CLICINTCTL_45  =  0x00000000,
            CLICINTCTL_46  =  0x00000000,
            CLICINTCTL_47  =  0x00000000,
            CLICINTCTL_48  =  0x00000000,
            CLICINTCTL_49  =  0x00000000,
            CLICINTCTL_50  =  0x00000000,
            CLICINTCTL_51  =  0x00000000,
            CLICINTCTL_52  =  0x00000000,
            CLICINTCTL_53  =  0x00000000,
            CLICINTCTL_54  =  0x00000000,
            CLICINTCTL_55  =  0x00000000,
            CLICINTCTL_56  =  0x00000000,
            CLICINTCTL_57  =  0x00000000,
            CLICINTCTL_58  =  0x00000000,
            CLICINTCTL_59  =  0x00000000,
            CLICINTCTL_60  =  0x00000000,
            CLICINTCTL_61  =  0x00000000,
            CLICINTCTL_62  =  0x00000000,
            CLICINTCTL_63  =  0x00000000,
            CLICINTCTL_64  =  0x00000000,
            CLICINTCTL_65  =  0x00000000,
            CLICINTCTL_66  =  0x00000000,
            CLICINTCTL_67  =  0x00000000,
            CLICINTCTL_68  =  0x00000000,
            CLICINTCTL_69  =  0x00000000,
            CLICINTCTL_70  =  0x00000000,
            CLICINTCTL_71  =  0x00000000,
            CLICINTCTL_72  =  0x00000000,
            CLICINTCTL_73  =  0x00000000,
            CLICINTCTL_74  =  0x00000000,
            CLICINTCTL_75  =  0x00000000,
            CLICINTCTL_76  =  0x00000000,
            CLICINTCTL_77  =  0x00000000,
            CLICINTCTL_78  =  0x00000000,
            CLICINTCTL_79  =  0x00000000,
            CLICINTCTL_80  =  0x00000000,
            CLICINTCTL_81  =  0x00000000,
            CLICINTCTL_82  =  0x00000000,
            CLICINTCTL_83  =  0x00000000,
            CLICINTCTL_84  =  0x00000000,
            CLICINTCTL_85  =  0x00000000,
            CLICINTCTL_86  =  0x00000000,
        )

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.gpio) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.gpio) + offset, data, size)
