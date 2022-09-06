#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
from Registry import Registry

# ERRORS CODE
# https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
ERROR_SUCCESS = 0x0
ERROR_INVALID_FUNCTION = 0x1
ERROR_FILE_NOT_FOUND = 0x2
ERROR_PATH_NOT_FOUND = 0x3
ERROR_ACCESS_DENIED = 0x5
ERROR_INVALID_HANDLE = 0x6
ERROR_INVALID_PARAMETER = 0x57
ERROR_BUFFER_OVERFLOW = 0x6F
ERROR_INSUFFICIENT_BUFFER = 0x7A
ERROR_ALREADY_EXISTS = 0xB7
ERROR_MORE_DATA = 0xEA
ERROR_NO_MORE_ITEMS = 0x103
ERROR_NOT_OWNER = 0x120
ERROR_OLD_WIN_VERSION = 0X47E
# ...

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
STATUS_SUCCESS = 0
STATUS_UNSUCCESSFUL = 0xC0000001
# ...
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_PORT_NOT_SET = 0xC0000353
STATUS_NO_YIELD_PERFORMED = 0x40000024
# ...

INVALID_HANDLE_VALUE = -1

STD_INPUT_HANDLE = 0xfffffff6
STD_OUTPUT_HANDLE = 0xfffffff5
STD_ERROR_HANDLE = 0xfffffff4

# Registry Type

# Predefined Keys
REG_KEYS = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000005: "HKEY_CURRENT_CONFIG",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000007: "HKEY_CURRENT_USER_LOCAL_SETTINGS",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000004: "HKEY_PERFORMANCE_DATA",
    0x80000060: "HKEY_PERFORMANCE_NLSTEXT",
    0x80000050: "HKEY_PERFORMANCE_TEXT",
    0x80000003: "HKEY_USERS"
}

REG_TYPES = {
    "REG_NONE": Registry.RegNone,
    "REG_SZ": Registry.RegSZ,
    "REG_EXPAND_SZ": Registry.RegExpandSZ,
    "REG_BINARY": Registry.RegBin,
    "REG_DWORD": Registry.RegDWord,
    "REG_DWORD_BIG_ENDIAN": Registry.RegBigEndian,
    "REG_LINK": Registry.RegLink,
    "REG_MULTI_SZ": Registry.RegMultiSZ,
    "REG_RESOURCE_LIST": Registry.RegResourceList,
    "REG_FULL_RESOURCE_DESCRIPTOR": Registry.RegFullResourceDescriptor,
    "REG_RESOURCE_REQUIREMENTS_LIST": Registry.RegResourceRequirementsList,
    "REG_QWORD": Registry.RegQWord,

    Registry.RegNone: "REG_NONE",
    Registry.RegSZ: "REG_SZ",
    Registry.RegExpandSZ: "REG_EXPAND_SZ",
    Registry.RegBin: "REG_BINARY",
    Registry.RegDWord: "REG_DWORD",
    Registry.RegBigEndian: "REG_DWORD_BIG_ENDIAN",
    Registry.RegLink: "REG_LINK",
    Registry.RegMultiSZ: "REG_MULTI_SZ",
    Registry.RegResourceList: "REG_RESOURCE_LIST",
    Registry.RegFullResourceDescriptor: "REG_FULL_RESOURCE_DESCRIPTOR",
    Registry.RegResourceRequirementsList: "REG_RESOURCE_REQUIREMENTS_LIST",
    Registry.RegQWord: "REG_QWORD"
}

RTL_MAXIMUM_ATOM_LENGTH = 255
RTL_USER_PROCESS_PARAMETERS_NORMALIZED = 0x01
RTL_USER_PROCESS_PARAMETERS_PROFILE_USER = 0x02
RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL = 0x04
RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER = 0x08
RTL_USER_PROCESS_PARAMETERS_UNKNOWN = 0x10
RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB = 0x20
RTL_USER_PROCESS_PARAMETERS_RESERVE_16MB = 0x40
RTL_USER_PROCESS_PARAMETERS_CASE_SENSITIVE = 0x80
RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS = 0x100
RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_1 = 0x200
RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_2 = 0x400
RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH = 0x1000
RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH = 0x2000
RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING = 0x4000
RTL_USER_PROCESS_PARAMETERS_NX = 0x20000
RTL_MAX_DRIVE_LETTERS = 32
RTL_DRIVE_LETTER_VALID = 0x0001
# EXCEPTION_CHAIN_END = ((PEXCEPTION_REGISTRATION_RECORD)-1)
SEM_FAILCRITICALERRORS = 0x0001
SEM_NOGPFAULTERRORBOX = 0x0002
SEM_NOALIGNMENTFAULTEXCEPT = 0x0004
SEM_NOOPENFILEERRORBOX = 0x8000
RTL_SEM_FAILCRITICALERRORS = (SEM_FAILCRITICALERRORS << 4)
RTL_SEM_NOGPFAULTERRORBOX = (SEM_NOGPFAULTERRORBOX << 4)
RTL_SEM_NOALIGNMENTFAULTEXCEPT = (SEM_NOALIGNMENTFAULTEXCEPT << 4)
RTL_RANGE_LIST_ADD_IF_CONFLICT = 0x00000001
RTL_RANGE_LIST_ADD_SHARED = 0x00000002
RTL_RANGE_SHARED = 0x01
RTL_RANGE_CONFLICT = 0x02
RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_RELEASE_ON_DEACTIVATION = 0x01
RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NO_DEACTIVATE = 0x02
RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ON_FREE_LIST = 0x04
RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_HEAP_ALLOCATED = 0x08
RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_NOT_REALLY_ACTIVATED = 0x10
RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_ACTIVATED = 0x20
RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_DEACTIVATED = 0x40
RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_FORMAT_WHISTLER = 0x01
RTL_ACTIVATE_ACTIVATION_CONTEXT_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION = 0x01
RTL_DEACTIVATE_ACTIVATION_CONTEXT_FLAG_FORCE_EARLY_DEACTIVATION = 0x01
RTL_QUERY_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT = 0x01
RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_HMODULE = 0x02
RTL_QUERY_ACTIVATION_CONTEXT_FLAG_IS_ADDRESS = 0x04
RTL_QUERY_ACTIVATION_CONTEXT_FLAG_NO_ADDREF = 0x80000000
HEAP_SETTABLE_USER_VALUE = 0x00000100
HEAP_SETTABLE_USER_FLAG1 = 0x00000200
HEAP_SETTABLE_USER_FLAG2 = 0x00000400
HEAP_SETTABLE_USER_FLAG3 = 0x00000800
HEAP_SETTABLE_USER_FLAGS = 0x00000E00
HEAP_CLASS_0 = 0x00000000
HEAP_CLASS_1 = 0x00001000
HEAP_CLASS_2 = 0x00002000
HEAP_CLASS_3 = 0x00003000
HEAP_CLASS_4 = 0x00004000
HEAP_CLASS_5 = 0x00005000
HEAP_CLASS_6 = 0x00006000
HEAP_CLASS_7 = 0x00007000
HEAP_CLASS_8 = 0x00008000
HEAP_CLASS_MASK = 0x0000F000
HEAP_FLAG_ALLOCS = 0x01000000
HEAP_PROTECTION_ENABLED = 0x02000000
HEAP_BREAK_WHEN_OUT_OF_VM = 0x04000000
HEAP_NO_ALIGNMENT = 0x08000000
HEAP_CAPTURE_STACK_BACKTRACES = 0x08000000
HEAP_SKIP_VALIDATION_CHECKS = 0x10000000
HEAP_VALIDATE_ALL_ENABLED = 0x20000000
HEAP_VALIDATE_PARAMETERS_ENABLED = 0x40000000
HEAP_LOCK_USER_ALLOCATED = 0x80000000
# HEAP_CREATE_VALID_MASK
RTL_REGISTRY_ABSOLUTE = 0
RTL_REGISTRY_SERVICES = 1
RTL_REGISTRY_CONTROL = 2
RTL_REGISTRY_WINDOWS_NT = 3
RTL_REGISTRY_DEVICEMAP = 4
RTL_REGISTRY_USER = 5
RTL_REGISTRY_MAXIMUM = 6
RTL_REGISTRY_HANDLE = 0x40000000
RTL_REGISTRY_OPTIONAL = 0x80000000
RTL_QUERY_REGISTRY_SUBKEY = 0x00000001
RTL_QUERY_REGISTRY_TOPKEY = 0x00000002
RTL_QUERY_REGISTRY_REQUIRED = 0x00000004
RTL_QUERY_REGISTRY_NOVALUE = 0x00000008
RTL_QUERY_REGISTRY_NOEXPAND = 0x00000010
RTL_QUERY_REGISTRY_DIRECT = 0x00000020
RTL_QUERY_REGISTRY_DELETE = 0x00000040
VER_MINORVERSION = 0x0000001
VER_MAJORVERSION = 0x0000002
VER_BUILDNUMBER = 0x0000004
VER_PLATFORMID = 0x0000008
VER_SERVICEPACKMINOR = 0x0000010
VER_SERVICEPACKMAJOR = 0x0000020
VER_SUITENAME = 0x0000040
VER_PRODUCT_TYPE = 0x0000080
VER_PLATFORM_WIN32s = 0
VER_PLATFORM_WIN32_WINDOWS = 1
VER_PLATFORM_WIN32_NT = 2
VER_EQUAL = 1
VER_GREATER = 2
VER_GREATER_EQUAL = 3
VER_LESS = 4
VER_LESS_EQUAL = 5
VER_AND = 6
VER_OR = 7
VER_CONDITION_MASK = 7
VER_NUM_BITS_PER_CONDITION_MASK = 3
TIME_ZONE_ID_UNKNOWN = 0
TIME_ZONE_ID_STANDARD = 1
TIME_ZONE_ID_DAYLIGHT = 2
MAX_PATH = 260
RTL_CRITSECT_TYPE = 0
RTL_RESOURCE_TYPE = 1
RTL_ACQUIRE_PRIVILEGE_IMPERSONATE = 1
RTL_ACQUIRE_PRIVILEGE_PROCESS = 2
MESSAGE_RESOURCE_UNICODE = 0x0001
MAXIMUM_LEADBYTES = 12
RTL_DEBUG_QUERY_MODULES = 0x01
RTL_DEBUG_QUERY_BACKTRACES = 0x02
RTL_DEBUG_QUERY_HEAPS = 0x04
RTL_DEBUG_QUERY_HEAP_TAGS = 0x08
RTL_DEBUG_QUERY_HEAP_BLOCKS = 0x10
RTL_DEBUG_QUERY_LOCKS = 0x20
RTL_HANDLE_VALID = 0x1
RTL_ATOM_IS_PINNED = 0x1
CS_LOCK_BIT = 0x1
CS_LOCK_BIT_V = 0x0
CS_LOCK_WAITER_WOKEN = 0x2
CS_LOCK_WAITER_INC = 0x4
# RTL_CONSTANT_LARGE_INTEGER(quad_part) = { { (quad_part), (quad_part)>>32 } }
# RTL_MAKE_LARGE_INTEGER(low_part, high_part) = { { (low_part), (high_part) } }
RTL_FLS_MAXIMUM_AVAILABLE = 128
RTL_RESOURCE_FLAG_LONG_TERM = 0x00000001
# UMSCTX_SCHEDULED_THREAD_MASK = (1 << UMSCTX_SCHEDULED_THREAD_BIT)
# UMSCTX_SUSPENDED_MASK = (1 << UMSCTX_SUSPENDED_BIT)
# UMSCTX_VOLATILE_CONTEXT_MASK = (1 << UMSCTX_VOLATILE_CONTEXT_BIT)
# UMSCTX_TERMINATED_MASK = (1 << UMSCTX_TERMINATED_BIT)
# UMSCTX_DEBUG_ACTIVE_MASK = (1 << UMSCTX_DEBUG_ACTIVE_BIT)
# UMSCTX_RUNNING_ON_SELF_THREAD_MASK = (1 << UMSCTX_RUNNING_ON_SELF_THREAD_BIT)
# UMSCTX_DENY_RUNNING_ON_SELF_THREAD_MASK = (1 << UMSCTX_DENY_RUNNING_ON_SELF_THREAD_BIT)


# File operation
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
GENERIC_EXECUTE = 0x20000000

CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
TRUNCATE_EXISTING = 5

# HRESULT values
S_OK = 0x00
S_FALSE = 0x01
E_ABORT = 0x80004004
E_ACCESSDENIED = 0x80070005
E_FAIL = 0x80004005
E_HANDLE = 0x80070006
E_INVALIDARG = 0x80070057
E_NOINTERFACE = 0x80004002
E_NOTIMPL = 0x80004001
E_OUTOFMEMORY = 0x8007000E
E_POINTER = 0x80004003
E_UNEXPECTED = 0x8000FFFF

# LOCALE values
# https://docs.microsoft.com/it-it/windows/win32/intl/locale-custom-constants
LOCALE_USER_DEFAULT = 0x0400
LOCALE_CUSTOM_DEFAULT = 0x0C00
LOCALE_CUSTOM_UI_DEFAULT = 0x1400
LOCALE_CUSTOM_UNSPECIFIED = 0x1000

LOCALE_EN_US = {
    # http://www.borgendale.com/locale/en_US.htm
    0x1004: "utf-8",
    0x1005: "\x00",
    0x1009: "1",
    "sName": "en_US",
    "xLocaleToken": "100210e9",
    "xWinLocale": "0409",
    "sEngLanguage": "English",
    "sEngCountry": "United States",
    "sCountry": "United States",
    "sLanguage": "English",
    "sNativeCtryName": "United States",
    "sLanguageID": "en",
    "sCountryID": "US",
    "iCountry": "1",
    "sAbbrevLangName": "ENU",
    "jISO3CountryName": "USA",
    "iCodepage": "437",
    "iAltCodepage": "850",
    "iAnsiCodepage": "1252",
    "sISOCodepage": "ISO8859-1",
    "iMacCodepage": "1275",
    "iEbcdicCodepage": "37",
    "sSetCodepage": "",
    "sKeyboard": "us",
    "sCollate": "",
    "sCurrency": "$",
    "sIntlSymbol": "USD",
    "iCurrency": 0,
    "iCurrDigits": 2,
    "iNegCurr": 0,
    "sMonDecimalSep": ".",
    "sMonThousandSep": ",",
    "sMonGrouping": "«3»",
    "iDigits": 2,
    "iNegNumber": 1,
    "sDecimal": ".",
    "sThousand": ",",
    "sGrouping": "«3»",
    "iLzero": 0,
    "iTLzero": 0,
    "sList": ",",
    "iMeasure": 1,
    "iPaper": 1,
    "iTime": 0,
    "iDate": 0,
    "sDate": "/",
    "sTime": ":",
    "sDateTime": "%a %b %e %H:%M:%S %Z %Y",
    "sShortDate": "%m/%d/%y",
    "sTimeFormat": "%I:%M:%S %p",
    "sLongDate": "%B %d, %Y",
    "wTimeFormat": "hh:mm:ss tt",
    "wShortDate": "MM/dd/yy",
    "wLongDate": "MMMM dd, yyyy",
    "iLDate": 0,
    "iCalendarType": 1,
    "iFirstDayOfWeek": 6,
    "iFirstWeekOfYear": 0,
    "iTimePrefix": 0,
    "s1159": "am",
    "s2359": "pm",
    "sDayName7": "Sunday",
    "sDayName1": "Monday",
    "sDayName2": "Tuesday",
    "sDayName3": "Wednesday",
    "sDayName4": "Thursday",
    "sDayName5": "Friday",
    "sDayName6": "Saturday",
    "sAbbrevDayName7": "Sun",
    "sAbbrevDayName1": "Mon",
    "sAbbrevDayName2": "Tue",
    "sAbbrevDayName3": "Wed",
    "sAbbrevDayName4": "Thu",
    "sAbbrevDayName5": "Fri",
    "sAbbrevDayName6": "Sat",
    "sMonthName1": "January",
    "sMonthName2": "February",
    "sMonthName3": "March",
    "sMonthName4": "April",
    "sMonthName5": "May",
    "sMonthName6": "June",
    "sMonthName7": "July",
    "sMonthName8": "August",
    "sMonthName9": "September",
    "sMonthName10": "October",
    "sMonthName11": "November",
    "sMonthName12": "December",
    "sAbbrevMonthName1": "Jan",
    "sAbbrevMonthName2": "Feb",
    "sAbbrevMonthName3": "Mar",
    "sAbbrevMonthName4": "Apr",
    "sAbbrevMonthName5": "May",
    "sAbbrevMonthName6": "Jun",
    "sAbbrevMonthName7": "Jul",
    "sAbbrevMonthName8": "Aug",
    "sAbbrevMonthName9": "Sep",
    "sAbbrevMonthName10": "Oct",
    "sAbbrevMonthName11": "Nov",
    "sAbbrevMonthName12": "Dec",
    "sYesString": "yes:y:Y",
    "sNoString": "no:n:N",
    "sNativeDigits": "0123456789",
    "sYesExpr": "^([yY]|[yY][eE][sS])",
    "sNoExpr": "^([nN]|[nN][oO])",
    "iUpperType": 0,
    "iUpperMissing": 0,
    "sPositiveSign": "",
    "sNegativeSign": "-",
    "sLeftNegative": "(",
    "sRightNegative": ")",
    "sDebit": "DB",
    "sCredit": "CR",
    "jPercentPattern": "#,##0%",
    "jPercentSign": "%",
    "jExponent": "E",
    "jFullTimeFormat": "HH:mm:ss 'o''''clock' z",
    "jLongTimeFormat": "HH:mm:ss z",
    "jShortTimeFormat": "HH:mm",
    "jFullDateFormat": "EEEE, MMMM d, yyyy",
    "jMediumDateFormat": "dd-MMM-yy",
    "jDateTimePattern": "{1} {0}"
}
LOCALE = {
    0x409: LOCALE_EN_US,
    "default": LOCALE_EN_US
}
# SYSTEM_INFORMATION_CLASS
# Defined in Winternl.h
# Used by NTQuerySystemInformation and ZwQuerySystemInformation
SystemBasicInformation = 0
SystemPerformanceInformation = 2
SystemTimeOfDayInformation = 3
SystemProcessInformation = 5
SystemProcessorPerformanceInformation = 8
SystemInterruptInformation = 23
SystemExceptionInformation = 33
SystemRegistryQuotaInformation = 37
SystemLookasideInformation = 45
# Code Page Identifiers
# https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
OEM_US = 437

# SystemMetrics
# https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics
SM_ARRANGE = 56
SM_CLEANBOOT = 67
SM_CMONITORS = 80
SM_CMOUSEBUTTONS = 43
SM_CONVERTIBLESLATEMODE = 0x2003
SM_CXBORDER = 5
SM_CXCURSOR = 13
SM_CXDLGFRAME = 7
SM_CXDOUBLECLK = 36
SM_CXDRAG = 68
SM_CXEDGE = 45
SM_CXFIXEDFRAME = 7
SM_CXFOCUSBORDER = 83
SM_CXFRAME = 32
SM_CXFULLSCREEN = 16
SM_CXHSCROLL = 21
SM_CXHTHUMB = 10
SM_CXICON = 11
SM_CXICONSPACING = 38
SM_CXMAXIMIZED = 61
SM_CXMAXTRACK = 59
SM_CXMENUCHECK = 71
SM_CXMENUSIZE = 54
SM_CXMIN = 28
SM_CXMINIMIZED = 57
SM_CXMINSPACING = 47
SM_CXMINTRACK = 34
SM_CXPADDEDBORDER = 92
SM_CXSCREEN = 0
SM_CXSIZE = 30
SM_CXSIZEFRAME = 32
SM_CXSMICON = 49
SM_CXSMSIZE = 52
SM_CXVIRTUALSCREEN = 78
SM_CXVSCROLL = 2
SM_CYBORDER = 6
SM_CYCAPTION = 4
SM_CYCURSOR = 14
SM_CYDLGFRAME = 8
SM_CYDOUBLECLK = 37
SM_CYDRAG = 69
SM_CYEDGE = 46
SM_CYFIXEDFRAME = 8
SM_CYFOCUSBORDER = 84
SM_CYFRAME = 33
SM_CYFULLSCREEN = 17
SM_CYHSCROLL = 3
SM_CYICON = 12
# Got bored, will add more if is necessary


# VirtualKey Mappings
# https://docs.microsoft.com/it-it/windows/win32/inputdev/virtual-key-codes
# https://www.win.tue.nl/~aeb/linux/kbd/scancodes-1.html
MAPVK_VK_TO_VSC = {
    0x5b: 0x5b,
    0x10: 0x2a,
    0xa0: 0x2a,
    0xa1: 0x36,
    0x11: 0x1d,
    0x12: 0x38
}
# more to add, just inserted the necessary for a sample

MAP_VK = {
    0: MAPVK_VK_TO_VSC
}

# Crypt String Mappings
# https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinarya

CRYPT_STRING_BASE64HEADER = 0
CRYPT_STRING_BASE64 = 1
CRYPT_STRING_BINARY = 2
CRYPT_STRING_BASE64REQUESTHEADER = 3
# ...

# File Attribtues Constantsc
# https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
FILE_ATTRIBUTE_ARCHIVE = 0x0020
FILE_ATTRIBUTE_COMPRESSED = 0x0800
FILE_ATTRIBUTE_DEVICE = 0x0040
FILE_ATTRIBUTE_DIRECTORY = 0x0010
FILE_ATTRIBUTE_ENCRYPTED = 0x4000
FILE_ATTRIBUTE_HIDDEN = 0x0002
FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x8000
FILE_ATTRIBUTE_NORMAL = 0x0080
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x20000
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_READONLY = 0x0001
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_SPARSE_FILE = 0x0004
FILE_ATTRIBUTE_TEMPORARY = 0x0100
FILE_ATTRIBUTE_VIRTUAL = 0x10000

HFILE_ERROR = -1

# ShellApi Constants
# https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shgetfileinfow

SHGFI_ADDOVERLAYS = 0x000000020
SHGFI_ATTR_SPECIFIED = 0x000020000
SHGFI_ATTRIBUTES = 0x000000800
SHGFI_DISPLAYNAME = 0x000000200
SHGFI_EXETYPE = 0x000002000
SHGFI_ICON = 0x000000100
SHGFI_ICONLOCATION = 0x000001000
SHGFI_LARGEICON = 0x000000000
# ...

# Tlhelp32 Constans
# https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
TH32CS_INHERIT = 0x80000000
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004

# CSIDL Constants
# https://tarma.com/support/im9/using/symbols/functions/csidls.htm
# http://winbatch.hpdd.de/MyWbtHelp/other/CSIDL.txt
CSIDL_ADMINTOOLS = 0x30
CSIDL_ALTSTARTUP = 0x1D
CSIDL_APPDATA = 0x1A
CSIDL_BITBUCKET = 0x0A
CSIDL_CDBURN_AREA = 0x3B
CSIDL_COMMON_ADMINTOOLS = 0x2F
CSIDL_COMMON_ALTSTARTUP = 0x1E
CSIDL_COMMON_APPDATA = 0x23
# ...
CSIDL_FLAG_CREATE = 0x8000

# Show constants
# https://docs.microsoft.com/it-it/windows/win32/api/shellapi/nf-shellapi-shellexecutea
SW_HIDE = 0
SW_MAXIMIZE = 3
SW_MINIMIZE = 6
SW_RESTORE = 9
SW_SHOW = 5
SW_SHOWDEFAULT = 10
SW_SHOWMAXIMIZED = 3
SW_SHOWMINIMIZED = 2
SW_SHOWMINNOACTIVE = 7
SW_SHOWNA = 8
SW_SHOWNOACTIVATE = 4
SW_SHOWNORMAL = 1

# OsVersionInfoConstants
# https://docs.microsoft.com/it-it/windows/win32/api/winnt/ns-winnt-osversioninfoexa

VER_NT_DOMAIN_CONTROLLER = 0x0000002
VER_NT_SERVER = 0x0000003
VER_NT_WORKSTATION = 0x0000001

# major, minor, product
SYSTEMS_VERSION = {
    "1001": "Windows 10",
    "1000": "Windows Server 2016",

    "631": "Windows 8.1",
    "630": "Windows Server 2012 R2",

    "621": "Windows 8",
    "620": "Windows Server 2012",

    "611": "Windows 7",
    "610": "Windows Server 2008 R2",

    "601": "Windows Vista",
    "600": "Windows Server 2008",

    # ...

    "510": "Windows XP"
    # ...
}

# Mapper for ordinal syscalls
Mapper = {
    "shell32": {
        175: "SHGetSpecialFolderPathW"
    }
}

MAXUSHORT = 0xffff

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

# https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype
FILE_TYPE_CHAR = 0x2
FILE_TYPE_DISK = 0x1
FILE_TYPE_PIPE = 0x3
FILE_TYPE_REMOTE = 0x800
FILE_TYPE_UNKNOWN = 0x0

# https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent
PF_XSAVE_ENABLED = 0x17
# ...


# https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
ProcessBasicInformation = 0
ProcessDebugPort = 7
ProcessExecuteFlags = 0x22
ProcessWow64Information = 26
ProcessImageFileName = 27
ProcessBreakOnTermination = 29
ProcessProtectionInformation = 61
ProcessDebugObjectHandle = 0x1E
ProcessDebugFlags = 0x1F

# https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ps/psquery/class.htm
ThreadBasicInformation = 0x0
ThreadTimes = 0x1
ThreadPriority = 0x2
# ...
ThreadHideFromDebugger = 0x11
# ...


# https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw

MB_ABORTRETRYIGNORE = 0x000000020
MB_CANCELTRYCONTINUE = 0x000000060
MB_HELP = 0x000040000
MB_OK = 0x000000000
MB_OKCANCEL = 0x000000010
MB_RETRYCANCEL = 0x000000050
MB_YESNO = 0x000000040
MB_YESNOCANCEL = 0x000000030

IDABORT = 3
IDCANCEL = 2
IDCONTINUE = 11
IDIGNORE = 5
IDNO = 7
IDOK = 1
IDRETRY = 4
IDTRYAGAIN = 10
IDYES = 6

# https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories

LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200
LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400

# https://groups.google.com/forum/#!topic/microsoft.public.vc.language/UERvWrmTn-o
CSTR_LESS_THAN = 1
CSTR_EQUAL = 2
CSTR_GREATER_THAN = 3

# https://docs.microsoft.com/it-it/windows/win32/memory/memory-protection-constants
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x1
PAGE_READONLY = 0x2
PAGE_READWRITE = 0x4
PAGE_WRITECOPY = 0x8
PAGE_TARGETS_INVALID = 0x40000000
PAGE_TARGETS_NO_UPDATE = 0x40000000
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400


# https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
# https://gist.github.com/soxfmr/16c495d6e4ad99e9e46f5bfd558d152f
ObjectTypeInformation = 0x2
ObjectBasicInformation = 0x1
ObjectAllTypesInformation = 0x3

# https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-sethandleinformation
HANDLE_FLAG_INHERIT = 0x1
HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x2

# https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfile
OF_READ      = 0x00000000
OF_WRITE     = 0x00000001
OF_READWRITE = 0x00000002
OF_PARSE     = 0x00000100
OF_DELETE    = 0x00000200
OF_VERIFY    = 0x00000400
OF_CANCEL    = 0x00000800
OF_CREATE    = 0x00001000
OF_PROMPT    = 0x00002000
OF_EXIST     = 0x00004000
OF_REOPEN    = 0x00008000

OF_SHARE_COMPAT     = 0x00000000
OF_SHARE_EXCLUSIVE  = 0x00000010
OF_SHARE_DENY_WRITE = 0x00000020
OF_SHARE_DENY_READ  = 0x00000030
OF_SHARE_DENY_NONE  = 0x00000040
