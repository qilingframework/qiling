#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from unicorn.x86_const import *
from qiling.os.windows.utils import *
from qiling.exception import *
from qiling.os.windows.sid import *
from qiling.os.windows.handle import *
from enum import IntEnum


class Token:
    class TokenInformationClass(IntEnum):
        # https://docs.microsoft.com/it-it/windows/win32/api/winnt/ne-winnt-token_information_class
        TokenUser = 1,
        TokenGroups = 2,
        TokenPrivileges = 3,
        TokenOwner = 4,
        TokenPrimaryGroup = 5,
        TokenDefaultDacl = 6,
        TokenSource = 7,
        TokenType = 8,
        TokenImpersonationLevel = 9,
        TokenStatistics = 10,
        TokenRestrictedSids = 11,
        TokenSessionId = 12,
        TokenGroupsAndPrivileges = 13,
        TokenSessionReference = 14,
        TokenSandBoxInert = 15,
        TokenAuditPolicy = 16,
        TokenOrigin = 17,
        TokenElevationType = 18,
        TokenLinkedToken = 19,
        TokenElevation = 20,
        TokenHasRestrictions = 21,
        TokenAccessInformation = 22,
        TokenVirtualizationAllowed = 23,
        TokenVirtualizationEnabled = 24,
        TokenIntegrityLevel = 25,
        TokenUIAccess = 26,
        TokenMandatoryPolicy = 27,
        TokenLogonSid = 28,
        TokenIsAppContainer = 29,
        TokenCapabilities = 30,
        TokenAppContainerSid = 31,
        TokenAppContainerNumber = 32,
        TokenUserClaimAttributes = 33,
        TokenDeviceClaimAttributes = 34,
        TokenRestrictedUserClaimAttributes = 35,
        TokenRestrictedDeviceClaimAttributes = 36,
        TokenDeviceGroups = 37,
        TokenRestrictedDeviceGroups = 38,
        TokenSecurityAttributes = 39,
        TokenIsRestricted = 40,
        TokenProcessTrustLevel = 41,
        TokenPrivateNameSpace = 42,
        TokenSingletonAttributes = 43,
        TokenBnoIsolation = 44,
        TokenChildProcessFlags = 45,
        TokenIsLessPrivilegedAppContainer = 46,
        TokenIsSandboxed = 47,
        TokenOriginatingProcessTrustLevel = 48,
        MaxTokenInfoClass = 49

    def __init__(self, ql):
        # We will create them when we need it. There are too many structs
        self.struct = {}
        self.ql = ql
        self.struct[Token.TokenInformationClass.TokenUIAccess.value] = 0x1.to_bytes(length=4,

                                                                                    byteorder='little')
        # We create a Sid Structure, set its handle and return the value
        sid = Sid(ql)
        handle = Handle(sid=sid)
        ql.handle_manager.append(handle)
        self.struct[Token.TokenInformationClass.TokenIntegrityLevel] = ql.pack(handle.id)

    def get(self, value):
        res = self.struct[value]
        if res is None:
            raise QlErrorNotImplemented("[!] API not implemented")
        else:
            return res
