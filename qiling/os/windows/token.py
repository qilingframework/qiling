from enum import IntEnum


class Token:
    class TokenInformationClass(IntEnum):
        # https://docs.microsoft.com/it-it/windows/win32/api/winnt/ne-winnt-token_information_class
        TokenUser = 0,
        TokenGroups = 1,
        TokenPrivileges = 2,
        TokenOwner = 3,
        TokenPrimaryGroup = 4,
        TokenDefaultDacl = 5,
        TokenSource = 6,
        TokenType = 7,
        TokenImpersonationLevel = 8,
        TokenStatistics = 9,
        TokenRestrictedSids = 10,
        TokenSessionId = 11,
        TokenGroupsAndPrivileges = 12,
        TokenSessionReference = 13,
        TokenSandBoxInert = 14,
        TokenAuditPolicy = 15,
        TokenOrigin = 16,
        TokenElevationType = 17,
        TokenLinkedToken = 18,
        TokenElevation = 19,
        TokenHasRestrictions = 20,
        TokenAccessInformation = 21,
        TokenVirtualizationAllowed = 22,
        TokenVirtualizationEnabled = 23,
        TokenIntegrityLevel = 24,
        TokenUIAccess = 25,
        TokenMandatoryPolicy = 26,
        TokenLogonSid = 27,
        TokenIsAppContainer = 28,
        TokenCapabilities = 29,
        TokenAppContainerSid = 30,
        TokenAppContainerNumber = 31,
        TokenUserClaimAttributes = 32,
        TokenDeviceClaimAttributes = 33,
        TokenRestrictedUserClaimAttributes = 34,
        TokenRestrictedDeviceClaimAttributes = 35,
        TokenDeviceGroups = 36,
        TokenRestrictedDeviceGroups = 37,
        TokenSecurityAttributes = 38,
        TokenIsRestricted = 39,
        TokenProcessTrustLevel = 40,
        TokenPrivateNameSpace = 41,
        TokenSingletonAttributes = 42,
        TokenBnoIsolation = 43,
        TokenChildProcessFlags = 44,
        TokenIsLessPrivilegedAppContainer = 45,
        TokenIsSandboxed = 46,
        TokenOriginatingProcessTrustLevel = 47,
        MaxTokenInfoClass = 48

    def __init__(self, ql):
        # We will create them when we need it. There are too many structs
        self.struct = {}
        self.struct[Token.TokenInformationClass.TokenUIAccess.value] = 1

    def get(self, value):
        res = self.struct[value]
        if res is None:
            raise QlErrorNotImplemented("[!] API not implemented")
        else:
            return res
