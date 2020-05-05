#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import pefile
from qiling.const import QL_OS, QL_OS_ALL, QL_ARCH, QL_ENDIAN
from qiling.exception import QlErrorArch, QlErrorOsType

def ql_checkostype(path):
    arch = None
    ostype = None
    archendian = None

    arch, ostype, archendian = ql_elf_check_archtype(path)

    if ostype not in (QL_OS.LINUX, QL_OS.FREEBSD):
        arch, ostype, archendian = ql_macho_check_archtype(path)

    if ostype not in (QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS):
        arch, ostype, archendian = ql_pe_check_archtype(path)

    if ostype not in (QL_OS_ALL):
        raise QlErrorOsType("[!] File does not belong to either 'linux', 'windows', 'freebsd', 'macos', 'ios'")

    return arch, ostype, archendian

def ql_elf_check_archtype(path):
    def getident():
        return elfdata

    with open(path, "rb") as f:
        elfdata = f.read()[:20]

    ident = getident()
    ostype = None
    arch = None
    archendian = None

    if ident[: 4] == b'\x7fELF':
        elfbit = ident[0x4]
        endian = ident[0x5]
        osabi = ident[0x7]
        e_machine = ident[0x12:0x14]

        if osabi == 0x11 or osabi == 0x03 or osabi == 0x0:
            ostype = QL_OS.LINUX
        elif osabi == 0x09:
            ostype = QL_OS.FREEBSD
        else:
            ostype = None

        if e_machine == b"\x03\x00":
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.X86
        elif e_machine == b"\x08\x00" and endian == 1 and elfbit == 1:
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.MIPS
        elif e_machine == b"\x00\x08" and endian == 2 and elfbit == 1:
            archendian = QL_ENDIAN.EB
            arch = QL_ARCH.MIPS
        elif e_machine == b"\x28\x00" and endian == 1 and elfbit == 1:
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.ARM
        elif e_machine == b"\x00\x28" and endian == 2 and elfbit == 1:
            archendian = QL_ENDIAN.EB
            arch = QL_ARCH.ARM            
        elif e_machine == b"\xB7\x00":
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.ARM64
        elif e_machine == b"\x3E\x00":
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.X8664
        else:
            arch = None

    return arch, ostype, archendian

def ql_macho_check_archtype(path):
    def getident():
        return machodata

    with open(path, "rb") as f:
        machodata = f.read()[:32]

    ident = getident()

    macho_macos_sig64 = b'\xcf\xfa\xed\xfe'
    macho_macos_sig32 = b'\xce\xfa\xed\xfe'
    macho_macos_fat = b'\xca\xfe\xba\xbe'  # should be header for FAT

    ostype = None
    arch = None
    archendian = None

    if ident[: 4] in (macho_macos_sig32, macho_macos_sig64, macho_macos_fat):
        ostype = QL_OS.MACOS
    else:
        ostype = None

    if ostype:
        # if ident[0x7] == 0: # 32 bit
        #    arch = QL_ARCH.X86
        if ident[0x4] == 7 and ident[0x7] == 1:  # X86 64 bit
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.X8664
        elif ident[0x4] == 12 and ident[0x7] == 1:  # ARM64  ident[0x4] = 0x0C
            archendian = QL_ENDIAN.EL
            arch = QL_ARCH.ARM64
        else:
            arch = None

    return arch, ostype, archendian

def ql_pe_check_archtype(path):
    pe = pefile.PE(path, fast_load=True)
    ostype = None
    arch = None
    archendian = None

    machine_map = {
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: QL_ARCH.X86,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: QL_ARCH.X8664,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']: QL_ARCH.ARM,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_THUMB']: QL_ARCH.ARM,
        # pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']     :   QL_ARCH.ARM64       #pefile does not have the definition
        # for IMAGE_FILE_MACHINE_ARM64
        0xAA64: QL_ARCH.ARM64  # Temporary workaround for Issues #21 till pefile gets updated
    }
    # get arch
    archendian = QL_ENDIAN.EL
    arch = machine_map.get(pe.FILE_HEADER.Machine)

    if arch:
        ostype = QL_OS.WINDOWS
    else:
        ostype = None

    return arch, ostype, archendian
