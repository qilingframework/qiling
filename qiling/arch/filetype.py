#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import lief

from qiling.exception import *

QL_X86          = 1
QL_X8664        = 2
QL_ARM          = 3
QL_ARM_THUMB    = 4
QL_ARM64        = 5
QL_MIPS32EL     = 6

QL_LINUX    = 1
QL_FREEBSD  = 2
QL_MACOS    = 3
QL_WINDOWS  = 4

QL_OUT_DEFAULT  = 1
QL_OUT_OFF      = 2
QL_OUT_DEBUG    = 3
QL_OUT_DUMP     = 4
QL_OUT_DISASM   = 5

QL_ARCH = [ QL_ARM, QL_ARM64, QL_MIPS32EL, QL_X86, QL_X8664]
QL_OS = [ QL_LINUX, QL_FREEBSD, QL_MACOS, QL_WINDOWS ]
QL_OUTPUT = [QL_OUT_DEFAULT, QL_OUT_OFF, QL_OUT_DEBUG, QL_OUT_DUMP, QL_OUT_DISASM ]

def ql_get_arch_bits(arch):
    arch_32b = [QL_ARM, QL_MIPS32EL, QL_X86]
    arch_64b = [QL_ARM64, QL_X8664]

    if arch in arch_32b: return 32
    if arch in arch_64b: return 64
    raise QlErrorArch(f"Invalid Arch {arch}")

def ql_is_valid_ostype(ostype):
    if ostype not in QL_OS:
        return False
    return True

def ql_is_valid_arch(arch):
    if arch not in QL_ARCH:
        return False
    return True

def ql_ostype_convert_str(ostype):
    adapter = {
        QL_LINUX        : "linux",
        QL_MACOS        : "macos",
        QL_FREEBSD      : "freebsd",
        QL_WINDOWS      : "windows",
    }
    if ostype in adapter:
        return adapter[ostype]
    # invalid
    return None

def ostype_convert(ostype):
    adapter = {
        "linux"         : QL_LINUX,
        "macos"         : QL_MACOS,
        "freebsd"       : QL_FREEBSD,
        "windows"       : QL_WINDOWS,
        }
    if ostype in adapter:
        return adapter[ostype]
    # invalid
    return None, None

def ql_arch_convert_str(arch):
    adapter = {
        QL_X86          : "x86",
        QL_X8664        : "x8664",
        QL_MIPS32EL     : "mips32el",
        QL_ARM          : "arm",
        QL_ARM64        : "arm64",
        }
    if arch in adapter:
        return adapter[arch]
    # invalid
    return None

def arch_convert(arch):
    adapter = {
        "x86"           : QL_X86,
        "x8664"         : QL_X8664,
        "mips32el"      : QL_MIPS32EL,
        "arm"           : QL_ARM,
        "arm64"         : QL_ARM64,
        }
    if arch in adapter:
        return adapter[arch]
    # invalid
    return None, None

def output_convert(output):
    adapter = {
        None: QL_OUT_DEFAULT,
        "default": QL_OUT_DEFAULT,
        "disasm": QL_OUT_DISASM,
        "debug": QL_OUT_DEBUG,
        "dump": QL_OUT_DUMP,
        "off": QL_OUT_OFF,
        }
    if output in adapter:
        return adapter[output]
    # invalid
    return None, None

def ql_elf_check_archtype(path):
    if not lief.is_elf(path):
        return None, None

    arch, ostype = None, None
    elf = lief.parse(path)

    ei_osabi = elf.header.identity_os_abi
    if ei_osabi == lief.ELF.OS_ABI.SYSTEMV:     ostype = QL_LINUX
    elif ei_osabi == lief.ELF.OS_ABI.FREEBSD:   ostype = QL_FREEBSD

    e_machine = elf.header.machine_type
    if e_machine == lief.ELF.ARCH.i386:             arch = QL_X86
    elif e_machine == lief.ELF.ARCH.x86_64:         arch = QL_X8664
    elif e_machine == lief.ELF.ARCH.ARM:            arch = QL_ARM
    elif e_machine == lief.ELF.ARCH.AARCH64:        arch = QL_ARM64
    elif e_machine == lief.ELF.ARCH.MIPS_RS3_LE:    arch = QL_MIPS32EL

    return arch, ostype


def ql_macho_check_archtype(path):
    if not lief.is_macho(path):
        return None, None

    arch, ostype = None, None
    macho = lief.parse(path)

    cpu_type = macho.header.cpu_type
    if cpu_type == lief.MachO.CPU_TYPES.x86:
        arch, ostype = QL_X86, QL_MACOS
    elif cpu_type == lief.MachO.CPU_TYPES.x86_64:
        arch, ostype = QL_X8664, QL_MACOS

    return arch, ostype


def ql_pe_check_archtype(path):
    if not lief.is_pe(path):
        return None, None

    arch, ostype = None, None
    pe = lief.parse(path)

    machine_map = {
        lief.PE.MACHINE_TYPES.I386                          :   QL_X86,
        lief.PE.MACHINE_TYPES.AMD64                         :   QL_X8664,
        lief.PE.MACHINE_TYPES.ARM                           :   QL_ARM,
        lief.PE.MACHINE_TYPES.ARM64                         :   QL_ARM64,
        lief.PE.MACHINE_TYPES.THUMB                         :   QL_ARM,
    }

    machine = pe.header.machine
    if machine in machine_map:
        arch = machine_map[machine]
        ostype = QL_WINDOWS

    return arch, ostype


def ql_checkostype(path):

    arch = None
    ostype = None

    arch, ostype = ql_elf_check_archtype(path)

    if ostype not in (QL_LINUX, QL_FREEBSD):
        arch, ostype = ql_macho_check_archtype(path)

    if ostype not in (QL_LINUX, QL_FREEBSD, QL_MACOS):
        arch, ostype = ql_pe_check_archtype(path)

    if ostype not in (QL_OS):
        raise QlErrorOsType("ERROR: File does not belong to either 'linux', 'windows', 'freebsd', 'macos'")


    return arch, ostype
