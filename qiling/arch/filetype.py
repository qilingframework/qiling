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


def ostype_convert(ostype):
    adapter = {
        "linux": QL_LINUX,
        "macos": QL_MACOS,
        "freebsd": QL_FREEBSD,
        "windows": QL_WINDOWS,
        }
    if ostype in adapter:
        return adapter[ostype]
    # invalid
    return None, None 

def arch_convert(arch):
    adapter = {
        "x86": QL_X86,
        "x8664": QL_X8664,
        "mips32el": QL_MIPS32EL,
        "arm": QL_ARM,
        "arm64": QL_ARM64,
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
    def getident():
        return elfdata

    with open(path, "rb") as f:
        elfdata = f.read()[:-19]

    ident = getident()
    ostype = None
    arch = None

    if ident[ : 4] == b'\x7fELF':
        elfbit = ident[0x4]
        endian = ident[0x5]
        osabi = ident[0x7]
        e_machine = ident[0x12]

        if osabi == 0x11 or osabi == 0x03 or osabi == 0x0:
            ostype = QL_LINUX
        elif osabi == 0x09:
            ostype = QL_FREEBSD
        else:
            ostype = None

        if e_machine == 0x03:
            arch = QL_X86
        elif e_machine == 0x08 and endian == 1 and elfbit == 1:
            arch = QL_MIPS32EL
        elif e_machine == 0x28:
            arch = QL_ARM
        elif e_machine == 0xB7:
            arch = QL_ARM64
        elif e_machine == 0x3E:
            arch = QL_X8664
        else:
            arch = None    

    return arch, ostype

def ql_macho_check_archtype(path):
    def getident():
        return machodata  
    
    with open(path, "rb") as f:
        machodata = f.read()[:-32]
        
    ident = getident()

    macho_sig64 =  b'\xcf\xfa\xed\xfe'
    macho_sig32 =  b'\xce\xfa\xed\xfe'
   
    ostype = None
    arch = None

    if ident[ : 4] == macho_sig32 or ident[ : 4] == macho_sig64:
        ostype = QL_MACOS
        
        if ident[0x7] == 0: # 32 bit
            arch = QL_X86
        elif ident[0x7] == 1: # 64 bit
            arch = QL_X8664
        else:
            arch = None

    if arch:
        ostype = QL_MACOS
    else:
        ostype = None        

    return arch, ostype

def ql_pe_check_archtype(path):
    import pefile
    pe = pefile.PE(path, fast_load=True)
    ostype = None
    arch = None

    # get arch
    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        arch = QL_X86
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        arch = QL_X8664
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']:
        arch = QL_ARM
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_THUMB']:
        arch = QL_ARM
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']:
        arch = QL_ARM64
    else:
        arch = None

    if arch:
        ostype = QL_WINDOWS
    else:
        ostype = None        

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
