#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""

import sys, logging, importlib, pefile
from qiling.exception import *
from qiling.const import *
from os.path import dirname, exists
from os import makedirs

def ql_get_arch_bits(arch):
    arch_32b = [QL_ARM, QL_MIPS32, QL_X86]
    arch_64b = [QL_ARM64, QL_X8664]

    if arch in arch_32b:
        return 32
    if arch in arch_64b:
        return 64
    raise QlErrorArch("[!] Invalid Arch")


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
        QL_LINUX: "linux",
        QL_MACOS: "macos",
        QL_FREEBSD: "freebsd",
        QL_WINDOWS: "windows",
    }

    return adapter.get(ostype)


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


def ql_arch_convert_str(arch):
    adapter = {
        QL_X86: "x86",
        QL_X8664: "x8664",
        QL_MIPS32: "mips32",
        QL_ARM: "arm",
        QL_ARM64: "arm64",
    }
    return adapter.get(arch)


def arch_convert(arch):
    adapter = {
        "x86": QL_X86,
        "x8664": QL_X8664,
        "mips32": QL_MIPS32,
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
    }
    if output in adapter:
        return adapter[output]
    # invalid
    return None, None


def debugger_convert(debugger):
    adapter = {
        "gdb": QL_GDB,
        "ida": QL_IDAPRO,
    }
    if debugger in adapter:
        return adapter[debugger]
    # invalid
    return None, None

def debugger_convert_str(debugger_id):
    adapter = {
        None : "gdb",
        QL_GDB : "gdb",
        QL_IDAPRO: "ida",
    }
    if debugger_id in adapter:
        return adapter[debugger_id]
    # invalid
    return None, None

def ql_elf_check_archtype(self):
    path = self.path

    def getident():
        return elfdata

    with open(path, "rb") as f:
        elfdata = f.read()[:20]

    ident = getident()
    ostype = None
    arch = None

    if ident[: 4] == b'\x7fELF':
        elfbit = ident[0x4]
        endian = ident[0x5]
        osabi = ident[0x7]
        e_machine = ident[0x12:0x14]

        if osabi == 0x11 or osabi == 0x03 or osabi == 0x0:
            ostype = QL_LINUX
        elif osabi == 0x09:
            ostype = QL_FREEBSD
        else:
            ostype = None

        if e_machine == b"\x03\x00":
            arch = QL_X86
        elif e_machine == b"\x08\x00" and endian == 1 and elfbit == 1:
            self.archendian = QL_ENDIAN_EL
            arch = QL_MIPS32
        elif e_machine == b"\x00\x08" and endian == 2 and elfbit == 1:
            self.archendian = QL_ENDIAN_EB
            arch = QL_MIPS32
        elif e_machine == b"\x28\x00" and endian == 1 and elfbit == 1:
            self.archendian = QL_ENDIAN_EL
            arch = QL_ARM
        elif e_machine == b"\x00\x28" and endian == 2 and elfbit == 1:
            self.archendian = QL_ENDIAN_EB
            arch = QL_ARM            
        elif e_machine == b"\xB7\x00":
            arch = QL_ARM64
        elif e_machine == b"\x3E\x00":
            arch = QL_X8664
        else:
            arch = None

    return arch, ostype


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

    if ident[: 4] in (macho_macos_sig32, macho_macos_sig64, macho_macos_fat):
        ostype = QL_MACOS
    else:
        ostype = None

    if ostype:
        # if ident[0x7] == 0: # 32 bit
        #    arch = QL_X86
        if ident[0x4] == 7 and ident[0x7] == 1:  # X86 64 bit
            arch = QL_X8664
        elif ident[0x4] == 12 and ident[0x7] == 1:  # ARM64  ident[0x4] = 0x0C
            arch = QL_ARM64
        else:
            arch = None

    return arch, ostype


def ql_pe_check_archtype(path):
    pe = pefile.PE(path, fast_load=True)
    ostype = None
    arch = None

    machine_map = {
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: QL_X86,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: QL_X8664,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']: QL_ARM,
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_THUMB']: QL_ARM,
        # pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']     :   QL_ARM64       #pefile does not have the definition
        # for IMAGE_FILE_MACHINE_ARM64
        0xAA64: QL_ARM64  # Temporary workaround for Issues #21 till pefile gets updated
    }
    # get arch
    arch = machine_map.get(pe.FILE_HEADER.Machine)

    if arch:
        ostype = QL_WINDOWS
    else:
        ostype = None

    return arch, ostype


def ql_checkostype(self):
    path = self.path

    arch = None
    ostype = None

    arch, ostype = ql_elf_check_archtype(self)

    if ostype not in (QL_LINUX, QL_FREEBSD):
        arch, ostype = ql_macho_check_archtype(path)

    if ostype not in (QL_LINUX, QL_FREEBSD, QL_MACOS):
        arch, ostype = ql_pe_check_archtype(path)

    if ostype not in (QL_OS):
        raise QlErrorOsType("[!] File does not belong to either 'linux', 'windows', 'freebsd', 'macos', 'ios'")

    return arch, ostype

def ql_get_os_module_function(ql, function_name = None):
    if not ql_is_valid_ostype(ql.ostype):
        raise QlErrorOsType("[!] Invalid OSType")

    if not ql_is_valid_arch(ql.arch):
        raise QlErrorArch("[!] Invalid Arch")
    
    if function_name == None:
        ostype_str = ql_ostype_convert_str(ql.ostype)
        ostype_str = ostype_str.capitalize()
        function_name = "QlOs" + ostype_str + "Manager"
        module_name = ql_build_module_import_name("os", ql.ostype)
        return ql_get_module_function(module_name, function_name, ql)
    else:
        module_name = ql_build_module_import_name("os", ql.ostype, ql.arch)
        return ql_get_module_function(module_name, function_name)


def ql_get_arch_module_function(arch, function_name):
    if not ql_is_valid_arch(arch):
        raise QlErrorArch("[!] Invalid Arch")

    module_name = ql_build_module_import_name("arch", None, arch)
    return ql_get_module_function(module_name, function_name)


def ql_get_commonos_module_function(ostype):
    if not ql_is_valid_ostype(ostype):
        raise QlErrorOsType("[!] Invalid OSType")
    
    # common os class, posix type OS share one same class
    if ostype in (QL_POSIX):
        module_name = ql_build_module_import_name("os", "posix", "posix")
        func_name = "QlPosixManager"
    else:
        module_name = ""    
    if module_name: 
        return ql_get_module_function(module_name, func_name)

def ql_build_module_import_name(module, ostype, arch = None):
    ret_str = "qiling." + module

    ostype_str = ostype
    arch_str = arch

    if type(ostype) is int:
        ostype_str = ql_ostype_convert_str(ostype)
    
    if ostype_str:
        ret_str += "." + ostype_str

    if arch:
        if module == "arch" and arch == QL_X8664:  # This is because X86_64 is bundled into X86 in arch
            arch_str = "x86"
        elif type(arch) is int:
            arch_str = ql_arch_convert_str(arch)
    else:
        arch_str = ostype_str
        
    ret_str += "." + arch_str
    return ret_str


def ql_get_module_function(module_name, function_name = None, ql = None):
    if function_name == None and ql:
        pass
    try:
        imp_module = importlib.import_module(module_name)
    except:
        raise QlErrorModuleNotFound("[!] Unable to import module %s" % module_name)

    try:
        module_function = getattr(imp_module, function_name)
    except:
        raise QlErrorModuleFunctionNotFound("[!] Unable to import %s from %s" % (function_name, imp_module))

    return module_function


def ql_setup_logger(logger_name=None):
    if logger_name is None: # increasing logger name counter to prevent conflict 
        loggers = logging.root.manager.loggerDict
        _counter = len(loggers)
        logger_name = 'qiling_%s' % _counter
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    return logger


def ql_setup_logging_stream(ql, logger=None):
    ql_mode = ql.output

    # setup StreamHandler for logging to stdout
    if ql.log_console == True:
        ch = logging.StreamHandler()
    else:
        # not print out to stdout by using NullHandler
        ch = logging.NullHandler()

    ch.setLevel(logging.DEBUG)
    
    # use empty character for string terminator by default
    ch.terminator = ""

    if logger is None:
        logger = ql_setup_logger()

    logger.addHandler(ch)
    return logger


def ql_setup_logging_file(ql_mode, log_file_path, logger=None):

    # setup FileHandler for logging to disk file
    fh = logging.FileHandler('%s.qlog' % log_file_path)
    fh.setLevel(logging.DEBUG)
    
    # use empty character for stirng terminateor by default
    fh.terminator = ""

    if logger is None:
        logger = ql_setup_logger()

    logger.addHandler(fh)
    return logger
