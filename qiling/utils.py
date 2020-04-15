#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that can be used
thoughout the qiling framework
"""

import logging, importlib, pefile, os, socket
from .os.const import *
from .exception import *
from .const import *

def catch_KeyboardInterrupt(ql):
    def decorator(func):
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except BaseException as e:
                ql.os.stop(stop_event=THREAD_EVENT_UNEXECPT_EVENT)
                ql.internal_exception = e
        return wrapper
    return decorator

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

def ql_loadertype_convert_str(ostype):
    adapter = {
        QL_LINUX: "ELF",
        QL_MACOS: "MACHO",
        QL_FREEBSD: "ELF",
        QL_WINDOWS: "PE",
    }

    return adapter.get(ostype)

def ostype_convert(ostype):
    adapter = {
        "linux": QL_LINUX,
        "macos": QL_MACOS,
        "darwin": QL_MACOS,
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


def ql_archmanager_convert_str(arch):
    adapter = {
        QL_X86: "QlArchX86Manager",
        QL_X8664: "QlArchX8664Manager",
        QL_MIPS32: "QlArchMIPS32Manager",
        QL_ARM: "QlArchARMManager",
        QL_ARM64: "QlArchARM64Manager",
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
        None: QL_OUTPUT.DEFAULT,
        "default": QL_OUTPUT.DEFAULT,
        "disasm": QL_OUTPUT.DISASM,
        "debug": QL_OUTPUT.DEBUG,
        "dump": QL_OUTPUT.DUMP,
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

def ql_debugger_init(ql):

    def ql_debugger(ql, remotedebugsrv, ip=None, port=None):
        path = ql.path
        try:
            if ip is None:
                ip = '127.0.0.1'
            if port is None:
                port = 9999
            port = int(port) 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((ip, port))
            ql.nprint("\ndebugger> Initializing loadbase 0x%x\n" % (ql.loader.loadbase))
            ql.nprint("debugger> Listening on %s:%u\n" % (ip, port))
            sock.listen(1)
            conn, addr = sock.accept()
        except:
            ql.nprint("debugger> Error: Address already in use\n")
            raise
        try:
            mappings = [(hex(ql.loader.entry_point), 0x10)]
            exit_point = ql.loader.entry_point + os.path.getsize(path)
            remotedebugsrv = debugger_convert_str(remotedebugsrv)
            remotedebugsrv = str(remotedebugsrv) + "server" 
            DEBUGSESSION = str.upper(remotedebugsrv) + "session"
            DEBUGSESSION = ql_get_module_function("qiling.debugger." + remotedebugsrv + "." + remotedebugsrv, DEBUGSESSION)
            ql.remotedebugsession = DEBUGSESSION(ql, conn, exit_point, mappings)
        except:
            ql.nprint("debugger> Error: Not able to initialize Debugging Server\n")
            raise

    try:
        remotedebugsrv, ip, port = '', '', ''
        remotedebugsrv, ip, port = ql.debugger.split(':')
    except:
        ip, port = '', ''

    remotedebugsrv = "gdb"
    
    try:
        ip, port = ql.debugger.split(':')
        # If only ip:port is defined, remotedebugsrv is always gdb
    except:
        if ip is None:
            ip = "127.0.0.0"
        if port is None:
            port = "9999" 

    remotedebugsrv = debugger_convert(remotedebugsrv)

    if remotedebugsrv not in (QL_DEBUGGER):
        raise QlErrorOutput("[!] Error: Debugger not supported\n")       
    else:
        try:
            if ql.debugger is True:
                ql_debugger(ql, remotedebugsrv)
            else:
                ql_debugger(ql, remotedebugsrv, ip, port)
        
        except KeyboardInterrupt:
            if ql.remotedebugsession():
                ql.remotedebugsession.close()
            raise QlErrorOutput("[!] Remote debugging session ended\n")
                


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
            self.archendian = QL_ENDIAN.EL
            arch = QL_MIPS32
        elif e_machine == b"\x00\x08" and endian == 2 and elfbit == 1:
            self.archendian = QL_ENDIAN.EB
            arch = QL_MIPS32
        elif e_machine == b"\x28\x00" and endian == 1 and elfbit == 1:
            self.archendian = QL_ENDIAN.EL
            arch = QL_ARM
        elif e_machine == b"\x00\x28" and endian == 2 and elfbit == 1:
            self.archendian = QL_ENDIAN.EB
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


def ql_get_arch_module_function(arch, function_name):
    if not ql_is_valid_arch(arch):
        raise QlErrorArch("[!] Invalid Arch")
    function_name = function_name.upper()    
    module_name = ql_build_module_import_name("arch", None, arch)
    return ql_get_module_function(module_name, function_name)


def ql_build_module_import_name(module, ostype, arch = None):
    ret_str = "qiling." + module

    ostype_str = ostype
    arch_str = arch

    if type(ostype) is int:
        ostype_str = ql_ostype_convert_str(ostype)
    
    if ostype_str and "loader" not in ret_str:
        ret_str += "." + ostype_str

    if arch:
        # This is because X86_64 is bundled into X86 in arch
        if module == "arch" and arch == QL_X8664:  
            arch_str = "x86"
        elif type(arch) is int:
            arch_str = ql_arch_convert_str(arch)
    else:
        arch_str = ostype_str
        
    ret_str += "." + arch_str
    return ret_str


def ql_get_module_function(module_name, function_name = None):
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


def ql_setup_logging_env(ql, logger=None):
    if not os.path.exists(ql.log_dir):
        os.makedirs(ql.log_dir, 0o755)

    pid = os.getpid()

    if ql.append:
        ql.log_filename = ql.targetname + "_" + ql.append          
    else:
        ql.log_filename = ql.targetname
    
    ql.log_file = os.path.join(ql.log_dir, ql.log_filename) 

    _logger = ql_setup_logging_file(ql.output, ql.log_file + "_" + str(pid), logger)
    return _logger


def ql_setup_logging_stream(ql, logger=None):
    #ql_mode = ql.output

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


class Strace_filter(logging.Filter):
    def __init__(self, func_names):
        super(Strace_filter, self).__init__()
        self.filter_list = func_names.split(",") if isinstance(func_names, str) else func_names

    def filter(self, record):
        return any((record.getMessage().startswith(each) for each in self.filter_list))


def ql_arch_setup(ql):
    if not ql_is_valid_arch(ql.archtype):
        raise QlErrorArch("[!] Invalid Arch")
    
    archmanager = ql_arch_convert_str(ql.archtype).upper()
    archmanager = ("QlArch" + archmanager)

    module_name = ql_build_module_import_name("arch", None, ql.archtype)
    return ql_get_module_function(module_name, archmanager)(ql)


def ql_os_setup(ql, function_name = None):
    if not ql_is_valid_ostype(ql.ostype):
        raise QlErrorOsType("[!] Invalid OSType")

    if not ql_is_valid_arch(ql.archtype):
        raise QlErrorArch("[!] Invalid Arch %s" % ql.archtype)

    if function_name == None:
        ostype_str = ql_ostype_convert_str(ql.ostype)
        ostype_str = ostype_str.capitalize()
        function_name = "QlOs" + ostype_str
        module_name = ql_build_module_import_name("os", ql.ostype)
        return ql_get_module_function(module_name, function_name)(ql)

    elif function_name == "map_syscall":
        ostype_str = ql_ostype_convert_str(ql.ostype)
        arch_str = ql_arch_convert_str(ql.archtype)
        arch_str = arch_str + "_syscall"
        module_name = ql_build_module_import_name("os", ostype_str, arch_str)
        return ql_get_module_function(module_name, function_name)
    
    else:
        module_name = ql_build_module_import_name("os", ql.ostype, ql.archtype)
        return ql_get_module_function(module_name, function_name)


def ql_component_setup(ql, function_name = None):
    if not ql_is_valid_ostype(ql.ostype):
        raise QlErrorOsType("[!] Invalid OSType")

    if not ql_is_valid_arch(ql.archtype):
        raise QlErrorArch("[!] Invalid Arch %s" % ql.archtype)

    if function_name == "register":
        function_name = "QlRegisterManager"
        module_name = "qiling.arch.register"
        return ql_get_module_function(module_name, function_name)(ql)

    elif function_name == "memory":
        function_name = "QlMemoryManager"
        module_name = "qiling.os.memory"
        return ql_get_module_function(module_name, function_name)(ql)
    
    else:
        module_name = ql_build_module_import_name("os", ql.ostype, ql.archtype)
        return ql_get_module_function(module_name, function_name)


def ql_loader_setup(ql, function_name = None):
    if not ql_is_valid_ostype(ql.ostype):
        raise QlErrorOsType("[!] Invalid OSType")

    if not ql_is_valid_arch(ql.archtype):
        raise QlErrorArch("[!] Invalid Arch %s" % ql.archtype)

    if function_name == None:
        loadertype_str = ql_loadertype_convert_str(ql.ostype)
        function_name = "QlLoader" + loadertype_str
        module_name = ql_build_module_import_name("loader", loadertype_str.lower())
        return ql_get_module_function(module_name, function_name)(ql)        