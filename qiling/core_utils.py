import pefile, os, logging
from .utils import ql_build_module_import_name, ql_get_module_function
from .utils import ql_is_valid_arch, ql_is_valid_ostype
from .utils import ql_loadertype_convert_str, ql_ostype_convert_str, ql_arch_convert_str
from .const import QL_OS, QL_OS_ALL, QL_ARCH, QL_ENDIAN, QL_OUTPUT
from .exception import QlErrorArch, QlErrorOsType, QlErrorOutput

class QLCoreUtils:
    def __init__(self):
        self.archtype = None
        self.ostype = None
        self.path = None
        self.archendian = None

    # normal print out
    def nprint(self, *args, **kw):
        if self.multithread == True and self.os.thread_management is not None and self.os.thread_management.cur_thread is not None:
            fd = self.os.thread_management.cur_thread.log_file_fd
        else:
            fd = self.log_file_fd

        msg = args[0]

        # support keyword "end" in ql.print functions, use it as terminator or default newline character by OS
        msg += kw["end"] if kw.get("end", None) != None else os.linesep

        fd.info(msg)

        if fd is not None:
            if isinstance(fd, logging.FileHandler):
                fd.emit()
            elif isinstance(fd, logging.StreamHandler):
                fd.flush()

    # debug print out, always use with verbose level with dprint(D_INFO,"helloworld")
    def dprint(self, level, *args, **kw):
        try:
            self.verbose = int(self.verbose)
        except:
            raise QlErrorOutput("[!] Verbose muse be int")    
        
        if type(self.verbose) != int or self.verbose > 99 or (self.verbose > 1 and self.output not in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP)):
            raise QlErrorOutput("[!] Verbose > 1 must use with QL_OUTPUT.DEBUG or else ql.verbose must be 0")

        if self.output == QL_OUTPUT.DUMP:
            self.verbose = 99

        if int(self.verbose) >= level and self.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
            self.nprint(*args, **kw)

    def stack_push(self, data):
        self.arch.stack_push(data)

    def stack_pop(self):
        return self.arch.stack_pop()

    # read from stack, at a given offset from stack bottom
    def stack_read(self, offset):
        return self.arch.stack_read(offset)

    # write to stack, at a given offset from stack bottom
    def stack_write(self, offset, data):
        self.arch.stack_write(offset, data)

    def arch_setup(self):
        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch")
        
        archmanager = ql_arch_convert_str(self.archtype).upper()
        archmanager = ("QlArch" + archmanager)

        module_name = ql_build_module_import_name("arch", None, self.archtype)
        return ql_get_module_function(module_name, archmanager)(self)

    def os_setup(self, function_name = None):
        if not ql_is_valid_ostype(self.ostype):
            raise QlErrorOsType("[!] Invalid OSType")

        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch %s" % self.archtype)

        if function_name == None:
            ostype_str = ql_ostype_convert_str(self.ostype)
            ostype_str = ostype_str.capitalize()
            function_name = "QlOs" + ostype_str
            module_name = ql_build_module_import_name("os", self.ostype)
            return ql_get_module_function(module_name, function_name)(self)

        elif function_name == "map_syscall":
            ostype_str = ql_ostype_convert_str(self.ostype)
            arch_str = ql_arch_convert_str(self.archtype)
            arch_str = arch_str + "_syscall"
            module_name = ql_build_module_import_name("os", ostype_str, arch_str)
            return ql_get_module_function(module_name, function_name)
        
        else:
            module_name = ql_build_module_import_name("os", self.ostype, self.archtype)
            return ql_get_module_function(module_name, function_name)

    def loader_setup(self, function_name = None):
        if not ql_is_valid_ostype(self.ostype):
            raise QlErrorOsType("[!] Invalid OSType")

        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch %s" % self.archtype)

        if function_name == None:
            loadertype_str = ql_loadertype_convert_str(self.ostype)
            function_name = "QlLoader" + loadertype_str
            module_name = ql_build_module_import_name("loader", loadertype_str.lower())
            return ql_get_module_function(module_name, function_name)(self)

    def component_setup(self, function_name = None):
        if not ql_is_valid_ostype(self.ostype):
            raise QlErrorOsType("[!] Invalid OSType")

        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch %s" % self.archtype)

        if function_name == "register":
            function_name = "QlRegisterManager"
            module_name = "qiling.arch.register"
            return ql_get_module_function(module_name, function_name)(self)

        elif function_name == "memory":
            function_name = "QlMemoryManager"
            module_name = "qiling.os.memory"
            return ql_get_module_function(module_name, function_name)(self)
        
        else:
            module_name = ql_build_module_import_name("os", self.ostype, self.archtype)
            return ql_get_module_function(module_name, function_name)

    def checkostype(self):
        path = self.path

        arch = None
        ostype = None

        arch, ostype = self.ql_elf_check_archtype()

        if ostype not in (QL_OS.LINUX, QL_OS.FREEBSD):
            arch, ostype = self.ql_macho_check_archtype(path)

        if ostype not in (QL_OS.LINUX, QL_OS.FREEBSD, QL_OS.MACOS):
            arch, ostype = self.ql_pe_check_archtype(path)

        if ostype not in (QL_OS_ALL):
            raise QlErrorOsType("[!] File does not belong to either 'linux', 'windows', 'freebsd', 'macos', 'ios'")

        return arch, ostype

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
                ostype = QL_OS.LINUX
            elif osabi == 0x09:
                ostype = QL_OS.FREEBSD
            else:
                ostype = None

            if e_machine == b"\x03\x00":
                arch = QL_ARCH.X86
            elif e_machine == b"\x08\x00" and endian == 1 and elfbit == 1:
                self.archendian = QL_ENDIAN.EL
                arch = QL_ARCH.MIPS32
            elif e_machine == b"\x00\x08" and endian == 2 and elfbit == 1:
                self.archendian = QL_ENDIAN.EB
                arch = QL_ARCH.MIPS32
            elif e_machine == b"\x28\x00" and endian == 1 and elfbit == 1:
                self.archendian = QL_ENDIAN.EL
                arch = QL_ARCH.ARM
            elif e_machine == b"\x00\x28" and endian == 2 and elfbit == 1:
                self.archendian = QL_ENDIAN.EB
                arch = QL_ARCH.ARM            
            elif e_machine == b"\xB7\x00":
                arch = QL_ARCH.ARM64
            elif e_machine == b"\x3E\x00":
                arch = QL_ARCH.X8664
            else:
                arch = None

        return arch, ostype

    def ql_macho_check_archtype(self, path):
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
            ostype = QL_OS.MACOS
        else:
            ostype = None

        if ostype:
            # if ident[0x7] == 0: # 32 bit
            #    arch = QL_ARCH.X86
            if ident[0x4] == 7 and ident[0x7] == 1:  # X86 64 bit
                arch = QL_ARCH.X8664
            elif ident[0x4] == 12 and ident[0x7] == 1:  # ARM64  ident[0x4] = 0x0C
                arch = QL_ARCH.ARM64
            else:
                arch = None

        return arch, ostype

    def ql_pe_check_archtype(self, path):
        pe = pefile.PE(path, fast_load=True)
        ostype = None
        arch = None

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
        arch = machine_map.get(pe.FILE_HEADER.Machine)

        if arch:
            ostype = QL_OS.WINDOWS
        else:
            ostype = None

        return arch, ostype
