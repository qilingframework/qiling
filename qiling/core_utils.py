#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os, logging, configparser

try:
    from keystone import *
except:
    pass

from binascii import unhexlify

from .utils import ql_build_module_import_name, ql_get_module_function
from .utils import ql_is_valid_arch, ql_is_valid_ostype
from .utils import loadertype_convert_str, ostype_convert_str, arch_convert_str
from .utils import ql_setup_filter
from .const import QL_OS, QL_OS_ALL, QL_ARCH, QL_ENDIAN, QL_OUTPUT
from .const import D_INFO
from .exception import QlErrorArch, QlErrorOsType, QlErrorOutput
from .loader.utils import ql_checkostype

class QLCoreUtils(object):
    def __init__(self):
        super().__init__()
        self.archtype = None
        self.ostype = None
        self.path = None
        self.archendian = None

    # normal print out
    def nprint(self, *args, **kw):
        if type(self.console) is bool:
            pass
        else:
            raise QlErrorOutput("[!] consnsole must be True or False")     
        
        # FIXME: this is due to console must be able to update duirng runtime
        if self.log_file_fd is not None:
            if self.multithread == True and self.os.thread_management is not None and self.os.thread_management.cur_thread is not None:
                fd = self.os.thread_management.cur_thread.log_file_fd
            else:
                fd = self.log_file_fd

            # setup filter for logger
            # FIXME: only works for logging due to we might need runtime disable nprint, it should be a global filter not only syscall
            if self.filter != None and self.output == QL_OUTPUT.DEFAULT:
                self.log_file_fd.addFilter(ql_setup_filter(self.filter))

            console_handlers = []

            for each_handler in fd.handlers:
                if type(each_handler) == logging.StreamHandler:
                    console_handlers.append(each_handler)

            if self.console == False:
                for each_console_handler in console_handlers:
                    if '_FalseFilter' not in [each.__class__.__name__ for each in each_console_handler.filters]:
                        each_console_handler.addFilter(ql_setup_filter(False))

            elif self.console == True:
                for each_console_handler in console_handlers:
                    for each_filter in [each for each in each_console_handler.filters]:
                        if '_FalseFilter' in each_filter.__class__.__name__:
                            each_console_handler.removeFilter(each_filter)
            
            try:
                msg = "".join(args)
            except:
                msg = "".join(str(args))    

            if kw.get("end", None) != None:
                msg += kw["end"]

            elif msg != os.linesep:
                msg += os.linesep

            fd.info(msg)


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


    def add_fs_mapper(self, host_src, ql_dest):
        self.fs_mapper.append([host_src, ql_dest])


    # push to stack bottom, and update stack register
    def stack_push(self, data):
        self.arch.stack_push(data)


    # pop from stack bottom, and update stack register
    def stack_pop(self):
        return self.arch.stack_pop()


    # read from stack, at a given offset from stack bottom
    # NOTE: unlike stack_pop(), this does not change stack register
    def stack_read(self, offset):
        return self.arch.stack_read(offset)


    # write to stack, at a given offset from stack bottom
    # NOTE: unlike stack_push(), this does not change stack register
    def stack_write(self, offset, data):
        self.arch.stack_write(offset, data)


    def arch_setup(self):
        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch")
        
        archmanager = arch_convert_str(self.archtype).upper()
        archmanager = ("QlArch" + archmanager)

        module_name = ql_build_module_import_name("arch", None, self.archtype)
        return ql_get_module_function(module_name, archmanager)(self)


    def os_setup(self, function_name = None):
        if not ql_is_valid_ostype(self.ostype):
            raise QlErrorOsType("[!] Invalid OSType")

        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch %s" % self.archtype)

        if function_name == None:
            ostype_str = ostype_convert_str(self.ostype)
            ostype_str = ostype_str.capitalize()
            function_name = "QlOs" + ostype_str
            module_name = ql_build_module_import_name("os", self.ostype)
            return ql_get_module_function(module_name, function_name)(self)

        elif function_name == "map_syscall":
            ostype_str = ostype_convert_str(self.ostype)
            arch_str = arch_convert_str(self.archtype)
            arch_str = arch_str + "_syscall"
            module_name = ql_build_module_import_name("os", ostype_str, arch_str)
            return ql_get_module_function(module_name, function_name)
        
        else:
            module_name = ql_build_module_import_name("os", self.ostype, self.archtype)
            return ql_get_module_function(module_name, function_name)


    def loader_setup(self, function_name = None):
        if not self.shellcoder:
            self.archtype, self.ostype, self.archendian = ql_checkostype(self.path)

        if not ql_is_valid_ostype(self.ostype):
            raise QlErrorOsType("[!] Invalid OSType")

        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch %s" % self.archtype)

        if function_name == None:
            loadertype_str = loadertype_convert_str(self.ostype)
            function_name = "QlLoader" + loadertype_str
            module_name = ql_build_module_import_name("loader", loadertype_str.lower())
            return ql_get_module_function(module_name, function_name)(self)


    def component_setup(self, component_type, function_name):
        if not ql_is_valid_ostype(self.ostype):
            raise QlErrorOsType("[!] Invalid OSType")

        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch %s" % self.archtype)

        module_name = "qiling." + component_type + "." + function_name
        function_name = "Ql" + function_name.capitalize() + "Manager"
        return ql_get_module_function(module_name, function_name)(self)


    def profile_setup(self):
        if self.profile:
            self.dprint(D_INFO, "[+] Customized profile: %s" % self.profile)
        
        os_profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles", ostype_convert_str(self.ostype) + ".ql")
      
        if self.profile:
            profiles = [os_profile, self.profile]
        else:
            profiles = [os_profile]

        config = configparser.ConfigParser()
        config.read(profiles)
        return config


    def compile(self, archtype, runcode, arm_thumb=None):
        try:
            loadarch = KS_ARCH_X86
        except:
            raise QlErrorOutput("Please install Keystone Engine")


        def ks_convert(arch):
            if self.archendian == QL_ENDIAN.EB:
                adapter = {
                    QL_ARCH.X86: (KS_ARCH_X86, KS_MODE_32),
                    QL_ARCH.X8664: (KS_ARCH_X86, KS_MODE_64),
                    QL_ARCH.MIPS: (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN),
                    QL_ARCH.ARM: (KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN),
                    QL_ARCH.ARM_THUMB: (KS_ARCH_ARM, KS_MODE_THUMB),
                    QL_ARCH.ARM64: (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),
                }
            else:
                adapter = {
                    QL_ARCH.X86: (KS_ARCH_X86, KS_MODE_32),
                    QL_ARCH.X8664: (KS_ARCH_X86, KS_MODE_64),
                    QL_ARCH.MIPS: (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN),
                    QL_ARCH.ARM: (KS_ARCH_ARM, KS_MODE_ARM),
                    QL_ARCH.ARM_THUMB: (KS_ARCH_ARM, KS_MODE_THUMB),
                    QL_ARCH.ARM64: (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),
                }

            return adapter.get(arch, (None,None))


        def compile_instructions(runcode, archtype, archmode):

            ks = Ks(archtype, archmode)
            shellcode = ''
            try:
                # Initialize engine in X86-32bit mode
                encoding, count = ks.asm(runcode)
                shellcode = ''.join('%02x' % i for i in encoding)
                shellcode = unhexlify(shellcode)
            except KsError as e:
                raise
            return shellcode

        if arm_thumb and archtype == QL_ARCH.ARM:
            archtype = QL_ARCH.ARM_THUMB

        archtype, archmode = ks_convert(archtype)
        return compile_instructions(runcode, archtype, archmode)        
