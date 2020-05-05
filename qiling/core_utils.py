#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os, logging, configparser
from .utils import ql_build_module_import_name, ql_get_module_function
from .utils import ql_is_valid_arch, ql_is_valid_ostype
from .utils import loadertype_convert_str, ostype_convert_str, arch_convert_str
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
        if self.log_console == True:
            print (*args, **kw)
        elif type(self.log_console) is bool:
            pass
        else:
            raise QlErrorOutput("[!] log_consnsole must be True or False")     
        
        # FIXME: this is due to log_console must be able to update duirng runtime
        if self.log_file_fd is not None:
            if self.multithread == True and self.os.thread_management is not None and self.os.thread_management.cur_thread is not None:
                fd = self.os.thread_management.cur_thread.log_file_fd
            else:
                fd = self.log_file_fd

            msg = args[0]
            msg += kw["end"] if kw.get("end", None) != None else os.linesep
            fd.info(msg)

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

    def context(self, saved_context= None):
        if saved_context == None:
            return self.uc.context_save()
        else:
            self.uc.context_restore(saved_context)

    def add_fs_mapper(self, fm, to):
        self.fs_mapper.append([fm, to])
    
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
