#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import platform
import ntpath
import os
import logging

from .const import QL_ENDINABLE, QL_ENDIAN, QL_POSIX, QL_OS_ALL, QL_OUTPUT, QL_OS
from .exception import QlErrorFileNotFound, QlErrorArch, QlErrorOsType, QlErrorOutput
from .utils import arch_convert, ostype_convert, output_convert
from .utils import ql_is_valid_arch, ql_get_arch_bits
from .utils import ql_setup_logging_env
from .utils import Strace_filter
from .core_struct import QLCoreStructs
from .core_hooks import QLCoreHooks
from .core_utils import QLCoreUtils
from .debugger import ql_debugger_init

__version__ = "1.0"

class Qiling(QLCoreStructs, QLCoreHooks, QLCoreUtils):    
    def __init__(
            self,
            filename=None,
            rootfs=None,
            argv=None,
            env=None,
            shellcoder=None,
            ostype=None,
            archtype=None,
            bigendian=False,
            libcache=False,
            stdin=0,
            stdout=0,
            stderr=0,
            output=None,
            verbose=1,
            log_console=True,
            log_dir=None,
            append = None,
            profile=None
    ):
        super(Qiling, self).__init__()

        # Define during ql=Qiling()
        self.output = output
        self.verbose = verbose
        self.ostype = ostype
        self.archtype = archtype
        self.bigendian = bigendian
        self.shellcoder = shellcoder
        self.filename = filename
        self.rootfs = rootfs
        self.argv = argv if argv else []
        self.env = env if env else {}
        self.libcache = libcache
        self.log_console = log_console
        self.log_dir = log_dir
        # generic append function, eg log file        
        self.append = append
        self.profile = profile
        # OS dependent configuration for stdio
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

        ##################################
        # Defination after ql=Qiling()   #
        ##################################
        
        self.archbit = ''
        self.path = ''
        self.patch_bin = []
        self.patch_lib = []
        self.patched_lib = []
        self.log_file_fd = None
        self.fs_mapper = []
        self.exit_code = 0
        self.debug_stop = False
        self.internal_exception = None
        self.platform = platform.system()
        self.debugger = None
        # due to the instablity of multithreading, added a swtich for multithreading. at least for MIPS32EL for now
        self.multithread = False
        # To use IPv6 or not, to avoid binary double bind. ipv6 and ipv4 bind the same port at the same time
        self.ipv6 = False        
        # Bind to localhost
        self.bindtolocalhost = False
        # by turning this on, you must run your analysis with sudo
        self.root = True
        self.log_split = False
        # syscall filter for strace-like functionality
        self.strace_filter = None
        self.remotedebugsession = None
        self.automatize_input = False
        self.mmap_start = 0
        self.stack_address = 0
        self.stack_size = 0
        self.interp_base = 0

        """
        Qiling Framework Core Engine
        """
        # shellcoder or file settings
        if self.shellcoder:
            if (self.ostype and type(self.ostype) == str) and (self.archtype and type(self.archtype) == str ):
                self.ostype = self.ostype.lower()
                self.ostype = ostype_convert(self.ostype)
                self.archtype = self.archtype.lower()
                self.archtype = arch_convert(self.archtype)
                self.targetname = "qilingshellcode"

        elif self.shellcoder is None:
            if os.path.exists(str(self.filename[0])) and os.path.exists(self.rootfs):
                self.path = (str(self.filename[0]))
                self.argv = self.filename
                self.targetname = ntpath.basename(self.filename[0])
            else:
                if not os.path.exists(str(self.filename[0])):
                    raise QlErrorFileNotFound("[!] Target binary not found")
                if not os.path.exists(self.rootfs):
                    raise QlErrorFileNotFound("[!] Target rootfs not found")
        
        ##########
        # Loader #
        ##########        
        self.loader = self.loader_setup()

        # Looger's configuration
        if self.log_dir is not None and type(self.log_dir) == str:
            _logger = ql_setup_logging_env(self)    
            self.log_file_fd = _logger
        
        # qiling output method conversion
        if self.output and type(self.output) == str:
            # setter / getter for output
            self.output = self.output.lower()
            if self.output not in QL_OUTPUT:
                raise QlErrorOutput("[!] OUTPUT required: either 'default', 'disasm', 'debug', 'dump'")
            
        # check verbose, only can check after ouput being defined
        if type(self.verbose) != int or self.verbose > 99 and (self.verbose > 0 and self.output not in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP)):
            raise QlErrorOutput("[!] verbose required input as int and less than 99")
        
        ##############################
        # Define file is 32 or 64bit #
        # Define pointersize         #
        ##############################
        self.archbit = ql_get_arch_bits(self.archtype)
        self.pointersize = (self.archbit // 8)  
        
        #Endian for shellcode needs to set manually
        if self.shellcoder and self.bigendian == True and self.archtype in (QL_ENDINABLE):
            self.archendian = QL_ENDIAN.EB
        elif self.shellcoder:
            self.archendian = QL_ENDIAN.EL

        #############
        # Component #
        #############
        self.mem = self.component_setup("os", "memory")
        self.reg = self.component_setup("arch", "register")

        #####################################
        # Architecture                      #
        #####################################
        # Load architecture's and os module #
        # ql.reg.pc, ql.reg.sp and etc      #
        #####################################
        self.arch = self.arch_setup()

        ######
        # OS #
        ######
        self.os = self.os_setup()

    def run(self, begin=0, end=0, timeout=0, count=0):
        # replace the original entry point, exit point, timeout and count
        self.entry_point = begin
        self.exit_point = end
        self.timeout = timeout
        self.count = count

        # load the loader
        self.loader.run()
        
        # setup strace filter for logger
        # FIXME: only works for logging due to we might need runtime disable nprint
        if self.strace_filter != None and self.output == QL_OUTPUT.DEFAULT and self.log_file_fd:
            self.log_file_fd.addFilter(Strace_filter(self.strace_filter))

        # init debugger
        if self.debugger is not None:
            ql_debugger_init(self)

        # patch binary
        self.__enable_bin_patch()

        # run the binary
        self.os.run()     

        # resume with debugger
        if self.debugger is not None:
            self.remotedebugsession.run()

    # patch @code to memory address @addr
    def patch(self, addr, code, file_name=b''):
        if file_name == b'':
            self.patch_bin.append((addr, code))
        else:
            self.patch_lib.append((addr, code, file_name.decode()))
    
    # ql.output var getter
    @property
    def output(self):
        return self._output

    # ql.output - output var setter eg. QL_OUTPUT.DEFAULT and etc
    @output.setter
    def output(self, output):
        self._output = output_convert(output)
    
    # ql.platform - platform var = host os getter eg. LINUX and etc
    @property
    def platform(self):
        return self._platform

    # ql.platform - platform var = host os setter eg. LINUX and etc
    @platform.setter
    def platform(self, value):
        self._platform = ostype_convert(value.lower())

    def __enable_bin_patch(self):
        for addr, code in self.patch_bin:
            self.mem.write(self.loader.loadbase + addr, code)

    def enable_lib_patch(self):
        for addr, code, filename in self.patch_lib:
            self.mem.write(self.mem.get_lib_base(filename) + addr, code)

    def emu_stop(self):
        self.uc.emu_stop()

    def emu_start(self, begin, end, timeout=0, count=0):
        self.uc.emu_start(begin, end, timeout, count)
