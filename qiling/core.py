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
from .utils import ql_setup_logging_env, ql_setup_logging_stream
from .core_struct import QLCoreStructs
from .core_hooks import QLCoreHooks
from .core_utils import QLCoreUtils
from .extensions.debugger import ql_debugger_init

__version__ = "1.1" + "-alpha2"

class Qiling(QLCoreStructs, QLCoreHooks, QLCoreUtils):    
    def __init__(
            self,
            filename=None,
            rootfs=None,
            env=None,
            shellcoder=None,
            ostype=None,
            archtype=None,
            bigendian=False,
            output=None,
            verbose=1,
            profile=None,
            console=True,
            log_dir=None,
            log_split=None,
            append=None,
            libcache = False,
            stdin=0,
            stdout=0,
            stderr=0,
    ):
        super(Qiling, self).__init__()

        ##################################
        # Definition during ql=Qiling()  #
        ##################################
        self.filename = filename
        self.rootfs = rootfs
        self.env = env if env else {}
        self.shellcoder = shellcoder
        self.ostype = ostype
        self.archtype = archtype
        self.bigendian = bigendian
        self.output = output
        self.verbose = verbose
        self.profile = profile
        self.console = console
        self.log_dir = log_dir
        self.log_split = log_split
        self.append = append
        self.libcache = libcache
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        
        ##################################
        # Definition after ql=Qiling()   #
        ##################################
        self.patch_bin = []
        self.patch_lib = []
        self.patched_lib = []
        self.log_file_fd = None
        self.fs_mapper = []
        self.debug_stop = False
        self.internal_exception = None
        self.platform = platform.system()
        self.debugger = None
        # due to the instablity of multithreading, added a swtich for multithreading
        self.multithread = False
        # To use IPv6 or not, to avoid binary double bind. ipv6 and ipv4 bind the same port at the same time
        self.ipv6 = False
        # Bind to localhost
        self.bindtolocalhost = True
        # by turning this on, you must run your analysis with sudo
        self.root = False
        # generic filter to filter print (WIP)
        self.filter = None
        self.remote_debug = None

        """
        Qiling Framework Core Engine
        """

        # shellcoder settings
        if self.shellcoder:
            if (self.ostype and type(self.ostype) == str) and (self.archtype and type(self.archtype) == str):
                self.ostype = ostype_convert(self.ostype.lower())
                self.archtype = arch_convert(self.archtype.lower())
                self.filename = ["qilingshellcoder"]
                if self.rootfs is None:
                    self.rootfs = "."
        # file check
        if self.shellcoder is None:
            if not os.path.exists(str(self.filename[0])):
                raise QlErrorFileNotFound("[!] Target binary not found")
            if not os.path.exists(self.rootfs):
                raise QlErrorFileNotFound("[!] Target rootfs not found")
        
        self.path = (str(self.filename[0]))
        self.argv = self.filename
        self.targetname = ntpath.basename(self.filename[0])

        ##########
        # Loader #
        ##########        
        self.loader = self.loader_setup()

        ############
        # setup    #
        ############           
        self.profile = self.profile_setup()
        if self.append == None:
            self.append = self.profile["MISC"]["append"]
        if self.log_dir == None:
            self.log_dir = self.profile["LOG"]["dir"]
        if self.log_split == None:            
            self.log_split =  self.profile.getboolean('LOG', 'split')

         # Log's configuration
        if self.log_dir != "" and type(self.log_dir) == str:
            _logger = ql_setup_logging_env(self)
            self.log_file_fd = _logger
        elif self.console == True:
            _logger = ql_setup_logging_stream(self)
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
        
        ####################################
        # Set pointersize (32bit or 64bit) #
        ####################################
        self.archbit = ql_get_arch_bits(self.archtype)
        self.pointersize = (self.archbit // 8)  
        
        # Endian for shellcode needs to set manually
        if self.shellcoder:
            self.archendian = QL_ENDIAN.EL
            if self.bigendian == True and self.archtype in (QL_ENDINABLE):
                self.archendian = QL_ENDIAN.EB

        #############
        # Component #
        #############
        self.mem = self.component_setup("os", "memory")
        self.reg = self.component_setup("arch", "register")

        #####################################
        # Architecture and OS               #
        #####################################
        # Load architecture's and os module #
        #####################################
        self.arch = self.arch_setup()
        self.os = self.os_setup()

        # Run the loader
        self.loader.run()


    # Emulate the binary from begin until @end, with timeout in @timeout and
    # number of emulated instructions in @count
    def run(self, begin=None, end=None, timeout=0, count=0):
        # replace the original entry point, exit point, timeout and count
        self.entry_point = begin
        self.exit_point = end
        self.timeout = timeout
        self.count = count
        
        # init debugger
        if self.debugger is not None:
            ql_debugger_init(self)

        # patch binary
        self.__enable_bin_patch()

        # emulate the binary
        self.os.run()

        # resume with debugger
        if self.debugger is not None:
            self.remote_debug.run()


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
            self.mem.write(self.loader.load_address + addr, code)


    def enable_lib_patch(self):
        for addr, code, filename in self.patch_lib:
            try:
                self.mem.write(self.mem.get_lib_base(filename) + addr, code)
            except:
                raise RuntimeError("Fail to patch %s at address 0x%x" % (filename, addr))


    # stop emulation
    def emu_stop(self):
        self.uc.emu_stop()


    # start emulation
    def emu_start(self, begin, end, timeout=0, count=0):
        self.uc.emu_start(begin, end, timeout, count)
