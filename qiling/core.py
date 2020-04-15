#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys
import platform
import ntpath
import os as pyos

from .const import *
from .exception import *
from .utils import *
from .debugger.utils import *
from .core_struct import QLCoreStructs
from .core_hooks import QLCoreHooks

__version__ = "1.0"

class Qiling(QLCoreStructs, QLCoreHooks):    
    def __init__(
            self,
            filename=None,
            rootfs=None,
            argv=[],
            env={},
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
            mmap_start=0,
            stack_address=0,
            stack_size=0,
            interp_base=0,
            append = None,
    ):
        # Define during ql=Qiling()
        self.output = output
        self.verbose = verbose
        self.ostype = ostype
        self.archtype = archtype
        self.bigendian = bigendian
        self.shellcoder = shellcoder
        self.filename = filename
        self.rootfs = rootfs
        self.argv = argv
        self.env = env
        self.libcache = libcache
        self.log_console = log_console
        self.log_dir = log_dir
        self.mmap_start = mmap_start
        self.stack_address = stack_address
        self.stack_size = stack_size
        self.interp_base = interp_base
        # generic append function, eg log file        
        self.append = append

        # Define after ql=Qiling(), either defined by Qiling Framework or user defined
        self.archbit = ''
        self.path = ''
        self.entry_point = 0
        self.patch_bin = []
        self.patch_lib = []
        self.patched_lib = []
        self.timeout = 0
        self.until_addr = 0
        self.byte = 0
        self.log_file_fd = None
        self.fs_mapper = []
        self.exit_code = 0
        self.debug_stop = False
        self.internal_exception = None
        self.platform = platform.system()
        self.debugger = None
        self.automatize_input = False
        self.profile = None 
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


        """
        Qiling Framework Core Engine
        """
        # ostype string - int convertion
        if self.shellcoder:
            if (self.ostype and type(self.ostype) == str) and (self.archtype and type(self.archtype) == str ):
                self.ostype = self.ostype.lower()
                self.ostype = ostype_convert(self.ostype)
                self.archtype = self.archtype.lower()
                self.archtype = arch_convert(self.archtype)

        # read file propeties, not shellcoder
        if self.rootfs and self.shellcoder is None:
            if pyos.path.exists(str(self.filename[0])) and pyos.path.exists(self.rootfs):
                self.path = (str(self.filename[0]))
                if self.ostype is None or self.archtype is None:
                    self.archtype, self.ostype = ql_checkostype(self)

                self.argv = self.filename

            else:
                if not pyos.path.exists(str(self.filename[0])):
                    raise QlErrorFileNotFound("[!] Target binary not found")
                if not pyos.path.exists(self.rootfs):
                    raise QlErrorFileNotFound("[!] Target rootfs not found")

        if self.shellcoder:
            self.targetname = "qilingshellcode"
        else:    
            self.targetname = ntpath.basename(self.filename[0])

        # Looger's configuration
        _logger = ql_setup_logging_stream(self)
        if self.log_dir is not None and type(self.log_dir) == str:
            _logger = ql_setup_logging_env(self, _logger)    
        self.log_file_fd = _logger
            
        # OS dependent configuration for stdio
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

        # double check supported architecture
        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch")

        # chceck for supported OS type
        if self.ostype not in QL_OS_ALL:
            raise QlErrorOsType("[!] OSTYPE required: either 'linux', 'windows', 'freebsd', 'macos'")
        
        # qiling output method conversion
        if self.output and type(self.output) == str:
            self.output = self.output.lower()
            if self.output not in QL_OUTPUT:
                raise QlErrorOutput("[!] OUTPUT required: either 'default', 'off', 'disasm', 'debug', 'dump'")

        # check verbose, only can check after ouput being defined
        if type(self.verbose) != int or self.verbose > 99 and (self.verbose > 0 and self.output not in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP)):
            raise QlErrorOutput("[!] verbose required input as int and less than 99")
        
        ##############################################################
        # Define file is 32 or 64bit and check file endian           #
        # QL_ENDIAN.EL = Little Endian || QL_ENDIAN.EB = Big Endian  #
        # QL_ENDIAN.EB is define during ql_elf_check_archtype()      #
        ##############################################################
        self.archbit = ql_get_arch_bits(self.archtype)
        if self.archtype not in (QL_ENDINABLE):
            self.archendian = QL_ENDIAN.EL
        
        #Endian for shellcode needs to set manually
        if self.shellcoder and self.bigendian == True and self.archtype in (QL_ENDINABLE):
            self.archendian = QL_ENDIAN.EB
        elif self.shellcoder:
            self.archendian = QL_ENDIAN.EL

        # based on CPU bit and set pointer size
        if self.archbit:
            self.pointersize = (self.archbit // 8)            

        #############
        # Component #
        #############
        self.mem = ql_component_setup(self, "memory")
        self.reg = ql_component_setup(self, "register")

        #####################################
        # Architecture                      #
        #####################################
        # Load architecture's and os module #
        # ql.reg.pc, ql.reg.sp and etc      #
        #####################################
        self.arch = ql_arch_setup(self)

        ######
        # OS #
        ######
        self.os = ql_os_setup(self)

        ##########
        # Loader #
        ##########
        self.loader = ql_loader_setup(self)
       

    def run(self):
        # setup strace filter for logger
        if self.strace_filter != None and self.output == QL_OUTPUT.DEFAULT:
            self.log_file_fd.addFilter(Strace_filter(self.strace_filter))

        # init debugger
        ql_debugger_init(self)

        # patch binary
        self.__enable_bin_patch()

        # run the binary
        self.os.run()     

        # resume with debugger
        if self.debugger is not None:
            self.remotedebugsession.run()

    # normal print out
    def nprint(self, *args, **kw):
        if self.multithread == True and self.os.thread_management is not None and self.os.thread_management.cur_thread is not None:
            fd = self.os.thread_management.cur_thread.log_file_fd
        else:
            fd = self.log_file_fd

        msg = args[0]

        # support keyword "end" in ql.print functions, use it as terminator or default newline character by OS
        msg += kw["end"] if kw.get("end", None) != None else pyos.linesep

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

   
    # replace linux or windows syscall/api with custom api/syscall
    # if replace function name is needed, first syscall must be available
    # - ql.set_syscall(0x04, my_syscall_write)
    # - ql.set_syscall("write", my_syscall_write)
    def set_syscall(self, syscall_cur, syscall_new):
        if self.ostype in (QL_POSIX):
            if isinstance(syscall_cur, int):
                self.os.dict_posix_syscall_by_num[syscall_cur] = syscall_new
            else:
                syscall_name = "ql_syscall_" + str(syscall_cur)
                self.os.dict_posix_syscall[syscall_name] = syscall_new
        elif self.ostype == QL_OS.WINDOWS:
            self.set_api(syscall_cur, syscall_new)

    # replace Windows API with custom syscall
    def set_api(self, syscall_cur, syscall_new):
        if self.ostype == QL_OS.WINDOWS:
            self.os.user_defined_api[syscall_cur] = syscall_new
        elif self.ostype in (QL_POSIX):
            self.set_syscall(syscall_cur, syscall_new)

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

    # patch @code to memory address @addr
    def patch(self, addr, code, file_name=b''):
        if file_name == b'':
            self.patch_bin.append((addr, code))
        else:
            self.patch_lib.append((addr, code, file_name.decode()))
    
    # ql.register - read and write register 
    def register(self, register_str= None, value= None):
        return self.reg.rw(register_str, value)

    def context(self, saved_context= None):
        if saved_context == None:
            return self.uc.context_save()
        else:
            self.uc.context_restore(saved_context)

    def emu_stop(self):
        self.uc.emu_stop()

    def emu_start(self, begin, end, timeout=0, count=0):
        self.uc.emu_start(begin, end, timeout, count)

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

    def set_timeout(self, microseconds):
        self.timeout = microseconds

    def set_exit(self, until_addr):
        self.until_addr = until_addr

    def add_fs_mapper(self, fm, to):
        self.fs_mapper.append([fm, to])