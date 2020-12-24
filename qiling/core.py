#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from configparser import ConfigParser
import ctypes, logging, ntpath, os, pickle, platform
import io
from sys import stdin, stdout
# See https://stackoverflow.com/questions/39740632/python-type-hinting-without-cyclic-imports
from typing import Dict, List, Union
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .arch.register import QlRegisterManager
    from .arch.arch import QlArch
    from .os.os import QlOs
    from .os.memory import QlMemoryManager
    from .loader.loader import QlLoader

from .const import D_DRPT, QL_ARCH_ENDIAN, QL_ENDIAN, QL_INTERCEPT, QL_OS_POSIX, QL_OS_ALL, QL_OUTPUT, QL_OS
from .exception import QlErrorFileNotFound, QlErrorArch, QlErrorOsType, QlErrorOutput
from .utils import *
from .core_struct import QlCoreStructs
from .core_hooks import QlCoreHooks
from .__version__ import __version__

# Mixin Pattern
class Qiling(QlCoreHooks, QlCoreStructs):    
    def __init__(
            self,
            argv=None,
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
            multithread = False,
            stdin=0,
            stdout=0,
            stderr=0,
    ):
        """ Create a Qiling instance.

            For each argument or property, please refer to its docstring. e.g. Qiling.multithread.__doc__

            The only exception is "bigendian" parameter, see Qiling.archendian.__doc__ for details.
        """

        ##################################
        # Definition during ql=Qiling()  #
        ##################################
        self._argv = argv
        self._rootfs = rootfs
        self._env = env if env else {}
        self._shellcoder = shellcoder
        self._ostype = ostype
        self._archtype = archtype
        self._archendian = None
        self._archbit = None
        self._pointersize = None
        self._profile = profile
        self._console = console
        self._log_dir = log_dir
        self._log_split = log_split
        self._append = append
        self._multithread = multithread
        self._log_file_fd = None
        self._platform = ostype_convert(platform.system().lower())
        self._internal_exception = None
        self._uc = None
        
        ##################################
        # Definition after ql=Qiling()   #
        ##################################
        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr
        self._output = output
        self._verbose = verbose
        self._libcache = libcache
        self._patch_bin = []
        self._patch_lib = []
        self._debug_stop = False
        self._debugger = None
        self._root = False
        self._filter = None

        """
        Qiling Framework Core Engine
        """
        ##############
        # Shellcode? #
        ##############
        if self._shellcoder:
            if (self._ostype and type(self._ostype) == str) and (self._archtype and type(self._archtype) == str):
                self._ostype = ostype_convert(self._ostype.lower())
                self._archtype = arch_convert(self._archtype.lower())
                self._argv = ["qilingshellcoder"]
                if self._rootfs is None:
                    self._rootfs = "."

        # file check
        if self._shellcoder is None:
            if not os.path.exists(str(self._argv[0])):
                raise QlErrorFileNotFound("[!] Target binary not found")
            if not os.path.exists(self._rootfs):
                raise QlErrorFileNotFound("[!] Target rootfs not found")
        
        self._path = (str(self._argv[0]))
        self._targetname = ntpath.basename(self._argv[0])

        ##########
        # Loader #
        ##########
        if self._shellcoder is None:
            guessed_archtype, guessed_ostype, guessed_archendian = ql_guess_emu_env(self._path)
            if self._ostype is None:
                self._ostype = guessed_ostype
            if self._archtype is None:
                self._archtype = guessed_archtype
            if self.archendian is None:
                self._archendian = guessed_archendian

            if not ql_is_valid_ostype(self._ostype):
                raise QlErrorOsType("[!] Invalid OSType")

            if not ql_is_valid_arch(self._archtype):
                raise QlErrorArch("[!] Invalid Arch %s" % self._archtype)

        self._loader = loader_setup(self._ostype, self)

        #####################
        # Profile & Logging #
        #####################
        self._profile = profile_setup(self.ostype, self.profile, self)
        if self._append == None:
            self._append = self._profile["MISC"]["append"]
        if self._log_dir == None:
            self._log_dir = self._profile["LOG"]["dir"]
        if self._log_split == None:            
            self._log_split =  self._profile.getboolean('LOG', 'split')

        # Log's configuration
        
        # Setup output mode.
        self._output = output_convert(self._output)

        # We only use the root logger now.
        ql_setup_logger(self, 
                        self._log_dir, 
                        self._targetname + self._append + ".qlog", 
                        self._log_split, self._console, 
                        self._filter, 
                        self._multithread)
        # For compatibility.
        self._log_file_fd = logging.getLogger()
        
        ql_resolve_logger_level(self._output, self._verbose)
        
        ########################
        # Archbit & Endianness #
        ########################
        self._archbit = ql_get_arch_bits(self._archtype)
        self._pointersize = (self.archbit // 8)  
        
        # Endian for shellcode needs to set manually
        if self._shellcoder:
            self._archendian = QL_ENDIAN.EL
            if bigendian == True and self._archtype in (QL_ARCH_ENDIAN):
                self._archendian = QL_ENDIAN.EB
        
        # Once we finish setting up archendian and arcbit, we can init QlCoreStructs.
        QlCoreStructs.__init__(self, self._archendian, self._archbit)

        ##############
        # Components #
        ##############
        self._mem = component_setup("os", "memory", self)
        self._reg = component_setup("arch", "register", self)
        self._arch = arch_setup(self.archtype, self)
        
        # Once we finish setting up arch layer, we can init QlCoreHooks.
        self.uc = self.arch.init_uc
        QlCoreHooks.__init__(self, self.uc)

        self._os = os_setup(self.archtype, self.ostype, self)

        # Run the loader
        self.loader.run()
        
        # Setup Outpt
        self.os.setup_output()

    
    #####################
    # Qiling Components #
    #####################

    @property
    def mem(self) -> "QlMemoryManager":
        """ Qiling memory manager.

            Example: ql.mem.read(0xdeadbeaf, 4)
        """
        return self._mem
    
    @property
    def reg(self) -> "QlRegisterManager":
        """ Qiling register manager.

            Example: ql.reg.eax = 1
        """
        return self._reg
    
    @property
    def arch(self) -> "QlArch":
        """ Qiling architecture layer.

            Also see qiling/arch/<arch>.py
        """
        return self._arch

    @property
    def loader(self) -> "QlLoader":
        """ Qiling loader layer.

            Also see qiling/loader/<filetype>.py
        """
        return self._loader

    @property
    def os(self) -> "QlOs":
        """ Qiling os layer.

            Also see qiling/os/<os>/<os>/py
        """
        return self._os

    ##################
    # Qiling Options #
    ##################

    # If an option doesn't have a setter, it means that it can be only set during Qiling.__init__
    # TODO: Rename to suffix?
    @property
    def append(self) -> str:
        """ Suffix appended to the filename.
            Used when writing to file (e.g. logging).

            Type: str
            Example: Qiling(append="dbg")
        """
        return self._append

    @property
    def log_dir(self) -> str:
        """ Specify the logging directory.
            Use with ql.log_split.

            Type: str
            Example: Qiling(log_dir=".")
        """
        return self._log_dir
    
    @property
    def log_split(self) -> bool:
        """ Specify whether spliting logs within multiprocess/multithread context.
            Use with ql.log_dir.

            Type: bool
            Example: Qiling(log_split=True)
        """
        return self._log_split

    @property
    def console(self) -> bool:
        """ Specify whether enabling console output. 

            Type: bool
            Example: Qiling(console=True)
        """
        return self._console

    @property
    def multithread(self) -> bool:
        """ Specify whether multithread has been enabled.

            WARNING: This property shouldn't be set after Qiling.__init__.

            Type: bool
            Example: Qiling(multithread=True)
        """
        return self._multithread

    @property
    def profile(self) -> ConfigParser:
        """ Program profile. See qiling/profiles/*.ql for details.

            Note: Please pass None or the path string to Qiling.__init__.

            Type: ConfigParser
            Value: str
            Example: Qiling(profile="profiles/dos.ql")
        """
        return self._profile
    
    @property
    def argv(self) -> List[str]:
        """ The program argv.

            Type: List[str]
            Example: Qiling(argv=['/bin/ls', '-a'])
        """
        return self._argv

    @property
    def rootfs(self) -> str:
        """ The program rootfs. For some common rootfs, see examples/rootfs/ for details.

            Type: str
            Example: Qiling(argv=['/bin/ls', '-a'], rootfs='examples/rootfs/x8664_linux/')
        """
        return self._rootfs

    @property
    def env(self) -> Dict[str, str]:
        """ The program environment variables.

            Type: Dict[str, str]
            Example: Qiling(env={"LC_ALL" : "en_US.UTF-8"})
        """
        return self._env

    @property
    def ostype(self) -> int:
        """ The emulated os type.

            Note: Please pass None or one of the strings below to Qiling.__init__.
                  If you use shellcode, you must specify ostype and archtype manually.

            Type: int.
            Values:
              - "macos" : macOS.
              - "darwin" : an alias to "macos".
              - "freebsd" : FreeBSD
              - "windows" : Windows
              - "uefi" : UEFI
              - "dos" : DOS
            Example: Qiling(shellcoder=b"\x90", ostype="macos", archtype="x8664", bigendian=False)
        """
        return self._ostype

    @property
    def archtype(self) -> int:
        """ The emulated architecture type.

            Note: Please pass None or one of the strings below to Qiling.__init__.
                  If you use shellcode, you must specify ostype and archtype manually.
            
            Type: int
            Values:
              - "x86" : x86_32
              - "x8664" : x86_64
              - "mips" : MIPS
              - "arm" : ARM
              - "arm_thumb" : ARM with thumb mode.
              - "arm64" : ARM64
              - "a8086" : 8086
            Example: Qiling(shellcoder=b"\x90", ostype="macos", archtype="x8664", bigendian=False)
        """
        return self._archtype

    @property
    def archendian(self) -> int:
        """ The architecure endian.

            Note: Please pass "bigendian=True" or "bingendian=False" to set this property.
                  This option only takes effect for shellcode.

            Type: int
            Example: Qiling(shellcoder=b"\x90", ostype="macos", archtype="x8664", bigendian=False)
        """
        return self._archendian

    @property
    def archbit(self) -> int:
        """ The bits of the current architecutre.

            Type: int
        """
        return self._archbit

    @property
    def pointersize(self) -> int:
        """ The pointer size of current architecture.

            Type: int
        """
        return self._pointersize

    @property
    def shellcoder(self) -> bytes:
        """ The shellcode to execute.

            Note: It can't be used with "argv" parameter.

            Type: bytes
            Example: Qiling(shellcoder=b"\x90", ostype="macos", archtype="x8664", bigendian=False)
        """
        return self._shellcoder

    @property
    def path(self) -> str:
        """ The file path of the executable.

            Type: str
        """
        return self._path
    
    @property
    def targetname(self) -> str:
        """ The target name of the executable. e.g. "c.exe" in "a\b\c.exe"

            Type: str
        """
        return self._targetname

    @property
    def log_file_fd(self) -> logging.Logger:
        """ Only reserved for compatibility, never use it directly.

            Type: logging.Logger
        """
        return self._log_file_fd

    @property
    def platform(self):
        """ Specify current platform where Qiling runs on.

            Type: int
            Values: All possible values from platform.system()
        """
        return self._platform

    @platform.setter
    def platform(self, value):
        if type(value) is str:
            self._platform = ostype_convert(value.lower())
        else:
            self._platform = value

    @property
    def internal_exception(self) -> Exception:
        """ Internal exception catched during Unicorn callback. Not intended for regular users.

            Type: Exception
        """
        return self._internal_exception

    @property
    def stdin(self) -> io.IOBase:
        """ Stdin of the program. Can be any object which implements (even part of) io.IOBase.

            Type: io.Base
            Example: ql = Qiling(stdin=sys.stdin)
                     ql.stdin = sys.stdin
        """
        return self._stdin
    
    @stdin.setter
    def stdin(self, s):
        self._stdin = s
    
    @property
    def stdout(self) -> io.IOBase:
        """ Stdout of the program. Can be any object which implements (even part of) io.IOBase.

            Type: io.Base
            Example: ql = Qiling(stdout=sys.stdout)
                     ql.stdout = sys.stdout
        """
        return self._stdout

    @stdout.setter
    def stdout(self, s):
        self._stdout = s
    
    @property
    def stderr(self) -> io.IOBase:
        """ Stdout of the program. Can be any object which implements (even part of) io.IOBase.

            Type: io.Base
            Example: ql = Qiling(stderr=sys.stderr)
                     ql.stderr = sys.stderr
        """
        return self._stderr
    
    @stderr.setter
    def stderr(self, s):
        self._stderr = s
    
    @property
    def libcache(self) -> bool:
        """ Whether cache dll files. Only take effect in Windows emulation.

            Type: bool
            Example: ql = Qiling(libcache=False)
                     ql.libcache = True
        """
        return self._libcache

    @libcache.setter
    def libcache(self, lc):
        self._libcache = lc

    @property
    def output(self) -> int:
        """ Specify the qiling output. See Qiling.verbose.__doc__ for details.

            Note: Please pass None or one of the strings below to Qiling.__init__.

            Type: int
            Values:
              - "default": equals to "output=None", do nothing.
              - "off": an alias to "default".
              - "debug": set the log level to logging.DEBUG.
              - "disasm": diasm each executed instruction.
              - "dump": the most verbose output, dump registers and diasm the function blocks.
            Example: ql = Qiling(output="off")
                     ql.output = "off"
        """
        return self._output
    
    @output.setter
    def output(self, op):
        if type(op) is str:
            self._output = output_convert(op)
        else:
            self._output = op
        ql_resolve_logger_level(self._output, self._verbose)

    @property
    def verbose(self):
        """ Set the verbose level.
            
            If you set "ql.output" to "default" or "off", you can set logging level dynamically by
            changing "ql.verbose".

            Type: int
            Values:
              - 0  : logging.WARNING, almost no additional logs except the program output.
              - >=1: logging.INFO, the default logging level.
              - >=4: logging.DEBUG.
            Example: ql = Qiling(verbose=5)
                     ql.verbose = 0
        """
        return self._verbose
    
    @verbose.setter
    def verbose(self, v):
        self._verbose = v
        ql_resolve_logger_level(self._output, self._verbose)
    
    @property
    def patch_bin(self) -> list:
        """ Return the patches for binary.

            Type: list
        """
        return self._patch_bin
    
    @property
    def patch_lib(self) -> list:
        """ Return the patches for library.

            Type: list
        """
        return self._patch_lib

    @property
    def debug_stop(self) -> bool:
        """ Stop if some syscalls is not implemented.

            Note: This option is broken on some archs.

            Type: bool
            Example: ql.debug_stop = True
        """
        return self._debug_stop

    @debug_stop.setter
    def debug_stop(self, ds):
        self._debug_stop = ds

    @property
    def debugger(self) -> Union[str, bool]:
        """ Enable debugger.

            Type: debugger instance
            Values:
              - "gdb": enable gdb.
              - True : an alias to "gdb".
              - "gdb:0.0.0.0:1234" : gdb which listens on 0.0.0.0:1234
              - "qdb": enable qdb.
              - "qdb:rr": enable qdb with reverse debugging support.
            Example: ql.debugger = True
                     ql.debugger = "qdb"
        """
        return self._debugger
    
    @debugger.setter
    def debugger(self, dbger):
        self._debugger = dbger

    @property
    def root(self) -> bool:
        """ Whether run current program as root?

            Type: bool
            Examples: ql.root = True
        """
        return self._root

    @root.setter
    def root(self, root):
        self._root = root

    @property
    def filter(self) -> List[str]:
        """ Filter logs with regex.
            
            Type: List[str]
            Example: ql.filter = [r'^open']
        """
        return self._filter

    @filter.setter
    def filter(self, ft):
        self._filter = ft

    @property
    def uc(self):
        """ Raw uc instance.

            Type: Uc
        """
        return self._uc

    @uc.setter
    def uc(self, u):
        self._uc = u

    def __enable_bin_patch(self):
        for addr, code in self.patch_bin:
            self.mem.write(self.loader.load_address + addr, code)


    def enable_lib_patch(self):
        for addr, code, filename in self.patch_lib:
            try:
                self.mem.write(self.mem.get_lib_base(filename) + addr, code)
            except:
                raise RuntimeError("Fail to patch %s at address 0x%x" % (filename, addr))
    
    ###############
    # Qiling APIS #
    ###############

    # Emulate the binary from begin until @end, with timeout in @timeout and
    # number of emulated instructions in @count
    def run(self, begin=None, end=None, timeout=0, count=0):
        # replace the original entry point, exit point, timeout and count
        self.entry_point = begin
        self.exit_point = end
        self.timeout = timeout
        self.count = count

        # init debugger
        if self._debugger != False and self._debugger != None:
            self._debugger = debugger_setup(self._debugger, self)

        # patch binary
        self.__enable_bin_patch()

        # emulate the binary
        self.os.run()

        # run debugger
        if self._debugger != False and self._debugger != None:
            self._debugger.run()


    # patch code to memory address
    def patch(self, addr, code, file_name=b''):
        if file_name == b'':
            self.patch_bin.append((addr, code))
        else:
            self.patch_lib.append((addr, code, file_name.decode()))

    # Depreciated. Please use logging directly.
    # Will be removed in later release.
    def nprint(self, *args, **kw):
        if type(self.console) is bool:
            pass
        else:
            raise QlErrorOutput("[!] console must be True or False")     
        
        # FIXME: this is due to console must be able to update during runtime
        if self.log_file_fd is not None:
            if self.multithread == True and self.os.thread_management is not None and self.os.thread_management.cur_thread is not None:
                fd = self.os.thread_management.cur_thread.log_file_fd
            else:
                fd = self.log_file_fd
            
            args = map(str, args)
            msg = kw.get("sep", " ").join(args)

            if kw.get("end", None) != None:
                msg += kw["end"]

            fd.info(msg)

    # Depreciated. Please use logging directly.
    # Will be removed in later release.
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
            if int(self.verbose) >= D_DRPT:
                try:
                    current_pc = self.reg.arch_pc
                except:
                    current_pc = 0    

                args = (("0x%x:" % current_pc), *args)        
                
            self.nprint(*args, **kw)


    # save all qiling instance states
    def save(self, reg=True, mem=True, fd=False, cpu_context=False, os_context=False, loader=False, snapshot=None):
        saved_states = {}

        if reg == True:
            saved_states.update({"reg": self.reg.save()})

        if mem == True:
            saved_states.update({"mem": self.mem.save()})

        if fd == True: 
            saved_states.update({"fd": self.os.fd.save()})

        if cpu_context == True:
            saved_states.update({"cpu_context": self.arch.context_save()})

        if os_context == True:
            saved_states.update({"os_context": self.os.save()})
        
        if loader == True:
            saved_states.update({"loader": self.loader.save()})

        if snapshot != None:
            with open(snapshot, "wb") as save_state:
                pickle.dump(saved_states, save_state)
        else:
            return saved_states


    # restore states qiling instance from saved_states
    def restore(self, saved_states=None, snapshot=None):

        # snapshot will be ignored if saved_states is set
        if saved_states == None and snapshot != None:
            with open(snapshot, "rb") as load_state:
                saved_states = pickle.load(load_state)

        if "cpu_context" in saved_states:
            self.arch.context_restore(saved_states["cpu_context"])

        if "reg" in saved_states:
            self.reg.restore(saved_states["reg"])

        if "mem" in saved_states:
            self.mem.restore(saved_states["mem"])
        
        if "fd" in saved_states:
            self.os.fd.restore(saved_states["fd"])

        if "os_context" in saved_states:
            self.os.restore(saved_states["os_context"])
        
        if "loader" in saved_states:
            self.loader.restore(saved_states["loader"])

    # replace linux or windows syscall/api with custom api/syscall
    # if replace function name is needed, first syscall must be available
    # - ql.set_syscall(0x04, my_syscall_write)
    # - ql.set_syscall("write", my_syscall_write)
    # TODO: Add correspoinding API in ql.os!
    def set_syscall(self, target_syscall, intercept_function, intercept = None):
        if intercept == QL_INTERCEPT.ENTER:
            if isinstance(target_syscall, int):
                self.os.dict_posix_onEnter_syscall_by_num[target_syscall] = intercept_function
            else:
                syscall_name = "ql_syscall_" + str(target_syscall)
                self.os.dict_posix_onEnter_syscall[syscall_name] = intercept_function

        elif intercept == QL_INTERCEPT.EXIT:
            if self.ostype in (QL_OS_POSIX):
                if isinstance(target_syscall, int):
                    self.os.dict_posix_onExit_syscall_by_num[target_syscall] = intercept_function
                else:
                    syscall_name = "ql_syscall_" + str(target_syscall)
                    self.os.dict_posix_onExit_syscall[syscall_name] = intercept_function                    

        else:
            if self.ostype in (QL_OS_POSIX):
                if isinstance(target_syscall, int):
                    self.os.dict_posix_syscall_by_num[target_syscall] = intercept_function
                else:
                    syscall_name = "ql_syscall_" + str(target_syscall)
                    self.os.dict_posix_syscall[syscall_name] = intercept_function
            
            elif self.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
                self.set_api(target_syscall, intercept_function)
        

    # replace default API with customed function
    def set_api(self, api_name, intercept_function, intercept = None):
        if self.ostype == QL_OS.UEFI:
            api_name = "hook_" + str(api_name)

        if intercept == QL_INTERCEPT.ENTER:
            if self.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
                self.os.user_defined_api_onenter[api_name] = intercept_function
            else:
                self.os.add_function_hook(api_name, intercept_function, intercept) 

        elif intercept == QL_INTERCEPT.EXIT:
            if self.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
                self.os.user_defined_api_onexit[api_name] = intercept_function  
            else:
                self.os.add_function_hook(api_name, intercept_function, intercept)           

        else:
            if self.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
                self.os.user_defined_api[api_name] = intercept_function
            else:
                self.os.add_function_hook(api_name, intercept_function)  

    # Map "ql_path" to any objects which implements QlFsMappedObject.
    def add_fs_mapper(self, ql_path, real_dest):
        self.os.fs_mapper.add_fs_mapping(ql_path, real_dest)

    # push to stack bottom, and update stack register
    def stack_push(self, data):
        return self.arch.stack_push(data)

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
        return self.arch.stack_write(offset, data)

    # Assembler/Diassembler API
    @property
    def assembler(self):
        return self.create_assembler()

    @property
    def disassember(self):
        return self.create_disassembler()
    
    def create_disassembler(self):
        if self.archtype in (QL_ARCH.ARM, QL_ARCH.ARM64, QL_ARCH.ARM_THUMB):
            reg_cpsr = self.reg.cpsr
        else:
            reg_cpsr = None
        return ql_create_disassembler(self.archtype, self.archendian, reg_cpsr)
    
    def create_assembler(self):
        if self.archtype in (QL_ARCH.ARM, QL_ARCH.ARM64, QL_ARCH.ARM_THUMB):
            reg_cpsr = self.reg.cpsr
        else:
            reg_cpsr = None
        return ql_create_assembler(self.archtype, self.archendian, reg_cpsr)

    # stop emulation
    def emu_stop(self):
        self.uc.emu_stop()

    # start emulation
    def emu_start(self, begin, end, timeout=0, count=0):
        self.uc.emu_start(begin, end, timeout, count)
        
        if self._internal_exception != None:
            raise self._internal_exception
