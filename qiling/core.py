#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from configparser import ConfigParser
import ntpath, os, pickle, platform

# See https://stackoverflow.com/questions/39740632/python-type-hinting-without-cyclic-imports
from typing import Dict, List, Union
from typing import TYPE_CHECKING

from unicorn.unicorn import Uc
if TYPE_CHECKING:
    from .arch.register import QlRegisterManager
    from .arch.arch import QlArch
    from .os.os import QlOs
    from .os.memory import QlMemoryManager
    from .loader.loader import QlLoader

from .const import QL_ARCH_ENDIAN, QL_ENDIAN, QL_OS, QL_VERBOSE, QL_ARCH_NONEOS, QL_ARCH_HARDWARE
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
            code=None,
            shellcoder=None,
            ostype=None,
            archtype=None,
            bigendian=False,
            verbose=QL_VERBOSE.DEFAULT,
            profile=None,
            console=True,
            log_file=None,
            log_override=None,
            log_plain=False,
            libcache = False,
            multithread = False,
            filter = None,
            stop_on_stackpointer = False,
            stop_on_exit_trap = False,
            stdin=None,
            stdout=None,
            stderr=None,
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
        self._code = code
        self._shellcoder = shellcoder
        self._ostype = ostype
        self._archtype = archtype
        self._archendian = None
        self._archbit = None
        self._pointersize = None
        self._profile = profile
        self._console = console
        self._log_file = log_file
        self._multithread = multithread
        self._log_file_fd = None
        self._log_filter = None
        self._log_override = log_override
        self._log_plain = log_plain
        self._filter = filter
        self._platform = ostype_convert(platform.system().lower())
        self._internal_exception = None
        self._uc = None
        self._stop_options = QlStopOptions(stackpointer=stop_on_stackpointer, exit_trap=stop_on_exit_trap)

        ##################################
        # Definition after ql=Qiling()   #
        ##################################
        self._verbose = verbose
        self._libcache = libcache
        self._patch_bin = []
        self._patch_lib = []
        self._debug_stop = False
        self._debugger = None
        self._root = False

        ###############################
        # Properties configured later #
        ###############################
        self.entry_point = None
        self.exit_point = None
        self.timeout = None
        self.count = None
        self._initial_sp = None


        """
        Qiling Framework Core Engine
        """
        ##############
        # Shellcode? #
        ##############

        # for Legacy
        if self._shellcoder:
            self._code = self._shellcoder

        if self._code or (self._archtype and type(self._archtype) == str):
            if (self._archtype and type(self._archtype) == str):
                self._archtype= arch_convert(self._archtype.lower())

            if (self._ostype and type(self._ostype) == str):
                self._ostype = ostype_convert(self._ostype.lower())

            if self._archtype in QL_ARCH_NONEOS or self._ostype == None:
                if self._ostype == None:
                    self._ostype = arch_os_convert(self._archtype)
                if self._code == None:
                    self._code = self._archtype


            if self._argv is None:
                self._argv = ["qilingcode"]
            if self._rootfs is None:
                self._rootfs = "."

        # file check
        if self._code is None:
            if not os.path.exists(str(self._argv[0])):
                raise QlErrorFileNotFound("Target binary not found: %s" %(self._argv[0]))
            if not os.path.exists(self._rootfs):
                raise QlErrorFileNotFound("Target rootfs not found")

        self._path = (str(self._argv[0]))
        self._targetname = ntpath.basename(self._argv[0])

        ##########
        # Loader #
        ##########
        if self._code is None:
            guessed_archtype, guessed_ostype, guessed_archendian = ql_guess_emu_env(self._path)
            if self._ostype is None:
                self._ostype = guessed_ostype
            if self._archtype is None:
                self._archtype = guessed_archtype
            if self.archendian is None:
                self._archendian = guessed_archendian

            if not ql_is_valid_ostype(self._ostype):
                raise QlErrorOsType("Invalid OSType")

            if not ql_is_valid_arch(self._archtype):
                raise QlErrorArch("Invalid Arch %s" % self._archtype)

        self._loader = loader_setup(self._ostype, self)

        #####################
        # Profile & Logging #
        #####################
        self._profile, debugmsg = profile_setup(self.ostype, self.profile, self)

        # Log's configuration

        self._log_file_fd, self._log_filter = ql_setup_logger(self,
                                                              self._log_file,
                                                              self._console,
                                                              self._filter,
                                                              self._log_override,
                                                              self._log_plain)

        self.log.setLevel(ql_resolve_logger_level(self._verbose))

        # Now that the logger is configured, we can log profile debug msg:
        self.log.debug(debugmsg)

        ########################
        # Archbit & Endianness #
        ########################
        self._archbit = ql_get_arch_bits(self._archtype)
        self._pointersize = (self.archbit // 8)  

        # Endian for shellcode needs to set manually
        if self._code:
            self._archendian = QL_ENDIAN.EL
            if bigendian == True and self._archtype in (QL_ARCH_ENDIAN):
                self._archendian = QL_ENDIAN.EB

        # Once we finish setting up archendian and arcbit, we can init QlCoreStructs.
        QlCoreStructs.__init__(self, self._archendian, self._archbit)

        ##############
        # Components #
        ##############

        if self.archtype not in QL_ARCH_NONEOS:
            self._mem = component_setup("os", "memory", self)
            self._reg = component_setup("arch", "register", self)
        
        if self.archtype in QL_ARCH_HARDWARE:   
            self._hw  = component_setup("hw", "hw", self)

        self._arch = arch_setup(self.archtype, self)
        
        # Once we finish setting up arch layer, we can init QlCoreHooks.
        self.uc = self.arch.init_uc
        QlCoreHooks.__init__(self, self.uc)
        
        # Setup Outpt
        if self.archtype not in QL_ARCH_NONEOS:
            self.arch.utils.setup_output()

        if (self.archtype not in QL_ARCH_NONEOS):
            if (self.archtype not in QL_ARCH_HARDWARE):
                self._os = os_setup(self.archtype, self.ostype, self)

                if stdin is not None:
                    self._os.stdin = stdin

                if stdout is not None:
                    self._os.stdout = stdout

                if stderr is not None:
                    self._os.stderr = stderr

        # Run the loader
        self.loader.run()

        if (self.archtype not in QL_ARCH_NONEOS):
            if (self.archtype not in QL_ARCH_HARDWARE):
                # Add extra guard options when configured to do so
                self._init_stop_guard()    

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
    def hw(self) -> "QlHwManager":
        """ Qiling hardware manager.

            Example: 
        """
        return self._hw


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

            Also see qiling/os/<os>/<os>.py
        """
        return self._os

    @property
    def log(self) -> logging.Logger:
        """ Returns the logger this Qiling instance uses.

            You can override this log by passing `log_override=your_log` to Qiling.__init__

            Type: logging.Logger
            Example: ql.log.info("This goes to terminal")
        """
        return self._log_file_fd

    ##################
    # Qiling Options #
    ##################

    # If an option doesn't have a setter, it means that it can be only set during Qiling.__init__

    @property
    def console(self) -> bool:
        """ Specify whether enabling console output. 

            Type: bool
            Example: Qiling(console=True)
        """
        return self._console

    @property
    def log_file(self) -> str:
        """ Log to a file.

            Type: str
            Example: Qiling(log_file="./ql.log")
        """
        return self._log_file

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
    def ostype(self) -> QL_OS:
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
            Example: Qiling(code=b"\x90", ostype="macos", archtype="x8664", bigendian=False)
        """
        return self._ostype

    @property
    def archtype(self) -> QL_ARCH:
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
            Example: Qiling(code=b"\x90", ostype="macos", archtype="x8664", bigendian=False)
        """
        return self._archtype

    @property
    def archendian(self) -> QL_ENDIAN:
        """ The architecure endian.

            Note: Please pass "bigendian=True" or "bingendian=False" to set this property.
                  This option only takes effect for shellcode.

            Type: int
            Example: Qiling(code=b"\x90", ostype="macos", archtype="x8664", bigendian=False)
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
    def code(self) -> bytes:
        """ The shellcode to execute.

            Note: It can't be used with "argv" parameter.

            Type: bytes
            Example: Qiling(code=b"\x90", ostype="macos", archtype="x8664", bigendian=False)
        """
        return self._code

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
    def libcache(self) -> bool:
        """ Whether cache dll files. Only take effect in Windows emulation.

            Type: bool
            Example: - ql = Qiling(libcache=False)
                     - ql.libcache = True
        """
        return self._libcache

    @libcache.setter
    def libcache(self, lc):
        self._libcache = lc

    @property
    def verbose(self):
        """ Set the verbose level.

            Type: int
            Values:
              - 0  : logging.WARNING, almost no additional logs except the program output.
              - >=1: logging.INFO, the default logging level.
              - >=4: logging.DEBUG.
              - >=10: Disasm each executed instruction.
              - >=20: The most verbose output, dump registers and disasm the function blocks.
            Example: - ql = Qiling(verbose=5)
                     - ql.verbose = 0
        """
        return self._verbose

    @verbose.setter
    def verbose(self, v):
        self._verbose = v
        self.log.setLevel(ql_resolve_logger_level(self._verbose))
        if self.archtype not in QL_ARCH_NONEOS:
            self.arch.utils.setup_output()

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
    def filter(self) -> str:
        """ Filter logs with regex.
            Type: str
            Example: - Qiling(filter=r'^exit')
                     - ql.filter = r'^open'
        """
        return self._filter

    @filter.setter
    def filter(self, ft):
        self._filter = ft
        if self._log_filter is None:
            self._log_filter = RegexFilter(ft)
            self.log.addFilter(self._log_filter)
        else:
            self._log_filter.update_filter(ft)

    @property
    def uc(self) -> Uc:
        """ Raw uc instance.

            Type: Uc
        """
        return self._uc

    @uc.setter
    def uc(self, u):
        self._uc = u

    @property
    def stop_options(self) -> "QlStopOptions":
        """ The stop options configured:
            - stackpointer: Stop execution on a negative stackpointer
            - exit_trap: Stop execution when the ip enters a guarded region
            - any: Is any of the options enabled?

        Returns:
            QlStopOptions: What stop options are configured
        """
        return self._stop_options

    def __enable_bin_patch(self):
        for addr, code in self.patch_bin:
            self.mem.write(self.loader.load_address + addr, code)


    def enable_lib_patch(self):
        for addr, code, filename in self.patch_lib:
            try:
                self.mem.write(self.mem.get_lib_base(filename) + addr, code)
            except:
                raise RuntimeError("Fail to patch %s at address 0x%x" % (filename, addr))

    def _init_stop_guard(self):
        if not self.stop_options.any:
            return

        # Allocate a guard page, we need this in both cases
        # On a negative stack pointer, we still need a return address (otherwise we end up at 0)
        # Make sure it is not close to the heap (PE), otherwise the heap cannot grow
        self._exit_trap_addr = self.mem.find_free_space(0x1000, minaddr=0x9000000, align=0x10)
        self.mem.map(self._exit_trap_addr, 0x1000, info='[Stop guard]')

        # Stop on a negative stack pointer
        if self.stop_options.stackpointer:
            def _check_sp(ql, address, size):
                if not ql.loader.skip_exit_check:
                    sp = ql._initial_sp - ql.reg.arch_sp
                    if sp < 0:
                        self.log.info('Process returned from entrypoint (stackpointer)!')
                        ql.emu_stop()

            self.hook_code(_check_sp)

        # Stop when running to exit trap address
        if self.stop_options.exit_trap:
            def _exit_trap(ql):
                self.log.info('Process returned from entrypoint (exit_trap)!')
                ql.emu_stop()

            self.hook_address(_exit_trap, self._exit_trap_addr)

    def write_exit_trap(self):
        self._initial_sp = self.reg.arch_sp
        if self.stop_options.any:
            if not self.loader.skip_exit_check:
                self.log.debug(f'Setting up exit trap at 0x{hex(self._exit_trap_addr)}')
                self.stack_write(0, self._exit_trap_addr)
            elif self.stop_options.exit_trap:
                self.log.debug(f'Loader {self.loader} requested to skip exit_trap!')


    ###############
    # Qiling APIS #
    ###############

    # Emulate the binary from begin until @end, with timeout in @timeout and
    # number of emulated instructions in @count
    def run(self, begin=None, end=None, timeout=0, count=0, code = None):
        # replace the original entry point, exit point, timeout and count
        self.entry_point = begin
        self.exit_point = end
        self.timeout = timeout
        self.count = count

        if self.archtype in QL_ARCH_NONEOS:
            if code == None:
                return self.arch.run(self._code)
            else:
                return self.arch.run(code) 

        if self.archtype in QL_ARCH_HARDWARE:
            return self.arch.run(count=count)

        self.write_exit_trap()

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

        if "mem" in saved_states:
            self.mem.restore(saved_states["mem"])

        if "cpu_context" in saved_states:
            self.arch.context_restore(saved_states["cpu_context"])

        if "reg" in saved_states:
            self.reg.restore(saved_states["reg"])

        if "fd" in saved_states:
            self.os.fd.restore(saved_states["fd"])

        if "os_context" in saved_states:
            self.os.restore(saved_states["os_context"])

        if "loader" in saved_states:
            self.loader.restore(saved_states["loader"])


    # Either hook or replace syscall/api with custom api/syscall
    #  - if intercept is None, replace syscall with custom function
    #  - if intercept is ENTER/EXIT, hook syscall at enter/exit with custom function
    # If replace function name is needed, first syscall must be available
    # - ql.set_syscall(0x04, my_syscall_write)
    # - ql.set_syscall("write", my_syscall_write)
    # TODO: Add correspoinding API in ql.os!
    def set_syscall(self, target_syscall, intercept_function, intercept = None):
        self.os.set_syscall(target_syscall, intercept_function, intercept)


    # Either replace or hook API
    #  - if intercept is None, replace API with custom function
    #  - if intercept is ENTER/EXIT, hook API at enter/exit with custom function
    def set_api(self, api_name, intercept_function, intercept = None):
        self.os.set_api(api_name, intercept_function, intercept)
 

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
    def disassembler(self):
        return self.create_disassembler()


    def create_disassembler(self):
        return self.arch.create_disassembler()


    def create_assembler(self):
        return self.arch.create_assembler()

    # stop emulation
    def emu_stop(self):
        self.uc.emu_stop()
    
    # stop emulation
    def stop(self):
        if self.multithread:
            self.os.thread_management.stop() 
        else:
            self.uc.emu_stop()            

    # start emulation
    def emu_start(self, begin, end, timeout=0, count=0):
        self.uc.emu_start(begin, end, timeout, count)

        if self._internal_exception != None:
            raise self._internal_exception