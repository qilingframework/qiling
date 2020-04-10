#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, struct, platform, ntpath
import os as pyos
from unicorn import *

from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.exception import *
from qiling.utils import *
from qiling.os.utils import *
from qiling.arch.utils import *
from qiling.os.thread import *
from qiling.debugger.utils import *
from qiling.os.memory import QlMemoryManager


__version__ = "0.9"


def catch_KeyboardInterrupt(ql):
    def decorator(func):
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except BaseException as e:
                #ql.dprint(0, "Received a request from the user to stop!")
                ql.stop(stop_event=THREAD_EVENT_UNEXECPT_EVENT)
                ql.internal_exception = e
        return wrapper
    return decorator


class Qiling:
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
            verbose=0,
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

        # Define after ql=Qiling(), either defined by Qiling Framework or user defined
        self.archbit = ''
        self.path = ''
        self.entry_point = 0
        self.new_stack = 0
        self.brk_address = 0
        self.shellcode_init = 0
        self.file_des = []
        self.stdin = ql_file('stdin', sys.stdin.fileno())
        self.stdout = ql_file('stdout', sys.stdout.fileno())
        self.stderr = ql_file('stderr', sys.stderr.fileno())
        self.sigaction_act = []
        self.child_processes = False
        self.patch_bin = []
        self.patch_lib = []
        self.patched_lib = []
        self.loadbase = 0
        self.timeout = 0
        self.until_addr = 0
        self.byte = 0
        self.currentpath = pyos.getcwd()
        self.log_file_fd = None
        self.current_path = '/'
        self.fs_mapper = []
        self.exit_code = 0
        self.debug_stop = False
        self.internal_exception = None
        self.platform = platform.system()
        self.global_thread_id = 0
        self.debugger = None
        self.automatize_input = False
        self.profile = None 
        # due to the instablity of multithreading, added a swtich for multithreading. at least for MIPS32EL for now
        self.multithread = False
        self.thread_management = None    
        # To use IPv6 or not, to avoid binary double bind. ipv6 and ipv4 bind the same port at the same time
        self.ipv6 = False        
        # Bind to localhost
        self.bindtolocalhost = False
        # by turning this on, you must run your analysis with sudo
        self.root = True
        self.log_split = False
        self.shellcode_init = 0
        self.entry_point = 0
        # syscall filter for strace-like functionality
        self.strace_filter = None
        # generic append function
        self.append = append

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

            elif not pyos.path.exists(str(self.filename[0])) or not pyos.path.exists(self.rootfs):
                raise QlErrorFileNotFound("[!] Target binary or rootfs not found")

        if self.shellcoder:
            self.targetname = "qilingshellcode"
        else:    
            self.targetname = ntpath.basename(self.filename[0])
        
        self.cur_pathname = pyos.path.abspath(os.getcwd())

        # Looger's configuration
        _logger = ql_setup_logging_stream(self)

        if self.log_dir is not None and type(self.log_dir) == str:
            self.log_dir = pyos.path.join(self.cur_pathname, self.log_dir)   
            
            if not pyos.path.exists(self.log_dir):
                pyos.makedirs(self.log_dir, 0o755)

            pid = pyos.getpid()

            if self.append:
                self.log_filename = self.targetname + "_" + self.append          
            else:
                self.log_filename = self.targetname
            
            self.log_file = pyos.path.join(self.log_dir, self.log_filename)    
            _logger = ql_setup_logging_file(self.output, self.log_file + "_" + str(pid), _logger)
        
        self.log_file_fd = _logger
            
        # OS dependent configuration for stdio
        if self.ostype in (QL_LINUX, QL_FREEBSD, QL_MACOS):
            if stdin != 0:
                self.stdin = stdin

            if stdout != 0:
                self.stdout = stdout

            if stderr != 0:
                self.stderr = stderr

            self.file_des = [0] * 256
            self.file_des[0] = self.stdin
            self.file_des[1] = self.stdout
            self.file_des[2] = self.stderr

            for _ in range(256):
                self.sigaction_act.append(0)



        # double check supported architecture
        if not ql_is_valid_arch(self.archtype):
            raise QlErrorArch("[!] Invalid Arch")

        # chceck for supported OS type    
        if self.ostype not in QL_OS:
            raise QlErrorOsType("[!] OSTYPE required: either 'linux', 'windows', 'freebsd', 'macos'")
        
        # qiling output method conversion
        if self.output and type(self.output) == str:
            self.output = self.output.lower()
            if self.output not in QL_OUTPUT:
                raise QlErrorOutput("[!] OUTPUT required: either 'default', 'off', 'disasm', 'debug', 'dump'")

        # check verbose, only can check after ouput being defined
        if type(self.verbose) != int or self.verbose > 99 and (self.verbose > 0 and self.output not in (QL_OUT_DEBUG, QL_OUT_DUMP)):
            raise QlErrorOutput("[!] verbose required input as int and less than 99")

        """
        Define file is 32 or 64bit and check file endian
        QL_ENDIAN_EL = Little Endian || QL_ENDIAN_EB = Big Endian
        QL_ENDIAN_EB is define during ql_elf_check_archtype()
        """
        self.archbit = ql_get_arch_bits(self.archtype)
        if self.archtype not in (QL_ENDINABLE):
            self.archendian = QL_ENDIAN_EL
        
        """
        Endian for shellcode needs to set manually
        """
        if self.shellcoder and self.bigendian == True and self.archtype in (QL_ENDINABLE):
            self.archendian = QL_ENDIAN_EB
        elif self.shellcoder:
            self.archendian = QL_ENDIAN_EL

        # based on CPU bit and set pointer size
        if self.archbit:
            self.pointersize = (self.archbit // 8)            



        """
        Load memory module
        FIXME: We need to refactor this
        """
        if self.archbit == 64:
            max_addr = 0xFFFFFFFFFFFFFFFF
        elif self.archbit == 32:
            max_addr = 0xFFFFFFFF
        try:
            self.mem = QlMemoryManager(self, max_addr)
        except:
            raise QlErrorArch("[!] Cannot load Memory Management module")    


        """
        Load architecture's and os module
        ql.pc, ql.sp and etc
        """

        self.arch = ql_arch_setup(self)
        self.os = ql_os_setup(self)

    def run(self):
        # setup strace filter for logger
        if self.strace_filter != None and self.output == QL_OUT_DEFAULT:

            self.log_file_fd.addFilter(Strace_filter(self.strace_filter))

        # debugger init
        if self.debugger is not None:
            try:
                remotedebugsrv, ip, port = '', '', ''
                remotedebugsrv, ip, port = self.debugger.split(':')
            except:
                ip, port = '', ''
                ip, port = self.debugger.split(':')
                # If only ip:port is defined, remotedebugsrv is always gdb
                remotedebugsrv = "gdb"
     
            remotedebugsrv = debugger_convert(remotedebugsrv)

            if remotedebugsrv not in (QL_DEBUGGER):
                raise QlErrorOutput("[!] Error: Debugger not supported\n")       
            else:
                try:
                    if self.debugger is True:
                        ql_debugger(self, remotedebugsrv)
                    else:
                        ql_debugger(self, remotedebugsrv, ip, port)
                
                except KeyboardInterrupt:
                    if self.remotedebugsession():
                        self.remotedebugsession.close()
                    raise QlErrorOutput("[!] Remote debugging session ended\n")

        # patch binary
        self.__enable_bin_patch()

        # run the binary
        self.os.run()     

        # resume with debugger
        if self.debugger is not None:
            self.remotedebugsession.run()

    # normal print out
    def nprint(self, *args, **kw):
        if self.thread_management is not None and self.thread_management.cur_thread is not None:
            fd = self.thread_management.cur_thread.log_file_fd
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

    # debug print out, always use with verbose level with dprint(0,"helloworld")
    def dprint(self, level, *args, **kw):
        try:
            self.verbose = int(self.verbose)
        except:
            raise QlErrorOutput("[!] Verbose muse be int")    
        
        if type(self.verbose) != int or self.verbose > 99 or (self.verbose > 0 and self.output not in (QL_OUT_DEBUG, QL_OUT_DUMP)):
            raise QlErrorOutput("[!] Verbose > 1 must use with QL_OUT_DEBUG or else ql.verbose must be 0")

        if self.output == QL_OUT_DUMP:
                self.verbose = 99

        if int(self.verbose) >= level and self.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                self.nprint(*args, **kw)


    def addr_to_str(self, addr, short=False, endian="big"):
        return ql_addr_to_str(self, addr, short, endian)


    def asm2bytes(self, runasm, arm_thumb=None):
        return ql_asm2bytes(self, self.archtype, runasm, arm_thumb)
    

    """
    replace linux or windows syscall/api with custom api/syscall
    if replace function name is needed, first syscall must be available
    - ql.set_syscall(0x04, my_syscall_write)
    - ql.set_syscall("write", my_syscall_write)
    """
    def set_syscall(self, syscall_cur, syscall_new):
        if self.ostype in (QL_POSIX):
            if isinstance(syscall_cur, int):
                self.os.dict_posix_syscall_by_num[syscall_cur] = syscall_new
            else:
                syscall_name = "ql_syscall_" + str(syscall_cur)
                self.os.dict_posix_syscall[syscall_name] = syscall_new
        elif self.ostype == QL_WINDOWS:
            self.set_api(syscall_cur, syscall_new)


    # replace Windows API with custom syscall
    def set_api(self, syscall_cur, syscall_new):
        if self.ostype == QL_WINDOWS:
            self.os.user_defined_api[syscall_cur] = syscall_new
        elif self.ostype in (QL_POSIX):
            self.set_syscall(syscall_cur, syscall_new)


    def hook_code(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, addr, size, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_CODE, _callback, (user_data, callback), begin, end)


    def hook_intr(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, intno, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, intno, user_data)
            else:
                # callback does not require user_data
                callback(self, intno)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_INTR, _callback, (user_data, callback), begin, end)


    def hook_block(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, addr, size, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_BLOCK, _callback, (user_data, callback), begin, end)

    def hook_mem_unmapped(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, access, addr, size, value, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, value, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size, value)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, _callback, (user_data, callback), begin, end)

    def hook_mem_read_invalid(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, access, addr, size, value, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, value, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size, value)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_MEM_READ_INVALID, _callback, (user_data, callback), begin, end)

    def hook_mem_write_invalid(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, access, addr, size, value, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, value, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size, value)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_MEM_WRITE_INVALID, _callback, (user_data, callback), begin, end)

    def hook_mem_fetch_invalid(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, access, addr, size, value, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, value, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size, value)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_MEM_FETCH_INVALID, _callback, (user_data, callback), begin, end)

    def hook_mem_invalid(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, access, addr, size, value, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, value, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size, value)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_MEM_VALID, _callback, (user_data, callback), begin, end)

    # a convenient API to set callback for a single address
    def hook_address(self, callback, address, user_data=None):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, _addr, _size, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, user_data)
            else:
                # callback does not require user_data
                callback(self)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_CODE, _callback, (user_data, callback), address, address)

    def hook_mem_read(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, access, addr, size, value, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, value, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size, value)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_MEM_READ, _callback, (user_data, callback), begin, end)

    def hook_mem_write(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, access, addr, size, value, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, value, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size, value)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_MEM_WRITE, _callback, (user_data, callback), begin, end)

    def hook_mem_fetch(self, callback, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback(uc, access, addr, size, value, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, addr, size, value, user_data)
            else:
                # callback does not require user_data
                callback(self, addr, size, value)

        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_MEM_FETCH, _callback, (user_data, callback), begin, end)

    def hook_insn(self, callback, arg1, user_data=None, begin=1, end=0):
        @catch_KeyboardInterrupt(self)
        def _callback_x86_syscall(uc, pack_data):
            # unpack what we packed for hook_add()
            user_data, callback = pack_data
            if user_data:
                callback(self, user_data)
            else:
                # callback does not require user_data
                callback(self)

        if arg1 == UC_X86_INS_SYSCALL:
            # pack user_data & callback for wrapper _callback
            self.uc.hook_add(UC_HOOK_INSN, _callback_x86_syscall, (user_data, callback), begin, end, arg1)
        else:
            self.uc.hook_add(UC_HOOK_INSN, callback, user_data, begin, end, arg1)

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

    def unpack64(self, x):
        return struct.unpack('Q', x)[0]

    def pack64(self, x):
        return struct.pack('Q', x)

    def unpack64s(self, x):
        return struct.unpack('q', x)[0]

    def unpack32(self, x):
        if self.archendian == QL_ENDIAN_EB:
            return struct.unpack('>I', x)[0]
        else:
            return struct.unpack('I', x)[0]

    def pack32(self, x):
        if self.archendian == QL_ENDIAN_EB:
            return struct.pack('>I', x)
        else:
            return struct.pack('I', x)

    def unpack32s(self, x):
        if self.archendian == QL_ENDIAN_EB:
            return struct.unpack('>i', x)[0]
        else:
            return struct.unpack('i', x)[0]

    def unpack32s_ne(self, x):
        return struct.unpack('i', x)[0]

    def pack32s(self, x):
        if self.archendian == QL_ENDIAN_EB:
            return struct.pack('>i', x)
        else:
            return struct.pack('i', x)

    def unpack16(self, x):
        if self.archendian == QL_ENDIAN_EB:
            return struct.unpack('>H', x)[0]
        else:
            return struct.unpack('H', x)[0]

    def pack16(self, x):
        if self.archendian == QL_ENDIAN_EB:
            return struct.pack('>H', x)
        else:
            return struct.pack('H', x)

    def pack(self, data):
        if self.archbit == 64:
            return self.pack64(data)
        elif self.archbit == 32:
            return self.pack32(data)
        else:
            raise

    def unpack(self, data):
        if self.archbit == 64:
            return self.unpack64(data)
        elif self.archbit == 32:
            return self.unpack32(data)
        else:
            raise

    def unpacks(self, data):
        if self.archbit == 64:
            return self.unpack64s(data)
        elif self.archbit == 32:
            return self.unpack32s(data)
        else:
            raise


    # patch @code to memory address @addr
    def patch(self, addr, code, file_name=b''):
        if file_name == b'':
            self.patch_bin.append((addr, code))
        else:
            self.patch_lib.append((addr, code, file_name.decode()))
    

    # ql.register - read and write register 
    def register(self, register_str, value= None):
        if value is None:
            return self.arch.get_register(register_str)
        else:    
            return self.arch.set_register(register_str, value)

    # ql.reg_pc - PC register name getter
    @property
    def reg_pc(self):
        return self.arch.get_reg_pc()

    # ql.reg_sp - SP register name getter
    @property
    def reg_sp(self):
        return self.arch.get_reg_sp()

    # ql.reg_tables - Register table getter
    @property
    def reg_table(self):
        return self.arch.get_reg_table()

    # ql.reg_name - Register name converter getter
    @property
    def reg_name(self):
        return self.arch.get_reg_name_str(self.uc_reg_name)

    # ql.reg_name - Register name converter setter
    @reg_name.setter
    def reg_name(self, uc_reg):
        self.uc_reg_name = uc_reg

    # ql.pc - PC register value getter
    @property
    def pc(self):
        return self.arch.get_pc()

    # ql.pc - PC register value setter
    @pc.setter
    def pc(self, value):
        self.arch.set_pc(value)

    # ql.sp - SP register value getter
    @property
    def sp(self):
        return self.arch.get_sp()

    # ql.sp - SP register value setter
    @sp.setter
    def sp(self, value):
        self.arch.set_sp(value)

    # ql.output var getter
    @property
    def output(self):
        return self._output

    # ql.output - output var setter eg. QL_OUT_DEFAULT and etc
    @output.setter
    def output(self, output):
        self._output = output_convert(output)
    
    # ql.platform - platform var = host os getter eg. QL_LINUX and etc
    @property
    def platform(self):
        return self._platform

    # ql.platform - platform var = host os setter eg. QL_LINUX and etc
    @platform.setter
    def platform(self, value):
        if value == 'Linux':
            self._platform = QL_LINUX
        elif value == 'Darwin':
            self._platform = QL_MACOS
        elif value == 'Windows':
            self._platform = QL_WINDOWS
        elif value == 'FreeBSD':
            self._platform = QL_FREEBSD
        else:
            self._platform = None

    def __enable_bin_patch(self):
        for addr, code in self.patch_bin:
            self.mem.write(self.loadbase + addr, code)

    def enable_lib_patch(self):
        for addr, code, filename in self.patch_lib:
            self.mem.write(self.mem.get_lib_base(filename) + addr, code)

    def set_timeout(self, microseconds):
        self.timeout = microseconds

    def set_exit(self, until_addr):
        self.until_addr = until_addr

    def add_fs_mapper(self, fm, to):
        self.fs_mapper.append([fm, to])

    def stop(self, stop_event=THREAD_EVENT_EXIT_GROUP_EVENT):
        if self.thread_management != None:
            td = self.thread_management.cur_thread
            td.stop()
            td.stop_event = stop_event
        self.uc.emu_stop()
