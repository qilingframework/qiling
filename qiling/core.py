#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, struct, os, platform, importlib
from unicorn import *

from qiling.arch.filetype import *
from qiling.os.posix.filestruct import *
from qiling.exception import *
from qiling.utils import *
from qiling.os.utils import *
from qiling.arch.utils import *
from qiling.os.linux.thread import *

__version__ = "0.9"

def catch_KeyboardInterrupt(ql):
    def decorator(func):
        def wrapper(*args, **kw):
            try:
                return func(*args, **kw)
            except BaseException as e:
                # ql.nprint("Received a request from the user to stop!")
                if ql.thread_management != None:
                    td = ql.thread_management.cur_thread
                    td.stop()
                    td.stop_event = THREAD_EVENT_UNEXECPT_EVENT
                ql.uc.emu_stop()
                ql.internal_exception = e
        return wrapper
    return decorator

class Qiling:
    arch                = ''
    archbit             = ''
    uc                  = ''
    path                = ''
    entry_point         = 0
    elf_entry           = 0
    new_stack           = 0
    brk_address         = 0
    shellcode_init      = 0
    file_des            = []
    stdin               = ql_file('stdin', sys.stdin.fileno())
    stdout              = ql_file('stdout', sys.stdout.fileno())
    stderr              = ql_file('stderr', sys.stderr.fileno())
    sigaction_act       = []
    child_processes     = False
    patch_bin           = []
    patch_lib           = []
    patched_lib         = []
    loadbase            = 0
    map_info            = []
    timeout             = 0
    until_addr          = 0
    byte                = 0
    thread_management   = None
    root                = True
    port                = 0
    currentpath         = os.getcwd()
    log_file_fd         = None
    log_file_name       = None
    current_path        = '/'
    fs_mapper           = []
    reg_dir             = None
    reg_diff            = None
    exit_code           = 0
    debug_stop          = False
    internal_exception  = None


    def __init__(
                    self, 
                    filename        = None, 
                    rootfs          = None, 
                    argv            = [], 
                    env             = {}, 
                    shellcoder      = None, 
                    ostype          = None, 
                    archtype        = None, 
                    libcache        = False,
                    stdin           = 0, 
                    stdout          = 0, 
                    stderr          = 0,
                    output          = None, 
                    log_console     = True,                     
                    log_file        = None, 
                    log_split       = False, 
                    mmap_start      = 0, 
                    stack_address   = 0, 
                    stack_size      = 0,
                    interp_base     = 0
                ):

        self.output                 = output
        self.ostype                 = ostype
        self.archtype               = archtype
        self.shellcoder             = shellcoder
        self.filename               = filename
        self.rootfs                 = rootfs
        self.argv                   = argv
        self.env                    = env
        self.libcache               = libcache
        self.log_console            = log_console
        self.log_file               = log_file
        self.log_split              = log_split
        self.platform               = platform.system()
        self.mmap_start             = mmap_start
        self.stack_address          = stack_address
        self.stack_size             = stack_size
        self.interp_base            = interp_base
        self.dict_posix_syscall     = dict()
        self.user_defined_winapi    = {}

        if self.log_file != None and type(self.log_file) == str:
            if self.log_file[0] != '/':
                self.log_file = os.getcwd() + '/' + self.log_file
            self.log_file_name = self.log_file
            if type(self.log_split) != bool or not self.log_split:
                self.log_file_fd = open(log_file + ".qlog", 'w+')
            else:
                #self.log_split = log_split
                self.log_file_fd = open(log_file + "_" + str(os.getpid()) + ".qlog", 'w+')

        if self.ostype and type(self.ostype) == str:
            self.ostype = self.ostype.lower()
            self.ostype = ostype_convert(self.ostype)
 
        if self.shellcode and self.archtype and type(self.archtype) == str:
            self.arch = self.arch.lower()
            self.arch = arch_convert(self.archtype)
           
        if self.rootfs and self.shellcoder == None:
            if (os.path.exists(str(self.filename[0])) and os.path.exists(self.rootfs)):
                self.path = (str(self.filename[0]))
                if self.ostype == None or self.arch == None:
                    self.arch, self.ostype = ql_checkostype(self.path)
              
                self.argv = self.filename
      
            elif  (not os.path.exists(str(self.filename[0])) or not os.path.exists(self.rootfs)):       
                raise QlErrorFileNotFound("[!] Target binary or rootfs not found")

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

        if not ql_is_valid_arch(self.arch):
            raise QlErrorArch("[!] Invalid Arch")

        arch_func = ql_get_arch_module_function( self.arch, ql_arch_convert_str(self.arch).upper() )

        self.archbit = ql_get_arch_bits(self.arch)
        self.archfunc = arch_func(self) 

        if self.archbit:
            self.pointersize = (self.archbit // 8)

        if not self.ostype in (QL_OS):
            raise QlErrorOsType("[!] OSTYPE required: either 'linux', 'windows', 'freebsd', 'macos','ios'")
        
        if self.output and type(self.output) == str:
            self.output = self.output.lower()
            if not self.output in (QL_OUTPUT):
                raise QlErrorOutput("[!] OUTPUT required: either 'default', 'off', 'disasm', 'debug', 'dump'")
 
        if self.shellcoder and self.arch and self.ostype:
            self.shellcode()
        else:
            self.load_exec()  

    def build_os_execution(self, function_name):
        self.runtype = ql_get_os_module_function(self.ostype, self.arch, "runner")
        return ql_get_os_module_function(self.ostype, self.arch, function_name)


    def load_exec(self):
        loader_file = self.build_os_execution("loader_file")
        loader_file(self)

 
    def shellcode(self):
        self.__enable_bin_patch()
        loader_shellcode = self.build_os_execution("loader_shellcode")
        loader_shellcode(self)


    def run(self):
        self.__enable_bin_patch()
        runner = self.build_os_execution("runner")
        runner(self)


    def nprint(self, *args, **kw):
        if self.thread_management != None and self.thread_management.cur_thread != None:
            fd = self.thread_management.cur_thread.log_file_fd
        else:
            fd = self.log_file_fd

        if (self.log_console == False or self.output == QL_OUT_OFF):
            pass
        elif self.log_console == False and self.log_file_name:
            print(*args, **kw, file = fd)
        elif (self.log_file_name and self.log_console):
            print(*args, **kw, file = fd)
            print(*args, **kw)
        else:
            print(*args, **kw)
                          
        if fd != None:
            fd.flush()


    def dprint(self, *args, **kw):
        if self.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            self.nprint(*args, **kw)


    def asm2bytes(self, runasm, arm_thumb = None):
        return ql_asm2bytes(self,  self.arch, runasm, arm_thumb)


    def set_syscall(self, syscall_cur, syscall_new):
        if self.ostype in (QL_LINUX, QL_MACOS, QL_FREEBSD, QL_IOS):
            self.dict_posix_syscall[syscall_cur] = syscall_new
        elif self.ostype == QL_WINDOWS:
            self.set_winapi(syscall_cur, syscall_new)


    def set_winapi(self, winapi_name, winapi_func):
        if self.ostype == QL_WINDOWS:
            self.user_defined_winapi[winapi_name] = winapi_func


    def hook_code(self, callback, user_data = None, begin = 1, end = 0):
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


    def hook_intr(self, callback, user_data = None, begin = 1, end = 0):
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


    def hook_block(self, callback, user_data = None, begin = 1, end = 0):
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


    def hook_mem_unmapped(self, callback, user_data = None, begin = 1, end = 0):
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


    def hook_mem_read_invalid(self, callback, user_data = None, begin = 1, end = 0):
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


    def hook_mem_write_invalid(self, callback, user_data = None, begin = 1, end = 0):
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


    def hook_mem_fetch_invalid(self, callback, user_data = None, begin = 1, end = 0):
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


    def hook_mem_invalid(self, callback, user_data = None, begin = 1, end = 0):
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
    def hook_address(self, callback, address, user_data = None):
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

    def hook_insn(self, callback, arg1, user_data = None, begin = 1, end = 0):
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
        self.archfunc.stack_push(data)


    def stack_pop(self):
        return self.archfunc.stack_pop()


    def stack_read(self, value):
        return self.archfunc.stack_read(value)


    def stack_write(self,value, data):
        self.archfunc.stack_write(value, data)       


    def unpack64(self, x):
        return  struct.unpack('Q', x)[0]


    def pack64(self, x):
        return struct.pack('Q', x)
    

    def unpack64s(self, x):
        return struct.unpack('q', x)[0]


    def unpack32(self, x):
        return struct.unpack('I', x)[0]


    def pack32(self, x):
        return struct.pack('I', x)


    def unpack32s(self, x):
        return struct.unpack('i', x)[0]


    def pack32s(self, x):
        return struct.pack('i', x)


    def unpack16(self, x):
        return struct.unpack('H', x)[0]


    def pack16(self, x):
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
    def patch(self, addr, code, file_name = b''):
        if file_name == b'':
            self.patch_bin.append((addr, code))
        else:
            self.patch_lib.append((addr, code, file_name.decode()))


    # read @size of bytes from memory address @addr
    def mem_read(self, addr, size):
        return self.uc.mem_read(addr, size)


    # write @data to memory address @addr
    def mem_write(self, addr, data):
        return self.uc.mem_write(addr, data)


    # get PC register
    @property
    def pc(self):
        return self.archfunc.get_pc()


    # pc.setter: set PC register
    @pc.setter
    def pc(self, value):
        self.archfunc.set_pc(value)


    # get stack pointer register
    @property
    def sp(self):
        return self.archfunc.get_sp()


    # sp.setter: set stack pointer register
    @sp.setter
    def sp(self, value):
        self.archfunc.set_sp(value)


    @property
    def output(self):
        return self._output


    @output.setter
    def output(self, output):
        self._output = output_convert(output)


    @property
    def platform(self):
        return self._platform


    @platform.setter
    def platform(self, value):
        if value == 'Linux':
            self._platform = QL_LINUX
        elif value == 'Darwin':
            self._platform = QL_MACOS
        else:
            self._platform = None


    def __enable_bin_patch(self):
        for addr, code in self.patch_bin:
            self.uc.mem_write(self.loadbase + addr, code)


    def enable_lib_patch(self):
        for addr, code, filename in self.patch_lib:
            self.uc.mem_write(self.__get_lib_base(filename) + addr, code)


    def set_timeout(self, microseconds):
        self.timeout = microseconds 


    def set_exit(self, until_addr):
        self.until_addr = until_addr


    def insert_map_info(self, mem_s, mem_e, mem_info):
        tmp_map_info = []
        insert_flag = 0
        map_info = self.map_info
        if len(map_info) == 0:
            tmp_map_info.append([mem_s, mem_e, mem_info])
        else:
            for s, e, info in map_info:
                if e <= mem_s:
                    tmp_map_info.append([s, e, info])
                    continue
                if s >= mem_e:
                    if insert_flag == 0:
                        insert_flag = 1
                        tmp_map_info.append([mem_s, mem_e, mem_info])
                    tmp_map_info.append([s, e, info])
                    continue
                if s < mem_s:
                    tmp_map_info.append([s, mem_s, info])

                if s == mem_s:
                    pass
                
                if insert_flag == 0:
                    insert_flag = 1
                    tmp_map_info.append([mem_s, mem_e, mem_info])
                
                if e > mem_e:
                    tmp_map_info.append([mem_e, e, info])
                
                if e == mem_e:
                    pass
            if insert_flag == 0:
                tmp_map_info.append([mem_s, mem_e, mem_info])
        map_info = []
        map_info.append(tmp_map_info[0])
        for s, e, info in tmp_map_info[1 : ]:
            if s == map_info[-1][1] and info == map_info[-1][2]:
                map_info[-1][1] = e
            else:
                map_info.append([s, e, info])
        self.map_info = map_info
    

    def show_map_info(self):
        for s, e, info in self.map_info:
            self.nprint("[+] %08x - %08x      %s" % (s, e, info))
    

    def __get_lib_base(self, filename):
        for s, e, info in self.map_info:
            if os.path.split(info)[1] == filename:
                return s
        return -1


    def add_fs_mapper(self, fm, to):
        self.fs_mapper.append([fm, to])

