from idaapi import *
from idc import *
from idautils import *
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import (QPushButton, QHBoxLayout)
from qiling import Qiling
from qiling.const import *
from qiling.os.filestruct import ql_file
from qiling.arch.x86_const import reg_map_32 as x86_reg_map_32
from qiling.arch.x86_const import reg_map_64 as x86_reg_map_64
from qiling.arch.x86_const import reg_map_misc as x86_reg_map_misc
from qiling.arch.x86_const import reg_map_st as x86_reg_map_st
from qiling.arch.arm_const import reg_map as arm_reg_map
from qiling.arch.arm64_const import reg_map as arm64_reg_map
from qiling.arch.mips_const import reg_map as mips_reg_map
import collections
from enum import Enum

class Colors(Enum):
    Blue = 0xE8864A
    Pink = 0xC0C0FB
    White = 0xFFFFFF
    Black = 0x000000
    Green = 0xd3ead9
    Gray = 0xd9d9d9
    Beige = 0xCCF2FF

### Qiling wrapper
class QlEmuQiling:
    def __init__(self):
        self.path = get_input_file_path()
        self.rootfs = None
        self.ql = None
        self.status = None
        self.exit_addr = None
        self.baseaddr = None

    def start(self):
        if sys.platform != 'win32':
            qlstdin = QlEmuMisc.QLStdIO('stdin', sys.__stdin__.fileno())
            qlstdout = QlEmuMisc.QLStdIO('stdout', sys.__stdout__.fileno())
            qlstderr = QlEmuMisc.QLStdIO('stderr', sys.__stderr__.fileno())
            
        if sys.platform != 'win32':
            self.ql = Qiling(filename=[self.path], rootfs=self.rootfs, output="debug", stdin=qlstdin, stdout=qlstdout, stderr=qlstderr)
        else:
            self.ql = Qiling(filename=[self.path], rootfs=self.rootfs, output="debug")
        
        self.exit_addr = self.ql.os.exit_point
        if self.ql.ostype == QL_OS.LINUX:
            self.baseaddr = self.ql.os.elf_mem_start
        else:
            self.baseaddr = 0x0

    def run(self, begin=None, end=None):
        self.ql.run(begin, end)

    def set_reg(self):
        reglist = QlEmuMisc.get_reg_map(self.ql)
        regs = [ [ row, int(self.ql.reg.read(row)), ql_get_arch_bits(self.ql.archtype) ] for row in reglist ]
        regs_len = len(regs)
        RegDig = QlEmuRegDialog(regs)
        if RegDig.show():
            for idx, val in enumerate(RegDig.items[0:regs_len-1]):
                self.ql.reg.write(reglist[idx], val[1])
            return True
        else:
            return False

    def save(self):
        savedlg = QlEmuSaveDialog()
        savedlg.Compile()

        if savedlg.Execute() != 1:
            return False

        savepath = savedlg.path_name.value

        self.ql.save(reg=True, mem=True,fd=True, cpu_context=True, snapshot=savepath)
        print('Save to ' + savepath)
        return True
    
    def load(self):
        loaddlg = QlEmuLoadDialog()
        loaddlg.Compile()

        if loaddlg.Execute() != 1:
            return False

        loadname = loaddlg.file_name.value

        self.ql.restore(snapshot=loadname)
        print('Restore from ' + loadname)
        return True

    def remove_ql(self):
        if self.ql is not None:
            del self.ql
            self.ql = None


### Misc
class QlEmuMisc:
    MenuItem = collections.namedtuple("MenuItem", ["action", "handler", "title", "tooltip", "shortcut", "popup"])
    class menu_action_handler(action_handler_t):
        def __init__(self, handler, action):
            action_handler_t.__init__(self)
            self.action_handler = handler
            self.action_type = action

        def activate(self, ctx):
            if ctx.form_type == BWN_DISASM:
                self.action_handler.ql_handle_menu_action(self.action_type)
            return 1

        # This action is always available.
        def update(self, ctx):
            return AST_ENABLE_ALWAYS

    @staticmethod
    def get_reg_map(ql:Qiling):
        tables = {
            QL_ARCH.X86     : list({**x86_reg_map_32, **x86_reg_map_misc, **x86_reg_map_st}.keys()),
            QL_ARCH.X8664   : list({**x86_reg_map_64, **x86_reg_map_misc, **x86_reg_map_st}.keys()),
            QL_ARCH.ARM     : list({**arm_reg_map}.keys()),
            QL_ARCH.ARM64   : list({**arm64_reg_map}.keys()),
            QL_ARCH.MIPS    : list({**mips_reg_map}.keys()),
        }

        if ql.archtype == QL_ARCH.X86:
            return tables[QL_ARCH.X86]
        elif ql.archtype == QL_ARCH.X8664:
            return tables[QL_ARCH.X8664]
        elif ql.archtype == QL_ARCH.ARM:
            return tables[QL_ARCH.ARM]
        elif ql.archtype == QL_ARCH.ARM64:
            return tables[QL_ARCH.ARM64]
        elif ql.archtype == QL_ARCH.MIPS:
            return tables[QL_ARCH.MIPS]
        else:
            return []

    @staticmethod
    def url_download(url):
        try:
            from urllib2 import Request, urlopen, URLError, HTTPError
        except:
            from urllib.request import Request, urlopen
            from urllib.error import URLError, HTTPError

        # create the url and the request
        req = Request(url)

        # Open the url
        try:
            # download this URL
            f = urlopen(req)
            content = f.read()
            return (0, content)

        # handle errors
        except HTTPError as e:
            # print "HTTP Error:", e.code , url
            # fail to download this file
            return (1, None)
        except URLError as e:
            # print "URL Error:", e.reason , url
            # fail to download this file
            return (1, None)
        except Exception as e:
            # fail to save the downloaded file
            # print("Error:", e)
            return (2, None)

    class QLStdIO(ql_file):
        def __init__(self, path, fd):
            super().__init__(path, fd)
            self.__fd = fd

        def write(self, write_buf):
            super().write(write_buf) 
            msg(write_buf.decode('utf-8'))

        def flush(self):
            pass

        def isatty(self):
            return False   