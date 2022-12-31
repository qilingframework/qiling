#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
import json
import re
import libr
from dataclasses import dataclass, field, fields
from functools import cached_property
from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Pattern, Tuple, Union
from qiling.const import QL_ARCH
from qiling.extensions import trace
from unicorn import UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL
from .callstack import CallStack
from .deflat import R2Deflator
from .utils import wrap_aaa, wrap_arg_addr

if TYPE_CHECKING:
    from qiling.extensions.r2 import R2Qiling

def perm2uc(permstr: str) -> int:
    '''convert "-rwx" to unicorn const'''
    perm = UC_PROT_NONE
    dic = {
        "r": UC_PROT_READ,
        "w": UC_PROT_WRITE,
        "x": UC_PROT_EXEC,
    }
    for ch in permstr:
        perm += dic.get(ch, 0)
    return perm


class R2Data:
    def __init__(self, **kwargs):
        names = set([f.name for f in fields(self)])
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)

    def __str__(self):
        kvs = []
        for k, v in sorted(self.__dict__.items()):
            if k.startswith("_") or not isinstance(v, (int, str)):
                continue
            v = hex(v) if isinstance(v, int) else v
            kvs.append(f"{k}={v}")
        return (f"{self.__class__.__name__}(" + ", ".join(kvs) + ")")
    
    __repr__ = __str__

    @cached_property
    def start_ea(self):
        return getattr(self, 'addr', None) or getattr(self, 'offset', None) or getattr(self, 'vaddr', None)

    @cached_property
    def end_ea(self):
        size = getattr(self, 'size', None) or getattr(self, 'length', None)
        if (self.start_ea or size) is None:
            return None
        return self.start_ea + size

    def __contains__(self, target):
        if isinstance(target, int):
            return self.start_ea <= target < (self.end_ea or 1<<32)
        else:
            return self.start_ea <= target.start_ea and ((target.end_ea or target.start_ea) <= (self.end_ea or 1<<32))
    

@dataclass(unsafe_hash=True, init=False)
class Section(R2Data):
    name: str
    size: int
    vsize: int
    paddr: int
    vaddr: int
    perm: int

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.perm = perm2uc(self.perm)


@dataclass(unsafe_hash=True, init=False)
class String(R2Data):
    string: str
    vaddr: int
    paddr: int
    size: int
    length: int
    section: str = None


@dataclass(unsafe_hash=True, init=False)
class Symbol(R2Data):
    # see https://github.com/rizinorg/rizin/blob/dev/librz/include/rz_bin.h
    SymbolType = Literal["NOTYPE", "OBJ", "FUNC", "FIELD", "IFACE", "METH", "STATIC", "SECT",
                         "FILE", "COMMON", "TLS", "NUM", "LOOS", "HIOS", "LOPROC", "HIPROC", "SPCL", "UNK"]

    SymbolBind = Literal["LOCAL", "GLOBAL", "WEAK", "NUM", "LOOS", "HIOS", "LOPROC", "HIPROC", "IMPORT", "UNKNOWN"]

    name: str
    realname: str
    bind: SymbolBind
    size: int
    type: SymbolType
    vaddr: int
    paddr: int
    is_imported: bool


@dataclass(unsafe_hash=True, init=False)
class Instruction(R2Data):
    offset: int
    size: int
    opcode: str  # raw opcode
    disasm: str = ''  # flag resolved opcode
    bytes: bytes
    type: str

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bytes = bytes.fromhex(kwargs["bytes"])

    def is_jcond(self):
        return self.type in ("cjmp", "cmov")


@dataclass(unsafe_hash=True, init=False)
class Operand(R2Data):
    type: str
    value: str
    size: int
    rw: int


@dataclass(unsafe_hash=True, init=False)
class AnalOp(R2Data):
    addr: int
    size: int
    type: str
    mnemonic: str
    opcode: str
    operands: List[Operand]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.operands = [Operand(**op) for op in kwargs["opex"]["operands"]]


@dataclass(unsafe_hash=True, init=False)
class Function(R2Data):
    name: str
    offset: int
    size: int
    signature: str



@dataclass(unsafe_hash=True, init=False)
class Flag(R2Data):
    offset: int  # should be addr but r2 calls it offset
    name: str = ''
    size: int = 0

    def __lt__(self, other):
        return self.offset < other.offset


@dataclass(unsafe_hash=True, init=False)
class Xref(R2Data):
    XrefType = Literal["NULL", "CODE", "CALL", "DATA", "STRN", "UNKN"]

    name: str
    fromaddr: int  # from is reserved word in Python
    type: XrefType
    perm: int
    addr: int
    refname: str

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.fromaddr = kwargs["from"]
        self.perm = perm2uc(self.perm)

    def __lt__(self, other):
        return self.fromaddr < other.fromaddr


@dataclass(unsafe_hash=True, init=False)
class BasicBlock(R2Data):
    addr: int
    size: int
    inputs: int
    outputs: int
    ninstr: int
    jump: Optional[int] = None
    fail: Optional[int] = None

    @cached_property
    def start(self):
        return self.addr

    @cached_property
    def end(self):
        return self.addr + self.size


class R2:
    def __init__(self, ql: 'R2Qiling', baseaddr=(1 << 64) - 1, loadaddr=0):
        super().__init__()
        self.ql = ql
        # r2 -B [baddr]   set base address for PIE binaries
        self.baseaddr = baseaddr
        self.loadaddr = loadaddr  # r2 -m [addr]    map file at given address
        self.analyzed = False
        self._r2c = libr.r_core.r_core_new()
        self._r2i = ctypes.cast(self._r2c.contents.io, ctypes.POINTER(libr.r_io.struct_r_io_t))
        self._setup_mem(ql)
        if ql.code is None:  # ql is initialized with file
            self._load_symbol_from_file(ql.path)

    def _qlarch2r(self, archtype: QL_ARCH) -> str:
        return {
            QL_ARCH.X86: "x86",
            QL_ARCH.X8664: "x86",
            QL_ARCH.ARM: "arm",
            QL_ARCH.ARM64: "arm",
            QL_ARCH.A8086: "x86",
            QL_ARCH.EVM: "evm.cs",
            QL_ARCH.CORTEX_M: "arm",
            QL_ARCH.MIPS: "mips",
            QL_ARCH.RISCV: "riscv",
            QL_ARCH.RISCV64: "riscv",
            QL_ARCH.PPC: "ppc",
        }[archtype]

    def _rbuf_map(self, cbuf: ctypes.Array, perm: int = UC_PROT_ALL, addr: int = 0, delta: int = 0):
        rbuf = libr.r_buf_new_with_pointers(cbuf, len(cbuf), False)  # last arg `steal` = False
        rbuf = ctypes.cast(rbuf, ctypes.POINTER(libr.r_io.struct_r_buf_t))
        desc = libr.r_io_open_buffer(self._r2i, rbuf, UC_PROT_ALL, 0)  # last arg `mode` is always 0 in r2 code
        libr.r_io.r_io_map_add(self._r2i, desc.contents.fd, desc.contents.perm, delta, addr, len(cbuf))

    def _setup_mem(self, ql: 'R2Qiling'):
        if not hasattr(ql, '_mem'):
            return
        for start, _end, perms, _label, _mmio in ql.mem.map_info:
            cbuf = ql.mem.cmap[start]
            self._rbuf_map(cbuf, perms, start)
        # set architecture and bits for r2 asm
        arch = self._qlarch2r(ql.arch.type)
        self._cmd(f"e,asm.arch={arch},asm.bits={ql.arch.bits}")
        self._cmd("oba")  # load bininfo and update flags
    
    def _load_symbol_from_file(self, path: str):
        r2c = libr.r_core.r_core_new()
        path = path.encode()
        fh = libr.r_core.r_core_file_open(r2c, path, UC_PROT_READ | UC_PROT_EXEC, self.loadaddr)
        libr.r_core.r_core_bin_load(r2c, path, self.baseaddr)
        symbols = self._cmdj("isj", r2c)
        for sym in symbols:
            name = sym['name']  # name is shoter, but starting with . causes error
            name = sym['flagname'] if name.startswith('.') else name
            if name:  # add each symbol as flag if symbol name is not empty
                self._cmd(f"f {name} {sym['size']} @ {sym['vaddr']}")
        libr.r_core_free(r2c)
    
    def _cmd(self, cmd: str, r2c = None) -> str:
        r2c = r2c or self._r2c
        r = libr.r_core.r_core_cmd_str(
            r2c, ctypes.create_string_buffer(cmd.encode("utf-8")))
        return ctypes.string_at(r).decode('utf-8')

    def _cmdj(self, cmd: str, r2c = None) -> Union[Dict, List[Dict]]:
        return json.loads(self._cmd(cmd, r2c))

    @property
    def offset(self) -> int:
        return self._r2c.contents.offset

    @cached_property
    def binfo(self) -> Dict[str, str]:
        return self._cmdj("iIj")

    @cached_property
    def baddr(self) -> int:
        return self.binfo["baddr"]

    @cached_property
    def bintype(self) -> str:
        return self.binfo["bintype"]

    @cached_property
    def sections(self) -> Dict[str, Section]:
        sec_lst = self._cmdj("iSj")
        return {dic['name']: Section(**dic) for dic in sec_lst}

    @cached_property
    def strings(self) -> Dict[str, String]:
        str_lst = self._cmdj("izzj")
        return {dic['string']: String(**dic) for dic in str_lst}

    @cached_property
    def symbols(self) -> Dict[str, Symbol]:
        sym_lst = self._cmdj("isj")
        return {dic['name']: Symbol(**dic).vaddr for dic in sym_lst}

    @cached_property
    @wrap_aaa
    def functions(self) -> Dict[str, Function]:
        fcn_lst = self._cmdj("aflj")
        return {dic['name']: Function(**dic) for dic in fcn_lst}

    @cached_property
    @wrap_aaa
    def flags(self) -> List[Flag]:
        return [Flag(**dic) for dic in self._cmdj("fj")]

    @cached_property
    @wrap_aaa
    def xrefs(self) -> List[Xref]:
        return [Xref(**dic) for dic in self._cmdj("axj")]

    @wrap_aaa
    @wrap_arg_addr
    def get_fcn_bbs(self, addr: int):
        '''list basic blocks of function'''
        return [BasicBlock(**dic) for dic in self._cmdj(f"afbj @ {addr}")]

    @wrap_aaa
    @wrap_arg_addr
    def get_bb(self, addr: int):
        '''get basic block at address'''
        try:
            dic = self._cmdj(f"afbj. {addr}")[0]
            return BasicBlock(**dic)
        except IndexError:
            pass

    @wrap_aaa
    @wrap_arg_addr
    def get_fcn(self, addr: int):
        try:
            dic = self._cmdj(f"afij {addr}")[0]  # afi show function information
            return Function(**dic)
        except IndexError:
            pass
    
    @wrap_aaa
    @wrap_arg_addr
    def anal_op(self, addr: int):
        '''r2 opcode analysis (detail about an instruction) at address'''
        dic = self._cmdj(f"aoj @ {addr}")[0]
        return AnalOp(**dic)

    def at(self, addr: int, parse=False) -> Union[str, Tuple[str, int]]:
        '''Given an address, return [name, offset] or "name + offset"'''
        name = self._cmd(f'fd {addr}').strip()
        if parse:
            try:
                name, offset = name.split(' + ')
                offset = int(offset)
            except ValueError:  # split fail when offset=0
                offset = 0
            return name, offset
        return name

    def where(self, name: str, offset: int=0) -> int:
        '''Given a name (+ offset), return its address (0 when not found)'''
        if offset != 0:  # name can already have offset, multiple + is allowd
            name += f' + {offset}'
        addr = self._cmd(f'?v {name}').strip()  # 0x0 when name is not found
        return int(addr, 16)

    def refrom(self, addr: int) -> List[Xref]:
        return [x for x in self.xrefs if x.fromaddr == addr]

    def refto(self, addr: int) -> List[Xref]:
        return [x for x in self.xrefs if x.addr == addr]

    def read(self, addr: int, size: int) -> bytes:
        hexstr = self._cmd(f"p8 {size} @ {addr}")
        return bytes.fromhex(hexstr)

    def write(self, addr: int, bs: bytes) -> None:
        self._cmd(f"wx {bs.hex()} @ {addr}")

    def dis_nbytes(self, addr: int, size: int) -> List[Instruction]:
        insts = [Instruction(**dic) for dic in self._cmdj(f"pDj {size} @ {addr}")]
        return insts

    def dis_ninsts(self, addr: int, n: int=1) -> List[Instruction]:
        insts = [Instruction(**dic) for dic in self._cmdj(f"pdj {n} @ {addr}")]
        return insts

    def dis(self, target: Union[Function, BasicBlock]) -> List[Instruction]:
        addr = target.start_ea
        size = target.size
        insts = [Instruction(**dic) for dic in self._cmdj(f"pDj {size} @ {addr}")]
        return insts

    def _backtrace_fuzzy(self, at: int = None, depth: int = 128) -> Optional[CallStack]:
        '''Fuzzy backtrace, see https://github.com/radareorg/radare2/blob/master/libr/debug/p/native/bt/fuzzy_all.c#L38
        Args:
            at: address to start walking stack, default to current SP
            depth: limit of stack walking
        Returns:
            List of Frame
        '''
        sp = at or self.ql.arch.regs.arch_sp
        wordsize = self.ql.arch.bits // 8
        frame = None
        cursp = oldsp = sp
        for i in range(depth):
            addr = self.ql.stack_read(i * wordsize)
            inst = self.dis_ninsts(addr)[0]
            if inst.type.lower() == 'call':
                newframe = CallStack(addr=addr, sp=cursp, bp=oldsp, name=self.at(addr), next=frame)
                frame = newframe
                oldsp = cursp
            cursp += wordsize
        return frame

    @wrap_arg_addr
    def set_backtrace(self, addr: int):
        '''Set backtrace at target address before executing'''
        def bt_hook(__ql: 'R2Qiling', *args):
            print(self._backtrace_fuzzy())
        self.ql.hook_address(bt_hook, addr)

    def disassembler(self, ql: 'R2Qiling', addr: int, size: int, filt: Pattern[str]=None) -> int:
        '''A human-friendly monkey patch of QlArchUtils.disassembler powered by r2, can be used for hook_code
            :param ql: Qiling instance
            :param addr: start address for disassembly
            :param size: size in bytes
            :param filt: regex pattern to filter instructions
            :return: progress of dissembler, should be equal to size if success
        '''
        anibbles = ql.arch.bits // 4
        progress = 0
        for inst in self.dis_nbytes(addr, size):
            if inst.type.lower() in ('invalid', 'ill'):
                break  # stop disasm
            name, offset = self.at(inst.offset, parse=True)
            if filt is None or filt.search(name):
                ql.log.info(f'{inst.offset:0{anibbles}x} [{name:20s} + {offset:#08x}] {inst.bytes.hex(" "):20s} {inst.disasm}')
            progress = inst.offset + inst.size - addr
        if progress < size:
            ql.arch.utils.disassembler(ql, addr + progress, size - progress)
        return progress

    def enable_disasm(self, filt_str: str=''):
        filt = re.compile(filt_str)
        self.ql.hook_code(self.disassembler, filt)

    def enable_trace(self, mode='full'):
        # simple map from addr to flag name, cannot resolve addresses in the middle
        self.ql.loader.symsmap = {flag.offset: flag.name for flag in self.flags}
        if mode == 'full':
            trace.enable_full_trace(self.ql)
        elif mode == 'history':
            trace.enable_history_trace(self.ql)

    @wrap_arg_addr
    def deflat(self, addr: int):
        '''Deflat function at given address, will patch ql code'''
        deflator = R2Deflator(self)
        deflator.parse_blocks_for_deobf(addr)
        deflator._search_path()
        deflator._patch_codes()

    @wrap_arg_addr
    def shell(self, addr: int = None):
        '''Start a r2-like interative shell at given address
        TODO: now it just a REPL, terminal graph UI is not supported
        '''
        self._cmd(f's {addr or self.ql.arch.regs.arch_pc or self.offset}')
        while True:
            print(f"[{self.offset:#x}]> ", end="")
            cmd = input()
            if cmd.strip() == "q":
                break
            print(self._cmd(cmd))

    def __del__(self):
        libr.r_core.r_core_free(self._r2c)
