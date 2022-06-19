#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
import json
import libr
from dataclasses import dataclass, fields
from enum import Enum
from functools import cached_property
from qiling.core import Qiling
from unicorn import UC_PROT_READ, UC_PROT_EXEC, UC_PROT_ALL


class R2Data:
    def __init__(self, **kwargs):
        names = set([f.name for f in fields(self)])
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)


@dataclass(unsafe_hash=True, init=False)
class Function(R2Data):
    name: str
    offset: int
    size: int
    signature: str


@dataclass(unsafe_hash=True, init=False)
class Section(R2Data):
    name: str
    size: int
    vsize: int
    paddr: int
    vaddr: int
    perm: str  # TODO: use int or enum


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
    class SymbolType(str, Enum):
        NOTYPE = "NOTYPE"
        OBJ = "OBJ"
        FUNC = "FUNC"
        FIELD = "FIELD"
        IFACE = "IFACE"
        METH = "METH"
        STATIC = "STATIC"
        SECT = "SECT"
        FILE = "FILE"
        COMMON = "COMMON"
        TLS = "TLS"
        NUM = "NUM"
        LOOS = "LOOS"
        HIOS = "HIOS"
        LOPROC = "LOPROC"
        HIPROC = "HIPROC"
        SPCL = "SPCL"
        UNK = "UNK"

    class SymbolBind(str, Enum):
        LOCAL = "LOCAL"
        GLOBAL = "GLOBAL"
        WEAK = "WEAK"
        NUM = "NUM"
        LOOS = "LOOS"
        HIOS = "HIOS"
        LOPROC = "LOPROC"
        HIPROC = "HIPROC"
        IMPORT = "IMPORT"
        UNKNOWN = "UNKNOWN"

    name: str
    realname: str
    bind: str
    size: int
    type: SymbolType
    vaddr: int
    paddr: int
    is_imported: bool


class R2:
    def __init__(self, ql: Qiling, baseaddr=(1 << 64) - 1, loadaddr=0):
        super().__init__()
        self.ql = ql
        self.baseaddr = baseaddr  # r2 -B [baddr]   set base address for PIE binaries
        self.loadaddr = loadaddr  # r2 -m [addr]    map file at given address

        self._r2c = libr.r_core.r_core_new()
        if ql.code:
            self._setup_code()
        else:
            self._setup_file()

        # set architecture and bits for r2 asm
        self._cmd(f"e,asm.arch={ql.arch.type.name.lower().removesuffix('64')},asm.bits={ql.arch.bits}")

    def _setup_code(self):
        sz = len(self.ql.code)
        path = f'malloc://{sz}'.encode()
        fh = libr.r_core.r_core_file_open(self._r2c, path, UC_PROT_ALL, self.loadaddr)
        libr.r_core.r_core_bin_load(self._r2c, path, self.baseaddr)
        cmd = f'wx {self.ql.code.hex()}'
        self._cmd(cmd)

    def _setup_file(self):
        path = self.ql.path.encode()
        fh = libr.r_core.r_core_file_open(self._r2c, path, UC_PROT_READ | UC_PROT_EXEC, self.loadaddr)
        libr.r_core.r_core_bin_load(self._r2c, path, self.baseaddr)

    def _cmd(self, cmd: str) -> str:
        r = libr.r_core.r_core_cmd_str(
            self._r2c, ctypes.create_string_buffer(cmd.encode("utf-8")))
        return ctypes.string_at(r).decode('utf-8')

    def _cmdj(self, cmd: str) -> list[dict]:
        return json.loads(self._cmd(cmd))

    @cached_property
    def sections(self) -> dict[str, Section]:
        sec_lst = self._cmdj("iSj")
        return {dic['name']: Section(**dic) for dic in sec_lst}

    @cached_property
    def strings(self) -> dict[str, String]:
        str_lst = self._cmdj("izzj")
        return {dic['string']: String(**dic) for dic in str_lst}

    @cached_property
    def symbols(self) -> dict[str, Symbol]:
        sym_lst = self._cmdj("isj")
        return {dic['name']: Symbol(**dic).vaddr for dic in sym_lst}

    @cached_property
    def functions(self) -> dict[str, Function]:
        self._cmd("aaa")
        fcn_lst = self._cmdj("aflj")
        return {dic['name']: Function(**dic) for dic in fcn_lst}

    @cached_property
    def baddr(self) -> int:
        _bin = ctypes.cast(self._r2c.contents.bin,
                           ctypes.POINTER(libr.r_bin.RBin))
        return libr.r_bin.r_bin_get_baddr(_bin)

    def __del__(self):
        libr.r_core.r_core_free(self._r2c)
