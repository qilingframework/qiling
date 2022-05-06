#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Iterator, Mapping, Optional, Sequence, Tuple
from pathlib import PurePath

from qiling.arch.arm_const import reg_map as arm_regs
from qiling.arch.arm_const import reg_vfp as arm_regs_vfp
from qiling.arch.arm64_const import reg_map as arm64_regs
from qiling.arch.mips_const import reg_map as mips_regs_gpr
from qiling.arch.mips_const import reg_map_fpu as mips_regs_fpu
from qiling.arch.x86_const import reg_map_16 as x86_regs_16
from qiling.arch.x86_const import reg_map_32 as x86_regs_32
from qiling.arch.x86_const import reg_map_64 as x86_regs_64
from qiling.arch.x86_const import reg_map_misc as x86_regs_misc
from qiling.arch.x86_const import reg_map_cr as x86_regs_cr
from qiling.arch.x86_const import reg_map_st as x86_regs_st
from qiling.arch.x86_const import reg_map_xmm as x86_regs_xmm
from qiling.arch.x86_const import reg_map_ymm as x86_regs_ymm

from qiling.const import QL_ARCH

RegEntry = Tuple[Optional[int], int, int]

# define a local dummy function to let us reference this module
__anchor__ = lambda x: x

def __get_xml_path(archtype: QL_ARCH) -> Tuple[str, PurePath]:
    import inspect

    p = PurePath(inspect.getfile(__anchor__))
    basedir = p.parent / 'xml' / archtype.name.lower()
    filename = basedir / 'target.xml'

    return str(filename), basedir

def __walk_xml_regs(filename: str, base_url: PurePath) -> Iterator[Tuple[int, str, int]]:
    from xml.etree import ElementTree, ElementInclude

    tree = ElementTree.parse(filename)
    root = tree.getroot()

    # NOTE: this is needed to load xinclude hrefs relative to the main xml file. starting
    # from python 3.9 ElementInclude.include has an argument for that called 'base_url'.
    # this is a workaround for earlier python versions such as 3.8

    def my_loader(base: PurePath):
        def __wrapped(href: str, parse, encoding=None):
            abshref = base / href

            return ElementInclude.default_loader(str(abshref), parse, encoding)

        return __wrapped

    ElementInclude.include(root, loader=my_loader(base_url))

    regnum = -1

    for reg in root.iter('reg'):
        # if regnum is not specified, assume it follows the previous one
        regnum = int(reg.get('regnum', regnum + 1))

        name = reg.attrib['name']
        bitsize = reg.attrib['bitsize']

        yield regnum, name, int(bitsize)

def load_regsmap(archtype: QL_ARCH) -> Sequence[RegEntry]:
    """Initialize registers map using available target XML files.

    Args:
        archtype: target architecture type

    Returns: a list representing registers data
    """

    # retreive the relevant set of registers; their order of appearance is not
    # important as it is determined by the info read from the xml files
    ucregs: Mapping[str, int] = {
        QL_ARCH.A8086    : dict(**x86_regs_16, **x86_regs_misc, **x86_regs_cr, **x86_regs_st),
        QL_ARCH.X86      : dict(**x86_regs_32, **x86_regs_misc, **x86_regs_cr, **x86_regs_st, **x86_regs_xmm),
        QL_ARCH.X8664    : dict(**x86_regs_64, **x86_regs_misc, **x86_regs_cr, **x86_regs_st, **x86_regs_xmm, **x86_regs_ymm),
        QL_ARCH.ARM      : dict(**arm_regs, **arm_regs_vfp),
        QL_ARCH.CORTEX_M : arm_regs,
        QL_ARCH.ARM64    : arm64_regs,
        QL_ARCH.MIPS     : dict(**mips_regs_gpr, **mips_regs_fpu)
    }[archtype]

    xmlpath = __get_xml_path(archtype)
    regsinfo = sorted(__walk_xml_regs(*xmlpath))

    # pre-allocate regmap and occupy it with null entries
    last_regnum = regsinfo[-1][0]
    regmap: Sequence[RegEntry] = [(None, 0, 0)] * (last_regnum + 1)

    pos = 0

    for regnum, name, bitsize in sorted(regsinfo):
        # reg value size in nibbles
        nibbles = bitsize // 4

        regmap[regnum] = (ucregs.get(name), pos, nibbles)

        # value position of next reg
        pos += nibbles

    return regmap

__all__ = ['RegEntry', 'load_regsmap']
