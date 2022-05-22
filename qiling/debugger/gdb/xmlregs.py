#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Iterator, Mapping, Optional, Sequence, Tuple
from pathlib import PurePath
from xml.etree import ElementTree, ElementInclude

from qiling.arch.arm_const import reg_map as arm_regs
from qiling.arch.arm_const import reg_vfp as arm_regs_vfp
from qiling.arch.arm64_const import reg_map as arm64_regs
from qiling.arch.arm64_const import reg_map_v as arm64_regs_v
from qiling.arch.mips_const import reg_map as mips_regs_gpr
from qiling.arch.mips_const import reg_map_fpu as mips_regs_fpu
from qiling.arch.x86_const import reg_map_32 as x86_regs_32
from qiling.arch.x86_const import reg_map_64 as x86_regs_64
from qiling.arch.x86_const import reg_map_misc as x86_regs_misc
from qiling.arch.x86_const import reg_map_cr as x86_regs_cr
from qiling.arch.x86_const import reg_map_st as x86_regs_st
from qiling.arch.x86_const import reg_map_xmm as x86_regs_xmm
from qiling.arch.x86_const import reg_map_ymm as x86_regs_ymm

from qiling.const import QL_ARCH, QL_OS

RegEntry = Tuple[Optional[int], int, int]

class QlGdbFeatures:
    def __init__(self, archtype: QL_ARCH, ostype: QL_OS):
        xmltree = QlGdbFeatures.__load_target_xml(archtype, ostype)
        regsmap = QlGdbFeatures.__load_regsmap(archtype, xmltree)

        self.xmltree = xmltree
        self.regsmap = regsmap

    def tostring(self) -> str:
        root = self.xmltree.getroot()

        return ElementTree.tostring(root, encoding='unicode', xml_declaration=True)

    @staticmethod
    def __get_xml_path(archtype: QL_ARCH) -> Tuple[str, PurePath]:
        import inspect

        p = PurePath(inspect.getfile(QlGdbFeatures))
        basedir = p.parent / 'xml' / archtype.name.lower()
        filename = basedir / 'target.xml'

        return str(filename), basedir

    @staticmethod
    def __load_target_xml(archtype: QL_ARCH, ostype: QL_OS) -> ElementTree.ElementTree:
        filename, base_url = QlGdbFeatures.__get_xml_path(archtype)

        tree = ElementTree.parse(filename)

        # NOTE: this is needed to load xinclude hrefs relative to the main xml file. starting
        # from python 3.9 ElementInclude.include has an argument for that called 'base_url'.
        # this is a workaround for earlier python versions such as 3.8

        # <WORKAROUND>
        def my_loader(base: PurePath):
            def __wrapped(href: str, parse, encoding=None):
                abshref = base / href

                return ElementInclude.default_loader(str(abshref), parse, encoding)

            return __wrapped
        # </WORKAROUND>

        # inline all xi:include elements
        ElementInclude.include(tree.getroot(), loader=my_loader(base_url))

        # patch xml osabi element with the appropriate abi tag
        osabi = tree.find('osabi')

        if osabi is not None:
            # NOTE: the 'Windows' abi tag is supported starting from gdb 10.
            # earlier gdb versions use 'Cygwin' instead

            abitag = {
                QL_OS.LINUX   : 'GNU/Linux',
                QL_OS.FREEBSD : 'FreeBSD',
                QL_OS.MACOS   : 'Darwin',
                QL_OS.WINDOWS : 'Windows',
                QL_OS.UEFI    : 'Windows',
                QL_OS.DOS     : 'Windows',
                QL_OS.QNX     : 'QNX-Neutrino'
            }.get(ostype, 'unknown')

            osabi.text = abitag

        return tree

    @staticmethod
    def __walk_xml_regs(xmltree: ElementTree.ElementTree) -> Iterator[Tuple[int, str, int]]:
        regnum = -1

        for reg in xmltree.iter('reg'):
            # if regnum is not specified, assume it follows the previous one
            regnum = int(reg.get('regnum', regnum + 1))

            name = reg.attrib['name']
            bitsize = reg.attrib['bitsize']

            yield regnum, name, int(bitsize)

    @staticmethod
    def __load_regsmap(archtype: QL_ARCH, xmltree: ElementTree.ElementTree) -> Sequence[RegEntry]:
        """Initialize registers map using available target XML files.

        Args:
            archtype: target architecture type

        Returns: a list representing registers data
        """

        # retreive the relevant set of registers; their order of appearance is not
        # important as it is determined by the info read from the xml files
        ucregs: Mapping[str, int] = {
            QL_ARCH.A8086    : dict(**x86_regs_32, **x86_regs_misc, **x86_regs_cr, **x86_regs_st),
            QL_ARCH.X86      : dict(**x86_regs_32, **x86_regs_misc, **x86_regs_cr, **x86_regs_st, **x86_regs_xmm),
            QL_ARCH.X8664    : dict(**x86_regs_64, **x86_regs_misc, **x86_regs_cr, **x86_regs_st, **x86_regs_xmm, **x86_regs_ymm),
            QL_ARCH.ARM      : dict(**arm_regs, **arm_regs_vfp),
            QL_ARCH.CORTEX_M : arm_regs,
            QL_ARCH.ARM64    : dict(**arm64_regs, **arm64_regs_v),
            QL_ARCH.MIPS     : dict(**mips_regs_gpr, **mips_regs_fpu)
        }[archtype]

        regsinfo = sorted(QlGdbFeatures.__walk_xml_regs(xmltree))

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


__all__ = ['RegEntry', 'QlGdbFeatures']
