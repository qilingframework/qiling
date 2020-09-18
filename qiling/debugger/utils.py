#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
from qiling import *

from elftools.common.exceptions import ELFError
from elftools.common.py3compat import (
        ifilter, byte2int, bytes2str, itervalues, str2bytes, iterbytes)
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.segments import InterpSegment
from elftools.elf.sections import NoteSection, SymbolTableSection
from elftools.elf.gnuversions import (
    GNUVerSymSection, GNUVerDefSection,
    GNUVerNeedSection,
    )
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_dt_flags, describe_dt_flags_1, describe_ver_flags, describe_note,
    describe_attr_tag_arm
    )
from elftools.elf.constants import E_FLAGS
from elftools.elf.constants import E_FLAGS_MASKS


class QLReadELF(object):
    def __init__(self, ql:Qiling, elf_stream):
        self.ql = ql
        self.elffile = ELFFile(elf_stream)

    def elf_file_header(self):
        elf_header = {}
        def add_info(key, value):
            elf_header[key] = value

        header = self.elffile.header
        e_ident = header['e_ident']

        add_info('Magic', ' '.join('%2.2x' % byte2int(b)
                   for b in self.elffile.e_ident_raw))
        add_info('Class',describe_ei_class(e_ident['EI_CLASS']))
        add_info('Data', describe_ei_data(e_ident['EI_DATA']))
        add_info('Version', e_ident['EI_VERSION'])
        add_info('OS/ABI', describe_ei_osabi(e_ident['EI_OSABI']))
        add_info('ABI Version', e_ident['EI_ABIVERSION'])
        add_info('Type', describe_e_type(header['e_type']))
        add_info('Machine', )
        add_info('Version_e', describe_e_version_numeric(header['e_version']))
        add_info('Entry point address', self._format_hex(header['e_entry']))
        add_info('Start of program headers', header['e_phoff'])
        add_info('Start of section headers', header['e_shoff'])
        add_info('Flags', [self._format_hex(header['e_flags']),
                self.decode_flags(header['e_flags'])])
        add_info('Size of this header', header['e_ehsize'])
        add_info('Size of program headers', header['e_phentsize'])
        add_info('Number of program headers', header['e_phnum'])
        add_info('Size of section headers', header['e_shentsize'])
        add_info('Number of section headers', header['e_shnum'])
        add_info('Section header string table index', header['e_shstrndx'])

        return elf_header

    def decode_flags(self, flags):
        description = ""
        if self.elffile['e_machine'] == "EM_ARM":
            eabi = flags & E_FLAGS.EF_ARM_EABIMASK
            flags &= ~E_FLAGS.EF_ARM_EABIMASK

            if flags & E_FLAGS.EF_ARM_RELEXEC:
                description += ', relocatable executabl'
                flags &= ~E_FLAGS.EF_ARM_RELEXEC

            if eabi == E_FLAGS.EF_ARM_EABI_VER5:
                EF_ARM_KNOWN_FLAGS = E_FLAGS.EF_ARM_ABI_FLOAT_SOFT|E_FLAGS.EF_ARM_ABI_FLOAT_HARD|E_FLAGS.EF_ARM_LE8|E_FLAGS.EF_ARM_BE8
                description += ', Version5 EABI'
                if flags & E_FLAGS.EF_ARM_ABI_FLOAT_SOFT:
                    description += ", soft-float ABI"
                elif flags & E_FLAGS.EF_ARM_ABI_FLOAT_HARD:
                    description += ", hard-float ABI"

                if flags & E_FLAGS.EF_ARM_BE8:
                    description += ", BE8"
                elif flags & E_FLAGS.EF_ARM_LE8:
                    description += ", LE8"

                if flags & ~EF_ARM_KNOWN_FLAGS:
                    description += ', <unknown>'
            else:
                description += ', <unrecognized EABI>'

        elif self.elffile['e_machine'] == "EM_MIPS":
            if flags & E_FLAGS.EF_MIPS_NOREORDER:
                description += ", noreorder"
            if flags & E_FLAGS.EF_MIPS_PIC:
                description += ", pic"
            if flags & E_FLAGS.EF_MIPS_CPIC:
                description += ", cpic"
            if (flags & E_FLAGS.EF_MIPS_ABI2):
                description += ", abi2"
            if (flags & E_FLAGS.EF_MIPS_32BITMODE):
                description += ", 32bitmode"
            if (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O32):
                description += ", o32"
            elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O64):
                description += ", o64"
            elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI32):
                description += ", eabi32"
            elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI64):
                description += ", eabi64"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
                description += ", mips1"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_2:
                description += ", mips2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_3:
                description += ", mips3"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_4:
                description += ", mips4"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_5:
                description += ", mips5"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32R2:
                description += ", mips32r2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64R2:
                description += ", mips64r2"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32:
                description += ", mips32"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64:
                description += ", mips64"

        return description

    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True,
                    alternate=False):
        """ Format an address into a hexadecimal string.

            fieldsize:
                Size of the hexadecimal field (with leading zeros to fit the
                address into. For example with fieldsize=8, the format will
                be %08x
                If None, the minimal required field size will be used.

            fullhex:
                If True, override fieldsize to set it to the maximal size
                needed for the elfclass

            lead0x:
                If True, leading 0x is added

            alternate:
                If True, override lead0x to emulate the alternate
                hexadecimal form specified in format string with the #
                character: only non-zero values are prefixed with 0x.
                This form is used by readelf.
        """
        if alternate:
            if addr == 0:
                lead0x = False
            else:
                lead0x = True
                fieldsize -= 2

        s = '0x' if lead0x else ''
        if fullhex:
            fieldsize = 8 if self.elffile.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr