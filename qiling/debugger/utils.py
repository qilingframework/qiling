#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

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

from qiling import Qiling


class QlReadELF(object):
    def __init__(self, ql:Qiling, elf_stream):
        self.ql = ql
        self.elffile = ELFFile(elf_stream)
        self._versioninfo = None

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
        add_info('Machine', describe_e_machine(header['e_machine']))
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

    def elf_program_headers(self):
        program_headers = []
        def add_info(dic):
            program_headers.append(dic)

        if self.elffile.num_segments() == 0:
            return None

        for segment in self.elffile.iter_segments():
            program_hdr = {}
            program_hdr['Type'] = describe_p_type(segment['p_type'])
            program_hdr['Offset'] = self._format_hex(segment['p_offset'], fieldsize=6)
            program_hdr['VirtAddr'] = self._format_hex(segment['p_vaddr'], fullhex=True)
            program_hdr['PhysAddr'] = self._format_hex(segment['p_paddr'], fullhex=True)
            program_hdr['FileSiz'] = self._format_hex(segment['p_filesz'], fieldsize=5)
            program_hdr['MemSiz'] = self._format_hex(segment['p_memsz'], fieldsize=5)
            program_hdr['Flg'] = describe_p_flags(segment['p_flags'])
            program_hdr['Align'] = self._format_hex(segment['p_align'])

            add_info(program_hdr)

        return program_headers

    def elf_section_headers(self):
        section_headers = []
        def add_info(dic):
            section_headers.append(dic)

        if self.elffile.num_sections() == 0:
            return None

        for nsec, section in enumerate(self.elffile.iter_sections()):
            section_hdr = {}
            section_hdr['index'] = nsec
            section_hdr['Name'] = section.name
            section_hdr['Type'] = describe_sh_type(section['sh_type'])
            section_hdr['Addr'] = self._format_hex(section['sh_addr'], fieldsize=8, lead0x=False)
            section_hdr['Offset'] = self._format_hex(section['sh_offset'], fieldsize=6, lead0x=False)
            section_hdr['Size'] = self._format_hex(section['sh_size'], fieldsize=6, lead0x=False)
            section_hdr['ES'] = self._format_hex(section['sh_entsize'], fieldsize=2, lead0x=False)
            section_hdr['Flag'] = describe_sh_flags(section['sh_flags'])
            section_hdr['Lk'] = section['sh_link']
            section_hdr['Inf'] = section['sh_info']
            section_hdr['Al'] = section['sh_addralign']

            add_info(section_hdr)

        return section_headers

    def elf_symbol_tables(self):
        symbol_tables_list = []
        def add_info(dic):
            symbol_tables_list.append(dic)

        self._init_versioninfo()

        symbol_tables = [s for s in self.elffile.iter_sections()
                    if isinstance(s, SymbolTableSection)]

        if not symbol_tables and self.elffile.num_sections() == 0:
            return None

        for section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                continue

            for nsym, symbol in enumerate(section.iter_symbols()):
                version_info = ''
                if (section['sh_type'] == 'SHT_DYNSYM' and
                        self._versioninfo['type'] == 'GNU'):
                    version = self._symbol_version(nsym)
                    if (version['name'] != symbol.name and
                        version['index'] not in ('VER_NDX_LOCAL',
                                                 'VER_NDX_GLOBAL')):
                        if version['filename']:
                            # external symbol
                            version_info = '@%(name)s (%(index)i)' % version
                        else:
                            # internal symbol
                            if version['hidden']:
                                version_info = '@%(name)s' % version
                            else:
                                version_info = '@@%(name)s' % version

                symbol_info = {}
                symbol_info['index'] = nsym
                symbol_info['Value'] = self._format_hex(
                        symbol['st_value'], fullhex=True, lead0x=False)
                symbol_info['Size'] = symbol['st_size']
                symbol_info['Type'] = describe_symbol_type(symbol['st_info']['type'])
                symbol_info['Bind'] = describe_symbol_bind(symbol['st_info']['bind'])
                symbol_info['Vis'] = describe_symbol_visibility(symbol['st_other']['visibility'])
                symbol_info['Ndx'] = describe_symbol_shndx(symbol['st_shndx'])
                symbol_info['Name'] = symbol.name
                symbol_info['version_info'] = version_info
                add_info(symbol_info)
        return symbol_tables_list

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

    def _init_versioninfo(self):
        """ Search and initialize informations about version related sections
            and the kind of versioning used (GNU or Solaris).
        """
        if self._versioninfo is not None:
            return

        self._versioninfo = {'versym': None, 'verdef': None,
                             'verneed': None, 'type': None}

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._versioninfo['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                self._versioninfo['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                self._versioninfo['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        self._versioninfo['type'] = 'GNU'
                        break

        if not self._versioninfo['type'] and (
                self._versioninfo['verneed'] or self._versioninfo['verdef']):
            self._versioninfo['type'] = 'Solaris'

    def _symbol_version(self, nsym):
        """ Return a dict containing information on the
                   or None if no version information is available
        """
        self._init_versioninfo()

        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self._versioninfo['versym'] or
                nsym >= self._versioninfo['versym'].num_symbols()):
            return None

        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self._versioninfo['type'] == 'GNU':
                # In GNU versioning mode, the highest bit is used to
                # store wether the symbol is hidden or not
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self._versioninfo['verdef'] and
                    index <= self._versioninfo['verdef'].num_versions()):
                _, verdaux_iter = \
                        self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = \
                        self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return symbol_version
