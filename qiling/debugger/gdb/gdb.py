#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# for watching actual protocol messages:
#   server:     gdbserver --remote-debug 127.0.0.1:9999 /path/to/exec
#   client:     gdb -q -ex "target remote 127.0.0.1:9999"
#
#   also, run this command on the gdb client:
#       (gdb) set debug remote 1
#
# gdb remote protocol:
#   https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html

import os, socket, re
from logging import Logger
from typing import Iterator, Optional, Union

from unicorn import UcError
from unicorn.unicorn_const import (
    UC_ERR_READ_UNMAPPED,  UC_ERR_WRITE_UNMAPPED,  UC_ERR_FETCH_UNMAPPED,
    UC_ERR_READ_PROT,      UC_ERR_WRITE_PROT,      UC_ERR_FETCH_PROT,
    UC_ERR_READ_UNALIGNED, UC_ERR_WRITE_UNALIGNED, UC_ERR_FETCH_UNALIGNED,
    UC_ERR_INSN_INVALID
)

from qiling import Qiling
from qiling.const import QL_ARCH, QL_ENDIAN, QL_OS
from qiling.debugger import QlDebugger
from qiling.debugger.gdb.xmlregs import QlGdbFeatures
from qiling.debugger.gdb.utils import QlGdbUtils

# gdb logging prompt
PROMPT = r'gdb>'

# default string encoding
ENCODING = 'latin'

# define a few handy linux signals
SIGINT  = 2
SIGILL  = 4
SIGTRAP = 5
SIGABRT = 6
SIGBUS  = 7
SIGKILL = 9
SIGSEGV = 11
SIGALRM = 14
SIGTERM = 15
SIGCHLD = 16
SIGCONT = 17
SIGSTOP = 18

# common replies
REPLY_ACK = b'+'
REPLY_EMPTY = b''
REPLY_OK = b'OK'

# reply type
Reply = Union[bytes, str]

class QlGdb(QlDebugger):
    """A simple gdbserver implementation.
    """

    def __init__(self, ql: Qiling, ip: str = '127.0.01', port: int = 9999):
        super().__init__(ql)

        if type(port) is str:
            port = int(port, 0)

        self.ip = ip
        self.port = port

        if ql.baremetal:
            load_address = ql.loader.load_address
            exit_point = load_address + os.path.getsize(ql.path)
        elif ql.code:
            load_address = ql.os.entry_point
            exit_point = load_address + len(ql.code)
        else:
            load_address = ql.loader.load_address
            exit_point = load_address + os.path.getsize(ql.path)

        if ql.baremetal:
            entry_point = ql.loader.entry_point
        elif ql.os.type in (QL_OS.LINUX, QL_OS.FREEBSD) and not ql.code:
            entry_point = ql.os.elf_entry
        else:
            entry_point = ql.os.entry_point

        # Only part of the binary file will be debugged.
        if ql.entry_point is not None:
            entry_point = ql.entry_point

        if ql.exit_point is not None:
            exit_point = ql.exit_point

        self.gdb = QlGdbUtils(ql, entry_point, exit_point)

        self.features = QlGdbFeatures(self.ql.arch.type, self.ql.os.type)
        self.regsmap = self.features.regsmap

    def run(self):
        server = GdbSerialConn(self.ip, self.port, self.ql.log)
        killed = False

        def __hexstr(value: int, nibbles: int = 0) -> str:
            """Encode a value into a hex string.
            """

            length = (nibbles or self.ql.arch.bits // 4) // 2
            byteorder = 'little' if self.ql.arch.endian == QL_ENDIAN.EL else 'big'

            return value.to_bytes(length, byteorder).hex()

        def __unkown_reg_value(nibbles: int) -> str:
            """Encode the hex string for unknown regsiter value.
            """

            return 'x' * nibbles

        def __get_reg_value(reg: Optional[int], pos: int, nibbles: int) -> str:
            # reg is either None or uc reg invalid
            if reg:
                value = self.ql.arch.regs.read(reg)
                assert type(value) is int

                hexstr = __hexstr(value, nibbles)
            else:
                hexstr = __unkown_reg_value(nibbles)

            return hexstr

        def __set_reg_value(reg: Optional[int], pos: int, nibbles: int, hexval: str) -> None:
            # reg is neither None nor uc reg invalid
            if reg and hexval != __unkown_reg_value(nibbles):
                assert len(hexval) == nibbles

                val = int(hexval, 16)

                if self.ql.arch.endian == QL_ENDIAN.EL:
                    val = __swap_endianess(val)

                self.ql.arch.regs.write(reg, val)

        def __swap_endianess(value: int) -> int:
            length = (value.bit_length() + 7) // 8
            raw = value.to_bytes(length, 'little')

            return int.from_bytes(raw, 'big')


        def handle_exclaim(subcmd: str) -> Reply:
            return REPLY_OK


        def handle_qmark(subcmd: str) -> Reply:
            """Request status.

            @see: https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html
            """

            from unicorn.x86_const import UC_X86_REG_EBP
            from unicorn.x86_const import UC_X86_REG_RBP
            from unicorn.arm_const import UC_ARM_REG_R11
            from unicorn.arm64_const import UC_ARM64_REG_X29
            from unicorn.mips_const import UC_MIPS_REG_INVALID

            arch_uc_bp = {
                QL_ARCH.X86      : UC_X86_REG_EBP,
                QL_ARCH.X8664    : UC_X86_REG_RBP,
                QL_ARCH.ARM      : UC_ARM_REG_R11,
                QL_ARCH.ARM64    : UC_ARM64_REG_X29,
                QL_ARCH.MIPS     : UC_MIPS_REG_INVALID, # skipped
                QL_ARCH.A8086    : UC_X86_REG_EBP,
                QL_ARCH.CORTEX_M : UC_ARM_REG_R11
            }[self.ql.arch.type]

            def __get_reg_idx(ucreg: int) -> int:
                """Get the index of a uc reg whithin the regsmap array.

                Returns: array index where this reg's info is stored, or -1 if not found
                """

                return next((i for i, (regnum, _, _) in enumerate(self.regsmap) if regnum == ucreg), -1)

            def __get_reg_info(ucreg: int) -> str:
                """Retrieve register info and pack it as a pair.
                """

                regnum = __get_reg_idx(ucreg)
                hexval = __get_reg_value(*self.regsmap[regnum])

                return f'{regnum:02x}:{hexval};'

            # mips targets skip this reg info pair
            bp_info = '' if self.ql.arch.type == QL_ARCH.MIPS else __get_reg_info(arch_uc_bp)

            # FIXME: a8086 should use 'esp' and 'eip' here instead of 'sp' and 'ip' set by its arch instance
            sp_info = __get_reg_info(self.ql.arch.regs.uc_sp)
            pc_info = __get_reg_info(self.ql.arch.regs.uc_pc)

            return f'T{SIGTRAP:02x}{bp_info}{sp_info}{pc_info}'


        def handle_c(subcmd: str) -> Reply:
            try:
                self.gdb.resume_emu()
            except UcError as err:
                sigmap = {
                    UC_ERR_READ_UNMAPPED   : SIGSEGV,
                    UC_ERR_WRITE_UNMAPPED  : SIGSEGV,
                    UC_ERR_FETCH_UNMAPPED  : SIGSEGV,
                    UC_ERR_WRITE_PROT      : SIGSEGV,
                    UC_ERR_READ_PROT       : SIGSEGV,
                    UC_ERR_FETCH_PROT      : SIGSEGV,
                    UC_ERR_READ_UNALIGNED  : SIGBUS,
                    UC_ERR_WRITE_UNALIGNED : SIGBUS,
                    UC_ERR_FETCH_UNALIGNED : SIGBUS,
                    UC_ERR_INSN_INVALID    : SIGILL
                }

                # determine signal from uc error; default to SIGTERM
                reply = f'S{sigmap.get(err.errno, SIGTERM):02x}'

            except KeyboardInterrupt:
                # emulation was interrupted with ctrl+c
                reply = f'S{SIGINT:02x}'

            else:
                if self.ql.arch.regs.arch_pc == self.gdb.last_bp:
                    # emulation stopped because it hit a breakpoint
                    reply = f'S{SIGTRAP:02x}'
                else:
                    # emulation has completed successfully
                    reply = f'W{self.ql.os.exit_code:02x}'

            return reply


        def handle_g(subcmd: str) -> Reply:
            # NOTE: in the past the 'g' reply packet for arm included the f0-f7 and fps registers between pc
            # and cpsr, which placed cpsr at index (regnum) 25. as the f-registers became obsolete the cpsr
            # index decreased. in order to maintain backward compatibility with older gdb versions, the gap
            # between pc and cpsr that used to represent the f-registers (96 bits each + 32 bits for fps) is
            # filled with unknown reg values.
            #
            # gdb clients that follow the xml definitions no longer need these placeholders, as registers
            # indices are flexible and may be defined arbitrarily though xml.
            #
            # see: ./xml/arm/arm-fpa.xml

            return ''.join(__get_reg_value(*entry) for entry in self.regsmap)


        def handle_G(subcmd: str) -> Reply:
            data = subcmd

            for reg, pos, nibbles in self.regsmap:
                hexval = data[pos : pos + nibbles]

                __set_reg_value(reg, pos, nibbles, hexval)

            return REPLY_OK


        def handle_H(subcmd: str) -> Reply:
            op = subcmd[0]

            if op in ('c', 'g'):
                return REPLY_OK

            return REPLY_EMPTY


        def handle_k(subcmd: str) -> Reply:
            global killed

            killed = True
            return REPLY_OK


        def handle_m(subcmd: str) -> Reply:
            """Read target memory.
            """

            addr, size = (int(p, 16) for p in subcmd.split(','))

            try:
                data = self.ql.mem.read(addr, size).hex()
            except UcError:
                return 'E14'
            else:
                return data


        def handle_M(subcmd: str) -> Reply:
            """Write target memory.
            """

            addr, data = subcmd.split(',')
            size, data = data.split(':')

            addr = int(addr, 16)
            data = bytes.fromhex(data)

            assert len(data) == size

            try:
                self.ql.mem.write(addr, data)
            except UcError:
                return 'E01'
            else:
                return REPLY_OK


        def handle_p(subcmd: str) -> Reply:
            """Read register value by index.
            """

            idx = int(subcmd, 16)

            return __get_reg_value(*self.regsmap[idx])


        def handle_P(subcmd: str) -> Reply:
            """Write register value by index.
            """

            idx, data = subcmd.split('=')
            idx = int(idx, 16)

            if idx < len(self.regsmap):
                __set_reg_value(*self.regsmap[idx], hexval=data)

                return REPLY_OK

            return 'E00'


        def handle_Q(subcmd: str) -> Reply:
            """General queries.

            @see: https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html
            """

            feature, *data = subcmd.split(':', maxsplit=1)

            supported = (
                'DisableRandomization',
                'NonStop',
                'PassSignals',
                'ProgramSignals',
                'StartNoAckMode'
            )

            if feature == 'StartNoAckMode':
                server.ack_mode = False
                server.log.debug('[noack mode enabled]')

            return REPLY_OK if feature in supported else REPLY_EMPTY


        def handle_D(subcmd: str) -> Reply:
            """Detach.
            """

            return REPLY_OK


        def handle_q(subcmd: str) -> Reply:
            query, *data = subcmd.split(':')

            # qSupported command
            #
            # @see: https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#qSupported

            if query == 'Supported':
                # list of supported features excluding the multithreading-related ones
                common = (
                    'BreakpointCommands+',
                    'ConditionalBreakpoints+',
                    'ConditionalTracepoints+',
                    'DisconnectedTracing+',
                    'EnableDisableTracepoints+',
                    'InstallInTrace+',
                    'QAgent+',
                    'QCatchSyscalls+',
                    'QDisableRandomization+',
                    'QEnvironmentHexEncoded+',
                    'QEnvironmentReset+',
                    'QEnvironmentUnset+',
                    'QNonStop+',
                    'QPassSignals+',
                    'QProgramSignals+',
                    'QSetWorkingDir+',
                    'QStartNoAckMode+',
                    'QStartupWithShell+',
                    'QTBuffer:size+',
                    'StaticTracepoints+',
                    'TraceStateVariables+',
                    'TracepointSource+',
                    # 'augmented-libraries-svr4-read+',
                    'exec-events+',
                    'fork-events+',
                    'hwbreak+',
                    'multiprocess+',
                    'no-resumed+',
                    'qXfer:auxv:read+',
                    'qXfer:exec-file:read+',
                    'qXfer:features:read+',
                    # 'qXfer:libraries-svr4:read+',
                    # 'qXfer:osdata:read+',
                    'qXfer:siginfo:read+',
                    'qXfer:siginfo:write+',
                    'qXfer:statictrace:read+',
                    'qXfer:threads:read+',
                    'qXfer:traceframe-info:read+',
                    'swbreak+',
                    'tracenz+',
                    'vfork-events+'
                )

                # might or might not need for multi thread
                if self.ql.multithread:
                    features = (
                        'PacketSize=47ff',
                        'FastTracepoints+',
                        'QThreadEvents+',
                        'Qbtrace-conf:bts:size+',
                        'Qbtrace-conf:pt:size+',
                        'Qbtrace:bts+',
                        'Qbtrace:off+',
                        'Qbtrace:pt+',
                        'qXfer:btrace-conf:read+',
                        'qXfer:btrace:read+',
                        'vContSupported+'
                    )

                else:
                    features = (
                        'PacketSize=3fff',
                        'qXfer:spu:read+',
                        'qXfer:spu:write+'
                    )

                return ';'.join(common + features)

            elif query == 'Xfer':
                feature, op, annex, params = data
                offset, length = (int(p, 16) for p in params.split(','))

                if feature == 'features' and op == 'read':
                    if annex == r'target.xml':
                        content = self.features.tostring()[offset:offset + length]

                    else:
                        self.ql.log.info(f'{PROMPT} did not expect "{annex}" here')
                        content = ''

                    return f'{"l" if len(content) < length else "m"}{content}'

                elif feature == 'threads' and op == 'read':
                    if not self.ql.baremetal and hasattr(self.ql.os, 'pid'):
                        content = '\r\n'.join((
                            '<threads>',
                            f'<thread id="{self.ql.os.pid}" core="1" name="{self.ql.targetname}"/>',
                            '</threads>'
                        ))

                    else:
                        content = ''

                    return f'l{content}'

                elif feature == 'auxv' and op == 'read':
                    auxv_data = bytearray()

                    if hasattr(self.ql.loader, 'auxv'):
                        nbytes = self.ql.arch.bits // 8

                        auxv_addr = self.ql.loader.auxv + offset
                        null_entry = bytes(nbytes * 2)

                        # keep reading until AUXV.AT_NULL is reached
                        while not auxv_data.endswith(null_entry):
                            auxv_data.extend(self.ql.mem.read(auxv_addr, nbytes))
                            auxv_addr += nbytes

                            auxv_data.extend(self.ql.mem.read(auxv_addr, nbytes))
                            auxv_addr += nbytes

                    return b'l' + auxv_data[:length]

                elif feature == 'exec-file' and op == 'read':
                    return f'l{os.path.abspath(self.ql.path)}'

                elif feature == 'libraries-svr4' and op == 'read':
                    # TODO: this one requires information of loaded libraries which currently not provided
                    # by the ELF loader. until we gather that information, we cannot fulfill this request
                    #
                    # see: https://sourceware.org/gdb/current/onlinedocs/gdb/Library-List-Format-for-SVR4-Targets.html
                    return REPLY_EMPTY

                    # if self.ql.os.type in (QL_OS.LINUX, QL_OS.FREEBSD):
                    #     tag = 'library-list-svr4'
                    #     xml_lib_entries = (f'<library name="{path}" lm="{ubnd:#x}" l_addr="{lbnd:#x}" l_ld="" />' for lbnd, ubnd, _, _, path in self.ql.mem.get_mapinfo() if path)
                    #
                    #     xml = '\r\n'.join((f'<{tag} version="1.0">', *xml_lib_entries, f'</{tag}>'))
                    #
                    #     return f'l{xml}'
                    # else:
                    #     return f''

                elif feature == 'btrace-conf' and op == 'read':
                    return 'E.Btrace not enabled.'

            elif query == 'Attached':
                return REPLY_EMPTY

            elif query == 'C':
                return REPLY_EMPTY

            elif query == 'L':
                return 'M001'

            elif query == 'fThreadInfo':
                return 'm0'

            elif query == 'sThreadInfo':
                return 'l'

            elif query == 'TStatus':
                tsize = __hexstr(0x500000)

                fields = (
                    'T0',
                    'tnotrun:0',
                    'tframes:0',
                    'tcreated:0',
                    f'tfree:{tsize}',
                    f'tsize:{tsize}',
                    'circular:0',
                    'disconn:0',
                    'starttime:0',
                    'stoptime:0',
                    'username:',
                    'notes::'
                )

                return ';'.join(fields)

            elif query in ('TfV', 'TsV', 'TfP', 'TsP'):
                return 'l'

            elif query == 'Symbol':
                return REPLY_OK

            elif query == 'Offsets':
                fields = ('Text=0', 'Data=0', 'Bss=0')

                return ';'.join(fields)

            return REPLY_EMPTY


        def handle_v(subcmd: str) -> Reply:
            if subcmd == 'MustReplyEmpty':
                return REPLY_EMPTY

            elif subcmd.startswith('File'):
                _, op, data = subcmd.split(':', maxsplit=2)
                params = data.split(',')

                if op == 'open':
                    fd = -1

                    # files can be opened only where there is an os that supports filesystem
                    if not self.ql.interpreter and hasattr(self.ql.os, 'path'):
                        path, flags, mode = params

                        path = bytes.fromhex(path).decode(encoding='utf-8')
                        flags = int(flags, 16)
                        mode = int(mode, 16)

                        # try to guess whether this is an emulated path or real one
                        if path.startswith(os.path.abspath(self.ql.rootfs)):
                            host_path = path
                        else:
                            host_path = self.ql.os.path.virtual_to_host_path(path)

                        self.ql.log.debug(f'{PROMPT} target file: {host_path}')

                        if os.path.exists(host_path) and not path.startswith(r'/proc'):
                            fd = os.open(host_path, flags, mode)

                    return f'F{fd:x}'

                elif op == 'pread':
                    fd, count, offset = (int(p, 16) for p in params)

                    data = os.pread(fd, count, offset)

                    return f'F{len(data):x};'.encode() + data

                elif op == 'close':
                    fd, *_ = params
                    fd = int(fd, 16)

                    os.close(fd)
                    return 'F0'

                return REPLY_EMPTY

            elif subcmd.startswith('Kill'):
                return handle_k('')

            elif subcmd.startswith('Cont'):
                # remove 'Cont' prefix
                data = subcmd[len('Cont'):]

                if data == '?':
                    # note 't' and 'r' are currently not supported
                    return ';'.join(('vCont', 'c', 'C', 's', 'S'))

                elif data.startswith(';'):
                    groups = subcmd.split(';')[1:]

                    for grp in groups:
                        cmd, tid = grp.split(':', maxsplit=1)

                        if cmd in ('c', f'C{SIGTRAP:02x}'):
                            return handle_c('')

                        elif cmd in ('s', f'S{SIGTRAP:02x}'):
                            return handle_s('')

                        # FIXME: not sure how to handle multiple command
                        # groups, so handling just the first one
                        break

            return REPLY_EMPTY


        def handle_s(subcmd: str) -> Reply:
            """Perform a single step.
            """

            # BUG: a known unicorn caching issue causes it to emulate more
            # steps than requestes. until that issue is fixed, single stepping
            # is essentially broken.
            #
            # @see: https://github.com/unicorn-engine/unicorn/issues/1606

            self.gdb.resume_emu(steps=1)

            return f'S{SIGTRAP:02x}'


        def handle_X(subcmd: str) -> Reply:
            """Write data to memory.
            """

            params, data = subcmd.split(':', maxsplit=1)
            addr, length = (int(p, 16) for p in params.split(','))

            if length != len(data):
                return 'E00'

            try:
                if data:
                    self.ql.mem.write(addr, data.encode(ENCODING))
            except UcError:
                return 'E01'
            else:
                return REPLY_OK


        def handle_Z(subcmd: str) -> Reply:
            """Insert breakpoints or watchpoints.
            """

            params, *conds = subcmd.split(';')
            type, addr, kind = (int(p, 16) for p in params.split(','))

            # type values:
            #   0 = sw breakpoint
            #   1 = hw breakpoint
            #   2 = write watchpoint
            #   3 = read watchpoint
            #   4 = access watchpoint

            if type == 0:
                self.gdb.bp_insert(addr)
                return REPLY_OK

            return REPLY_EMPTY


        def handle_z(subcmd: str) -> Reply:
            """Remove breakpoints or watchpoints.
            """

            type, addr, kind = (int(p, 16) for p in subcmd.split(','))

            if type == 0:
                try:
                    self.gdb.bp_remove(addr)
                except ValueError:
                    return 'E22'
                else:
                    return REPLY_OK

            return REPLY_EMPTY


        handlers = {
            '!': handle_exclaim,
            '?': handle_qmark,
            'c': handle_c,
            'C': handle_c,  # this is intentional; not a typo
            'D': handle_D,
            'g': handle_g,
            'G': handle_G,
            'H': handle_H,
            'k': handle_k,
            'm': handle_m,
            'M': handle_M,
            'p': handle_p,
            'P': handle_P,
            'q': handle_q,
            'Q': handle_Q,
            's': handle_s,
            'v': handle_v,
            'X': handle_X,
            'Z': handle_Z,
            'z': handle_z
        }

        # main server loop
        for packet in server.readpackets():
            if server.ack_mode:
                server.send(REPLY_ACK, raw=True)
                server.log.debug('[sent ack]')

            cmd, subcmd = packet[0], packet[1:]
            handler = handlers.get(f'{cmd:c}')

            if handler:
                reply = handler(subcmd.decode(ENCODING))
                server.send(reply)

                if killed:
                    break
            else:
                self.ql.log.info(f'{PROMPT} command not supported')
                server.send(REPLY_EMPTY)

        server.close()


class GdbSerialConn:
    """Serial connection handler.
    """

    # default recieve buffer size
    BUFSIZE = 4096

    def __init__(self, ipaddr: str, port: int, logger: Logger) -> None:
        """Create a new gdb serial connection handler.

        Args:
            ipaddr : ip address to bind the socket to
            port   : port number to listen on
            logger : logger instance to use
        """

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ipaddr, port))
        sock.listen()

        self.log = logger
        self.log.info(f'{PROMPT} listening on {ipaddr}:{port:d}')

        client, _ = sock.accept()

        self.sock = sock
        self.client = client

        # ack mode should be turend on by default
        self.ack_mode = True

    def close(self):
        """Close the gdb serial connection handler and release its resources.
        """

        self.client.close()
        self.sock.close()

    def readpackets(self) -> Iterator[bytes]:
        """Iterate through incoming packets in an active connection until
        it is terminated.
        """

        pattern = re.compile(br'^\$(?P<data>[^#]*)#(?P<checksum>[0-9a-fA-F]{2})')
        buffer = bytearray()

        while True:
            try:
                incoming = self.client.recv(self.BUFSIZE)
            except ConnectionError:
                break

            # remote connection closed
            if not incoming:
                break

            buffer += incoming

            # discard incoming acks
            if buffer[0:1] == REPLY_ACK:
                del buffer[0]

            packet = pattern.match(buffer)

            # if there is no match, the rest of the packet might be missing
            if not packet:
                continue

            data = packet['data']
            read_csum = int(packet['checksum'], 16)
            calc_csum = GdbSerialConn.checksum(data)

            if read_csum != calc_csum:
                raise IOError(f'checksum error: expected {calc_csum:02x} but got {read_csum:02x}')

            # follow gdbserver debug output format
            self.log.debug(f'getpkt ("{GdbSerialConn.__printable_prefix(data).decode(ENCODING)}");')

            data = GdbSerialConn.rle_decode(data)
            data = GdbSerialConn.unescape(data)

            del buffer[:packet.endpos]
            yield data

    def send(self, data: Reply, raw: bool = False) -> None:
        """Send out a packet.

        Args:
            data : data to send out
            raw : whether to encapsulate the data with standard header and
            checksum or leave it raw
        """

        if type(data) is str:
            data = data.encode(ENCODING)

        assert type(data) is bytes

        if raw:
            packet = data
        else:
            data = GdbSerialConn.escape(data)
            data = GdbSerialConn.rle_encode(data)

            packet = b'$' + data + b'#' + f'{GdbSerialConn.checksum(data):02x}'.encode()

        # follow gdbserver debug output format
        self.log.debug(f'putpkt ("{GdbSerialConn.__printable_prefix(data).decode(ENCODING)}");')

        self.client.sendall(packet)

    @staticmethod
    def __printable_prefix(data: bytes) -> bytes:
        """Follow the gnu gdbserver debug message format which emits only the
        printable prefix of a packet (either incoming or outgoing). Note that
        despite of its name, it includes non-printable characters as well.

        Args:
            data : packet data to scan

        Returns: a prefix of the specified data buffer
        """

        def __isascii(ch: int) -> bool:
            return 0 < ch < 0x80

        if data.isascii():
            return data

        return data[:next((i for i, ch in enumerate(data) if not __isascii(ch)), len(data))]

    @staticmethod
    def escape(data: bytes) -> bytes:
        """Escape data according to gdb protocol escaping rules.
        """

        def __repl(m: 're.Match[bytes]') -> bytes:
            ch, *_ = m[0]

            return bytes([ord('}'), ch ^ 0x20])

        return re.sub(br'[*#$}]', __repl, data, flags=re.DOTALL)

    @staticmethod
    def unescape(data: bytes) -> bytes:
        """Unescape data according to gdb protocol escaping rules.
        """

        def __repl(m: 're.Match[bytes]') -> bytes:
            _, ch = m[0]

            return bytes([ch ^ 0x20])

        return re.sub(br'}.', __repl, data, flags=re.DOTALL)

    @staticmethod
    def rle_encode(data: bytes) -> bytes:
        """Compact data using run-length encoding.
        """

        def __simple_rep(b: bytes, times: int) -> bytes:
            return b * times

        def __runlen_rep(b: bytes, times: int) -> bytes:
            return b + b'*' + bytes([times - 1 + 29])

        def __encode_rep(b: bytes, times: int) -> bytes:
            assert times > 0, 'time should be a positive value'

            if 0 < times < 4:
                return __simple_rep(b, times)

            elif times == 6+1 or times == 7+1:
                return __runlen_rep(b, 6) + __encode_rep(b, times - 6)

            else:
                return __runlen_rep(b, times)

        def __repl(m: 're.Match[bytes]') -> bytes:
            repetition = m[0]

            ch = repetition[0:1]
            times = len(repetition)

            return __encode_rep(ch, times)

        return re.sub(br'(.)\1{3,96}', __repl, data, flags=re.DOTALL)

    @staticmethod
    def rle_decode(data: bytes) -> bytes:
        """Expand run-length encoded data.
        """

        def __repl(m: 're.Match[bytes]') -> bytes:
            ch, _, times = m[0]

            return bytes([ch] * (1 + times - 29))

        return re.sub(br'.\*.', __repl, data, flags=re.DOTALL)

    @staticmethod
    def checksum(data: bytes) -> int:
        return sum(data) & 0xff
