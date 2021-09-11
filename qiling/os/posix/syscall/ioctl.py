#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct

from qiling import Qiling
from qiling.os.posix.filestruct import ql_socket

def ql_syscall_ioctl(ql: Qiling, fd: int, cmd: int, arg: int):
    TCGETS = 0x5401
    TIOCGWINSZ = 0x5413
    TIOCSWINSZ = 0x5414
    TCSETSW = 0x5403

    SIOCGIFADDR = 0x8915
    SIOCGIFNETMASK = 0x891b

    def ioctl(_fd: int, _cmd: int, _arg: int):
        # Stub for 'ioctl' syscall
        # Return the list of element to pack back depending on target ioctl
        #If the ioctl is disallowed, return False

        # list of (fd, cmd), None value for wildcard
        ioctl_allowed = (
            (0, TCGETS),
            (0, TIOCGWINSZ),
            (0, TIOCSWINSZ),
            (1, TCGETS),
            (1, TIOCGWINSZ),
            (1, TIOCSWINSZ)
        )

        # list of (fd, cmd), None value for wildcard
        ioctl_disallowed = (
            (2, TCGETS),
            (0, TCSETSW)
        )

        allowed = False
        disallowed = False

        for test in ((_fd, _cmd), (None, _cmd), (_fd, None)):
            if test in ioctl_allowed:
                allowed = True

            if test in ioctl_disallowed:
                disallowed = True

        if allowed and disallowed:
            raise ValueError(f'ioctl: (fd: {_fd:x}, cmd: {_cmd:x}) is both allowed and disallowed at the same time')

        if not allowed and not disallowed:
            raise KeyError(f'Unknown ioctl (fd: {_fd:x}, cmd: {_cmd:x})')

        if allowed:
            if _cmd == TCGETS:
                return 0, 0, 0, 0

            elif _cmd == TIOCGWINSZ:
                # struct winsize
                # {
                #   unsigned short ws_row;	/* rows, in characters */
                #   unsigned short ws_col;	/* columns, in characters */
                #   unsigned short ws_xpixel;	/* horizontal size, pixels */
                #   unsigned short ws_ypixel;	/* vertical size, pixels */
                # };
                return 1000, 360, 1000, 1000

            elif _cmd == TIOCSWINSZ:
                # Ignore it
                return None

            else:
                raise NotImplementedError

        if disallowed:
            return None

    if isinstance(ql.os.fd[fd], ql_socket) and cmd in (SIOCGIFADDR, SIOCGIFNETMASK):
        try:
            tmp_arg = ql.mem.read(arg, 64)
            ql.log.debug(f'query network card : {tmp_arg:s}')

            data = ql.os.fd[fd].ioctl(cmd, bytes(tmp_arg))
            ql.mem.write(arg, data)
        except:
            regreturn = -1
        else:
            regreturn = 0

    else:
        try:
            info = ioctl(fd, cmd, arg)

            if info is not None:
                if cmd == TCGETS:
                    data = struct.pack("BBBB", *info)
                    ql.mem.write(arg, data)

                elif cmd == TIOCGWINSZ:
                    data = struct.pack("HHHH", *info)
                    ql.mem.write(arg, data)
        except:
            regreturn = -1
        else:
            regreturn = 0

    # ql.log.debug(f'ioctl({ioctl_fd:#x}, {ioctl_cmd:#x}, {ioctl_arg:#x}) = {regreturn}')

    return regreturn
