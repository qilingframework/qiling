#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)


from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_ioctl(ql, ioctl_fd, ioctl_cmd, ioctl_arg, *args, **kw):
    TCGETS = 0x5401
    TIOCGWINSZ = 0x5413
    TIOCSWINSZ = 0x5414
    TCSETSW = 0x5403

    SIOCGIFADDR = 0x8915
    SIOCGIFNETMASK = 0x891b


    def ioctl(fd, cmd, arg):
    # Stub for 'ioctl' syscall
    # Return the list of element to pack back depending on target ioctl
    #If the ioctl is disallowed, return False

        ioctl_allowed = None # list of (fd, cmd), None value for wildcard
        ioctl_disallowed = None # list of (fd, cmd), None value for wildcard

        ioctl_allowed = [
        (0, TCGETS),
        (0, TIOCGWINSZ),
        (0, TIOCSWINSZ),
        (1, TCGETS),
        (1, TIOCGWINSZ),
        (1, TIOCSWINSZ),
        ]

        ioctl_disallowed = [
        (2, TCGETS),
        (0, TCSETSW),
        ]

        allowed = False
        disallowed = False

        for test in [(fd, cmd), (None, cmd), (fd, None)]:
            if test in ioctl_allowed:
                allowed = True
            if test in ioctl_disallowed:
                disallowed = True
        if allowed and disallowed:
            raise ValueError("fd: %x, cmd: %x is allowed and disallowed" % (fd, cmd))

        if allowed:

            if cmd == TCGETS:
                return 0, 0, 0, 0
            elif cmd == TIOCGWINSZ:
            # struct winsize
            # {
            #   unsigned short ws_row;	/* rows, in characters */
            #   unsigned short ws_col;	/* columns, in characters */
            #   unsigned short ws_xpixel;	/* horizontal size, pixels */
            #   unsigned short ws_ypixel;	/* vertical size, pixels */
            # };
                return 1000, 360, 1000, 1000
            elif cmd == TIOCSWINSZ:
                # Ignore it
                return
            else:
                raise RuntimeError("Not implemented")
        elif disallowed:
            return False
        else:
            raise KeyError("Unknown ioctl fd:%x cmd:%x" % (fd, cmd))

    if isinstance(ql.os.file_des[ioctl_fd], ql_socket) and (ioctl_cmd == SIOCGIFADDR or ioctl_cmd == SIOCGIFNETMASK):
        try:
            tmp_arg = ql.mem.read(ioctl_arg, 64)
            ql.dprint(D_INFO, "[+] query network card : %s" % tmp_arg)
            data = ql.os.file_des[ioctl_fd].ioctl(ioctl_cmd, bytes(tmp_arg))
            ql.mem.write(ioctl_arg, data)
            regreturn = 0
        except:
            regreturn = -1
    else:
        try:
            info = ioctl(ioctl_fd, ioctl_cmd, ioctl_arg)
            if ioctl_cmd == TCGETS:
                data = struct.pack("BBBB", *info)
                ql.mem.write(ioctl_arg, data)
            elif ioctl_cmd == TIOCGWINSZ:
                data = struct.pack("HHHH", *info)
                ql.mem.write(ioctl_arg, data)
            else:
                return
            regreturn = 0
        except :
            regreturn = -1

    ql.nprint("ioctl(0x%x, 0x%x, 0x%x) = %d" % (ioctl_fd, ioctl_cmd, ioctl_arg, regreturn))
    ql.os.definesyscall_return(regreturn)
