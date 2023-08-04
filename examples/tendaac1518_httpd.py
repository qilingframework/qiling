#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# Setup:
# - Unpack firmware rootfs (assumed hereby: 'rootfs/tendaac15')
#   - AC15 firmware may be acquired from https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip
# - Refresh webroot directory:
#   - Enter the 'squashfs-root' directory
#   - rm -rf webroot
#   - mv webroot_ro webroot
# - Set network device
#   - Open "qiling/profiles/linux.ql"
#   - Set 'ifrname_override' to your hosting system network device name (e.g. eth0, lo, etc.)
#
# Run:
#  $ PYTHONPATH=/path/to/qiling ROOTFS=/path/to/tenda_rootfs python3 tendaac1518_httpd.py

import os
import socket
import threading

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE


# user may set 'ROOTFS' environment variable to use as rootfs
ROOTFS = os.environ.get('ROOTFS', r'./rootfs/tendaac15')


def nvram_listener():
    server_address = fr'{ROOTFS}/var/cfm_socket'

    if os.path.exists(server_address):
        os.unlink(server_address)

    # Create UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(server_address)
    sock.listen(1)

    data = bytearray()

    with open('cfm_socket.log', 'wb') as ofile:
        while True:
            connection, _ = sock.accept()

            try:
                while True:
                    data += connection.recv(1024)

                    if b'lan.webiplansslen' not in data:
                        break

                    connection.send(b'192.168.170.169')

                    ofile.write(data)
                    data.clear()
            finally:
                connection.close()


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)
    ql.add_fs_mapper(r'/dev/urandom', r'/dev/urandom')

    # $ gdb-multiarch -q rootfs/tendaac15/bin/httpd
    # gdb> set remotetimeout 100
    # gdb> target remote localhost:9999

    if ql.debugger:
        def __vfork(ql: Qiling):
            return 0

        ql.os.set_syscall('vfork', __vfork)

    ql.run()


if __name__ == '__main__':
    nvram_listener_therad = threading.Thread(target=nvram_listener, daemon=True)
    nvram_listener_therad.start()

    my_sandbox([fr'{ROOTFS}/bin/httpd'], ROOTFS)
