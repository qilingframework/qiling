#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)


# 1. Download AC15 Firmware from https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip
# 2. unzip
# 3. binwalk -e US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin
# 4. locate squashfs-root
# 5. rm -rf webroot && mv webroot_ro webroot
#
# notes: we are using rootfs in this example, so rootfs = squashfs-root
#

import http.client
import json
import os
import socket
import sys
import time
import threading
import unittest

sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE


class ELFTest(unittest.TestCase):

    def test_tenda_ac15_arm(self):

        def nvram_listener():
            server_address = '../examples/rootfs/arm_tendaac15/var/cfm_socket'

            try:
                os.unlink(server_address)
            except OSError:
                if os.path.exists(server_address):
                    raise

            # Create UDS socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(server_address)
            sock.listen(1)

            data = bytearray()

            while True:
                connection, _ = sock.accept()

                try:
                    while True:
                        data += connection.recv(1024)

                        if b"lan.webiplansslen" in data:
                            connection.send(b'192.168.170.169')
                        else:
                            break

                        data.clear()
                finally:
                    connection.close()

        def patcher(ql: Qiling):
            br0_addr = ql.mem.search(b'br0\x00')

            for addr in br0_addr:
                ql.mem.write(addr, b'lo\x00')

        def my_tenda():
            ql = Qiling(["../examples/rootfs/arm_tendaac15/bin/httpd"], "../examples/rootfs/arm_tendaac15", verbose=QL_VERBOSE.DEBUG)
            ql.add_fs_mapper("/dev/urandom", "/dev/urandom")
            ql.hook_address(patcher, ql.loader.elf_entry)
            ql.run()

        if __name__ == "__main__":
            threads = [
                threading.Thread(target=nvram_listener, daemon=True),
                threading.Thread(target=my_tenda, daemon=True)
            ]

            for th in threads:
                th.start()

            time.sleep(5)

            headers = {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            web_data = {
                'page': 'CCCCAAAA',
                'entrys': 'sync'
            }

            json_data = json.dumps(web_data)
            conn = http.client.HTTPConnection('localhost', 8080, timeout=10)
            conn.request('POST', '/goform/addressNat', json_data, headers)
            response = conn.getresponse()

            self.assertIn(b"Please update your documents to reflect the new location.", response.read())


if __name__ == "__main__":
    unittest.main()
