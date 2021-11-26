
import sys, os, socket, threading, requests

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE

def test_http_elf_linux_arm():
    ql = Qiling(["../examples/rootfs/arm_linux/bin/vshttpd","-p","20011","-r","www"], "../examples/rootfs/arm_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)    
    ql.run()


if __name__ == "__main__":
    # test_http_elf_linux_arm_therad = threading.Thread(target=test_http_elf_linux_arm, daemon=True)
    # test_http_elf_linux_arm_therad.start()


    # r = requests.get('https://localhost:20011/')
    # print(r.text)[:200]
    test_http_elf_linux_arm()