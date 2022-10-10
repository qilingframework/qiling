import sys
from types import FrameType
sys.path.append('..')

from tests.test_elf import ELFTest
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.r2 import R2

def test_elf_linux_arm():
    def my_puts(ql: Qiling):
        params = ql.os.resolve_fcall_params(ELFTest.PARAMS_PUTS)
        print(f'puts("{params["s"]}")')
        # all_mem = ql.mem.save()
        # for lbound, ubound, perm, _, _, _data in ql.mem.map_info:
        #   print(f"{lbound:#x} - {ubound:#x} {ubound - lbound:#x} {len(_data):#x} {perm:#x}")
        # print()
        # ql.mem.restore(all_mem)

    ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_stat64"], "../examples/rootfs/arm_linux", verbose=QL_VERBOSE.DEBUG)
    ql.os.set_api('puts', my_puts)
    ql.run()
    del ql

def fn(frame: FrameType, msg, arg):
    if msg == 'return':
      print("Return: ", arg)
      return
    if msg != 'call':  return
    # Filter as appropriate
    if 'memory' not in frame.f_code.co_filename: return
    if '<' in frame.f_code.co_name: return
    caller = frame.f_back.f_code.co_name
    print("Called ", frame.f_code.co_name, "from ", caller)
    for i in range(frame.f_code.co_argcount):
        name = frame.f_code.co_varnames[i]
        var = frame.f_locals[name]
        if isinstance(var, (bytes, bytearray)):
          var = f'{type(var)} len {len(var)}'
        print("    Argument", name, "is", var)

sys.settrace(fn)

def unmap_hook(ql: "Qiling", access: int, addr: int, size: int, value: int):
    print(f"Unmapped memory access at {addr:#x} - {addr + size:#x} with {value:#x} in type {access}")

def mem_cmp_hook(ql: "Qiling", addr: int, size: int):
  mapinfo = ql.mem.map_info
  for i, mem_region in enumerate(ql.uc.mem_regions()):
      assert (mapinfo[i][0], mapinfo[i][1] - 1, mapinfo[i][2]) == mem_region
      uc_mem = ql.mem.read(mem_region[0], mem_region[1] - mem_region[0] + 1)
      data = ql.mem.map_info[i][5]
      if uc_mem == data: continue
      print(f"Memory region {i} {mem_region[0]:#x} - {mem_region[1]:#x} not equal to map_info from {addr:#x}")
      for line in ql.mem.get_formatted_mapinfo():
        print(line)
      with open("mem.bin", "wb") as f:
        f.write(uc_mem)
      with open("map.bin", "wb") as f:
        f.write(data)
      assert False

def addr_hook(ql: "Qiling"):
  mapinfo = ql.mem.map_info
  for i, mem_region in enumerate(ql.uc.mem_regions()):
    if i != 8: continue
    uc_mem = ql.mem.read(mem_region[0], mem_region[1] - mem_region[0] + 1)
    with open('right.bin', 'wb') as f:
      f.write(uc_mem)
  
if __name__ == '__main__':
  # from tests.test_shellcode import X8664_LIN
  env = {'LD_DEBUG': 'all'}
  # ql = Qiling(rootfs="rootfs/x8664_linux", code=X8664_LIN, archtype="x8664", ostype="linux", verbose=QL_VERBOSE.DEBUG)
  # ql = Qiling(["rootfs/x86_windows/bin/x86_hello.exe"], "rootfs/x86_windows")
  # ql = Qiling(["rootfs/arm_linux/bin/arm_hello_static"], "rootfs/arm_linux", verbose=QL_VERBOSE.DISASM)
  # ql = Qiling(["rootfs/arm_linux/bin/arm_hello"], "rootfs/arm_linux", env=env, verbose=QL_VERBOSE.DEBUG)
  ql = Qiling(["rootfs/x86_linux/bin/x86_hello"], "rootfs/x86_linux", verbose=QL_VERBOSE.DEBUG)
  # ql.hook_mem_unmapped(unmap_hook)
  # ql.hook_code(mem_cmp_hook)
  # mprot_addr = 0x047d4824
  # ql.hook_address(addr_hook, mprot_addr)
  # ql.debugger = 'qdb'
  # ql = Qiling(["rootfs/x8664_linux/bin/testcwd"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
  for line in ql.mem.get_formatted_mapinfo():
    print(line)
  ql.run()
  # test_elf_linux_arm()
