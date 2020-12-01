from qiling.const import QL_INTERCEPT
from qiling import Qiling
import curses

def input_index(ql: Qiling):
    return ql.unpack16(ql.mem.read(0x81ba, 2))

def target(ql: Qiling):
    return ql.unpack16(ql.mem.read(0x81bb, 2))

def stop(ql, b, c):
    ql.emu_stop()

def find_once(ql: Qiling, ch):
    old = target(ql)
    ql.reg.al = ch
    h1 = ql.hook_code(stop, begin=0x8004, end=0x8004) # Fail
    h2 = ql.hook_code(stop, begin=0x7fea, end=0x7fea) # Success
    h3 = ql.hook_code(stop, begin=0x7e37, end=0x7e37)
    ql.run(begin=0x7e3d)
    ql.hook_del(h1)
    ql.hook_del(h2)
    ql.hook_del(h3)
    new = target(ql)
    if new > old:
        return True
    else:
        return False

def find_next(ql: Qiling):
    ctx = ql.save()
    ctx_succ = None
    results = []
    for i in range(0x61, 0x7a + 1):
        if find_once(ql, i):
            results.append(i)
            ctx_succ = ql.save()
        ql.restore(ctx)
    if ctx_succ is None:
        ql.nprint("Can't find any suitbale result.")
        return None
    ql.restore(ctx_succ)
    return results

def print_flags(results):
    def _impl(fl, idx, results):
        if idx == len(results):
            print(f"flag: {fl}")
        else:
            for ch in results[idx]:
                _impl(fl + ch, idx + 1, results)
    curses.echo()
    curses.nocbreak()
    curses.endwin()
    return _impl("", 0, results)

def main():
    flag = ""
    results = []
    ql = Qiling(["rootfs/8086/dos/hfs.img"], rootfs="rootfs/8086", console=False, log_dir=".", output="off")
    h = ql.hook_code(stop, begin=0x7e3b, end=0x7e3b)
    ql.run()
    ql.hook_del(h)
    ql.reg.ip = 0x7e3d
    for i in range(9):
        r = find_next(ql)
        if r is None:
            ql.nprint("Fail to crack.")
            return
        else:
            r = list(map(lambda x: chr(x), r))
            ql.nprint(f"Get {r}")
            results.append(r)
    print_flags(results)

if __name__ == "__main__":
    main()
