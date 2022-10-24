from functools import wraps
from unicorn.unicorn_const import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC


def wrap_aaa(fun):
    @wraps(fun)
    def wrapper(self, *args, **kwargs):
        if self.analyzed is False:
            self._cmd("aaa")
            self.analyzed = True
        return fun(self, *args, **kwargs)
    return wrapper

def wrap_arg_addr(fun):
    @wraps(fun)
    def wrapper(self, *args, **kwargs):
        if not args:  # just return same func if not args
            return fun(self, *args, **kwargs)
        # parse first argument to address
        target = args[0]
        if isinstance(target, int):  # first arg is address
            addr = target
        elif isinstance(target, str):  # first arg is name
            addr = self.where(args[0])
        else:  # isinstance(target, R2Data)
            addr = target.start_ea
        newargs = (addr,) + args[1:]
        return fun(self, *newargs, **kwargs)
    return wrapper

def uc2perm(ps: int) -> str:
    perms_d = {
        UC_PROT_READ  : 'r',
        UC_PROT_WRITE : 'w',
        UC_PROT_EXEC  : 'x'
    }

    return ''.join(val if idx & ps else '-' for idx, val in perms_d.items())

def assert_mem_equal(ql: 'R2Qiling'):
    map_info = ql.mem.map_info
    mem_regions = list(ql.uc.mem_regions())
    assert len(map_info) == len(mem_regions), f'len: map_info={len(map_info)} != mem_regions={len(mem_regions)}'
    for i, mem_region in enumerate(mem_regions):
        s, e, p, _, _, data = map_info[i]
        if (s, e - 1, p) != mem_region:
            ql.log.error('map_info:')
            print('\n'.join(ql.mem.get_formatted_mapinfo()))
            ql.log.error('uc.mem_regions:')
            print('\n'.join(f'{s:010x} - {e:010x}   {uc2perm(p)}' for (s, e, p) in mem_regions))
            raise AssertionError(f'(start, end, perm): map_info={(s, e - 1, p)} != mem_region={mem_region}')
        uc_mem = ql.mem.read(mem_region[0], mem_region[1] - mem_region[0] + 1)
        assert len(data) == len(uc_mem), f'len of {i} mem: map_info={len(data)} != mem_region={len(uc_mem)}'
        assert data == uc_mem, f'Memory region {i} {mem_region[0]:#x} - {mem_region[1]:#x} not equal to map_info[{i}]'
