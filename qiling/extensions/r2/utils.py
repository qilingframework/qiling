from functools import wraps


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
