[LOADER]
slide           = 0x0000000000000000
dyld_slide      = 0x0000000500000000


[OS64]
stack_address = 0x7ffcf0000000
stack_size = 0x19a00000
vmmap_trap_address = 0x4000000f4000
mmap_address = 0x7ffbf0100000


[SHELLCODER]
# ram_size 0xa00000 is 10MB
ram_size = 0xa00000
entry_point = 0x1000000


[KERNEL]
uid = 1000
gid = 1000
pid = 1996


[LOG]
# log directory output
# usage: dir = qlog
dir =
# split log file, use with multithread
split = False


[MISC]
# append string into different logs
# maily for multiple times Ql run with one file
# usage: append = test1
append =