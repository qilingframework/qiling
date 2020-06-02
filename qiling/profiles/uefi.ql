[OS64]
heap_address = 0x500000000
heap_size = 0x5000000
stack_address = 0x7ffffffde000
stack_size = 0x40000
image_address  = 0x400000
dll_address = 0x7ffff0000000
entry_point = 0x140000000


[OS32]
heap_address = 0x5000000
heap_size = 0x5000000
stack_address = 0xfffdd000
stack_size = 0x21000
image_address  = 0x400000
dll_address  = 0x10000000
entry_point = 0x40000  


[GUID]
# EFI_GLOBAL_VARIABLE
configuration_table = 7739f24c-93d7-11d4-9a3a-0090273fc14d
data1 = 0x7739f24c
data2 = 0x93d7
data3 = 0x11d4
data4 = [0x9a, 0x3a, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d]
vendortable = 0

[LOADED_IMAGE_PROTOCOL]
guid = 5b1b31a1-9562-11d2-8e3f-00a0c969723b
revision = 0x1000

[KERNEL]
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