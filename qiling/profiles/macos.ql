[LOADER]
slide           = 0x0000000000000000
dyld_slide      = 0x0000000500000000


[OS64]
stack_address = 0x7ffcf0000000
stack_size = 0x19a00000
vmmap_trap_address = 0x4000000f4000
mmap_address = 0x7ffbf0100000
heap_address = 0x500000000
heap_size = 0x5000000


[CODE]
# ram_size 0xa00000 is 10MB
ram_size = 0xa00000
entry_point = 0x1000000


[KERNEL]
uid = 1000
gid = 1000
pid = 1996


[MISC]
current_path = /


[NETWORK]
# To use IPv6 or not, to avoid binary double bind. ipv6 and ipv4 bind the same port at the same time
ipv6 = False
# Bind to localhost
bindtolocalhost = True