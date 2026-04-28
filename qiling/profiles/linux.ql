[CODE]
# ram_size 0xa00000 is 10MB
ram_size = 0xa00000
load_address = 0x1000000
entry_point = 0x1000000


[OS64]
stack_address = 0x7ffffffd0000
stack_size = 0x30000
load_address = 0x555555554000
interp_address = 0x7ffff7dd5000
mmap_address = 0x7fffb7dd6000
vsyscall_address = 0xffffffffff600000


[OS32]
stack_address = 0x7ff0d000
stack_size = 0x30000
load_address = 0x56555000
interp_address = 0x047ba000
# used to be 0x90000000, but changed to comply with MIPS reserved areas
mmap_address = 0x01000000


[KERNEL]
uid = 1000
gid = 1000
pid = 1996


[MISC]
current_path = /


[NETWORK]
# override the ifr_name field in ifreq structures to match the hosts network interface name.
# that fixes certain socket ioctl errors where the requested interface name does not match the
# one on the host. comment out to avoid override
ifrname_override = eth0

# To use IPv6 or not, to avoid binary double bind. ipv6 and ipv4 bind the same port at the same time
bindtolocalhost = True
# Bind to localhost
ipv6 = False
