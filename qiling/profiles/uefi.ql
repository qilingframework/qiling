[OS64]
heap_address	= 0x78000000
heap_size		= 0x02000000
stack_address	= 0x77800000
stack_size		= 0x00800000
image_address 	= 0x00100000

[OS32]
heap_address	= 0x78000000
heap_size		= 0x02000000
stack_address	= 0x77800000
stack_size		= 0x00800000
image_address 	= 0x00100000

[SMRAM]
heap_address	= 0x7A000000
heap_size		= 0x02000000
# stack_address	= 0x77800000
# stack_size	= 0x00800000
# image_address = 0x77000000

[HOB_LIST]
# EFI_GLOBAL_VARIABLE
Guid = 7739f24c-93d7-11d4-9a3a-0090273fc14d
# the HOB list must end with an entry whose HobType is FFFF
TableData = FFFF000000000000

[DXE_SERVICE_TABLE]
Guid = 05ad34ba-6f02-4214-952e-4da0398e2bb9

[SMM_RUNTIME_SERVICES_TABLE]
Guid = 395c33fe-287f-413e-a055-8088c0e1d43e

[LOADED_IMAGE_PROTOCOL]
Guid = 5b1b31a1-9562-11d2-8e3f-00a0c969723b

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
current_path = /