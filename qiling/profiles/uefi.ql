[DXE]
heap_address	= 0x04000000
heap_size		= 0x01000000
stack_address	= 0x05000000
stack_size		= 0x00080000
image_address 	= 0x00100000

[SMM]
smram_base		= 0x70000000
smram_size		= 0x08000000
heap_address	= 0x77000000
heap_size		= 0x00800000
# allocated somewhere in smram; address stored in gSmmInitStack
stack_address	= 0x77ff0000
# PcdCpuSmmStackSize
stack_size		= 0x00010000
image_address	= 0x70100000

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

[MISC]
current_path = /
