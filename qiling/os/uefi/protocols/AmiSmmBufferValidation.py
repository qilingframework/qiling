from qiling.os.const import *
from ..fncc import *
from ..ProcessorBind import *

# Based on AMI codebase found on https://github.com/marktsai0316/RAIDOOBMODULE
# @see: AmiModulePkg/Include/Protocol/AmiSmmBufferValidation.h

AMI_SMM_VALIDATE_MEMORY_BUFFER	= FUNCPTR(PTR(VOID), UINTN)
AMI_SMM_VALIDATE_MMIO_BUFFER	= FUNCPTR(PTR(VOID), UINTN)
AMI_SMM_VALIDATE_SMRAM_BUFFER	= FUNCPTR(PTR(VOID), UINTN)

class AMI_SMM_BUFFER_VALIDATION_PROTOCOL(STRUCT):
	_fields_ = [
		('ValidateMemoryBuffer',AMI_SMM_VALIDATE_MEMORY_BUFFER),
 		('ValidateMmioBuffer',	AMI_SMM_VALIDATE_MMIO_BUFFER),
 		('ValidateSmramBuffer',	AMI_SMM_VALIDATE_SMRAM_BUFFER)
	]

@dxeapi(params = {
	"Buffer"	: POINTER,	# PTR(VOID)
	"BufferSize": INT		# UINTN
})
def hook_ValidateMemoryBuffer(ql, address, params):
	# TODO: see whether [Buffer, Buffer+BufferSize] is outside of SMRAM (return either EFI_SUCCESS or EFI_ACCESS_DENIED)
	pass

@dxeapi(params = {
	"Buffer"	: POINTER,	# PTR(VOID)
	"BufferSize": INT		# UINTN
})
def hook_ValidateMmioBuffer(ql, address, params):
	pass

@dxeapi(params = {
	"Buffer"	: POINTER,	# PTR(VOID)
	"BufferSize": INT		# UINTN
})
def hook_ValidateSmramBuffer(ql, address, params):
	# TODO: see whether [Buffer, Buffer+BufferSize] is whithin SMRAM (return either EFI_SUCCESS or EFI_ACCESS_DENIED)
	pass

descriptor = {
	"guid" : "da473d7f-4b31-4d63-92b7-3d905ef84b84",
	"struct" : AMI_SMM_BUFFER_VALIDATION_PROTOCOL,
	"fields" : (
		('ValidateMemoryBuffer',hook_ValidateMemoryBuffer),
		('ValidateMmioBuffer',	hook_ValidateMmioBuffer),
		('ValidateSmramBuffer',	hook_ValidateSmramBuffer)
	)
}
