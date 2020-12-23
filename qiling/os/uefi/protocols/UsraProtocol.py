from qiling.os.const import *
from ..fncc import *
from ..ProcessorBind import *
from .common import install_protocol

# @see: CpRcPkg\Include\UsraAccessType.h
class USRA_ADDRESS(UNION):
	_pack_ = True
	_fields_ = [
		('dwRawData',	UINT32 * 4)
		# ('Attribute',	ADDR_ATTRIBUTE_TYPE),
		# ('Pcie',		USRA_PCIE_ADDR_TYPE),
		# ('PcieBlk',	USRA_PCIE_ADDR_TYPE),
		# ('Csr',		USRA_CSR_ADDR_TYPE),
		# ('Mmio',		USRA_MMIO_ADDR_TYPE),
		# ('Io',		USRA_IO_ADDR_TYPE)
	]

# @see: CpRcPkg\Include\Protocol\SiliconRegAccess.h
class USRA_PROTOCOL(STRUCT):
	_fields_ = [
		('SmmRegRead',		FUNCPTR(INTN, PTR(USRA_ADDRESS), PTR(VOID))),
		('SmmRegWrite',		FUNCPTR(INTN, PTR(USRA_ADDRESS), PTR(VOID))),
		('SmmRegModify',	FUNCPTR(INTN, PTR(USRA_ADDRESS), PTR(VOID), PTR(VOID))),
		('SmmGetRegAddr',	FUNCPTR(INTN, PTR(USRA_ADDRESS)))
	]

@dxeapi(params = {
	"Address"	: POINTER,
	"Buffer"	: POINTER
})
def hook_SmmRegRead(ql, address, params):
	pass

@dxeapi(params = {
	"Address"	: POINTER,
	"Buffer"	: POINTER
})
def hook_SmmRegWrite(ql, address, params):
	pass

@dxeapi(params = {
	"Address"	: POINTER,
	"AndBuffer"	: POINTER,
	"OrBuffer"	: POINTER
})
def hook_SmmRegModify(ql, address, params):
	pass

@dxeapi(params = {
	"Address" : POINTER
})
def hook_SmmGetRegAddr(ql, address, params):
	pass

def install(ql, base, handles):
	descriptor = {
		"guid" : "fd480a76-b134-4ef7-adfe-b0e054639807",
		"struct" : USRA_PROTOCOL,
		"fields" : (
			('SmmRegRead',		hook_SmmRegRead),
			('SmmRegWrite',		hook_SmmRegWrite),
			('SmmRegModify',	hook_SmmRegModify),
			('SmmGetRegAddr',	hook_SmmGetRegAddr)
		)
	}

	return install_protocol(ql, base, descriptor, handles)

__all__ = ['install']
