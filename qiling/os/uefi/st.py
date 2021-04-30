#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.uefi import bs, rt, ds
from qiling.os.uefi.utils import install_configuration_table
from qiling.os.uefi.UefiSpec import EFI_SYSTEM_TABLE, EFI_BOOT_SERVICES, EFI_RUNTIME_SERVICES, EFI_CONFIGURATION_TABLE

# static mem layout:
#
#		+-- EFI_SYSTEM_TABLE ---------+
#		|                             |
#		| ...                         |
#		| RuntimeServices*     -> (1) |
#		| BootServices*        -> (2) |
#		| NumberOfTableEntries        |
#		| ConfigurationTable*  -> (4) |
#		+-----------------------------+
#	(1)	+-- EFI_RUNTIME_SERVICES -----+
#		|                             |
#		| ...                         |
#		+-----------------------------+
#	(2)	+-- EFI_BOOT_SERVICES --------+
#		|                             |
#		| ...                         |
#		+-----------------------------+
#	(3)	+-- EFI_DXE_SERVICES ---------+
#		|                             |
#		| ...                         |
#		+-----------------------------+
#	(4)	+-- EFI_CONFIGURATION_TABLE --+		of HOB_LIST
#		| VendorGuid                  |
#		| VendorTable*         -> (5) |
#		+-----------------------------+
#		+-- EFI_CONFIGURATION_TABLE --+		of DXE_SERVICE_TABLE
#		| VendorGuid                  |
#		| VendorTable*         -> (3) |
#		+-----------------------------+
#
#		... sizeof EFI_CONFIGURATION_TABLE x 98
#
#	(5)	+-- VOID* --------------------+
#		| ...                         |
#		+-----------------------------+
#
#		... the remainder of the 256 KiB chunk may be used for more conf table data

def initialize(ql: Qiling, gST: int):
	ql.loader.gST = gST

	gBS = gST + EFI_SYSTEM_TABLE.sizeof()		# boot services
	gRT = gBS + EFI_BOOT_SERVICES.sizeof()		# runtime services
	gDS = gRT + EFI_RUNTIME_SERVICES.sizeof()	# dxe services
	cfg = gDS + ds.EFI_DXE_SERVICES.sizeof()	# configuration tables array

	ql.log.info(f'Global tables:')
	ql.log.info(f' | gST   {gST:#010x}')
	ql.log.info(f' | gBS   {gBS:#010x}')
	ql.log.info(f' | gRT   {gRT:#010x}')
	ql.log.info(f' | gDS   {gDS:#010x}')
	ql.log.info(f'')

	bs.initialize(ql, gBS)
	rt.initialize(ql, gRT)
	ds.initialize(ql, gDS)

	instance = EFI_SYSTEM_TABLE()
	instance.RuntimeServices = gRT
	instance.BootServices = gBS
	instance.NumberOfTableEntries = 0
	instance.ConfigurationTable = cfg

	instance.saveTo(ql, gST)

	# configuration tables bookkeeping
	confs = []

	# these are needed for utils.CoreInstallConfigurationTable
	ql.loader.dxe_context.conf_table_array = confs
	ql.loader.dxe_context.conf_table_array_ptr = cfg

	# configuration table data space; its location is calculated by leaving
	# enough space for 100 configuration table entries. only a few entries are
	# expected, so 100 should definitely suffice
	conf_data = cfg + EFI_CONFIGURATION_TABLE.sizeof() * 100
	ql.loader.dxe_context.conf_table_data_ptr = conf_data
	ql.loader.dxe_context.conf_table_data_next_ptr = conf_data

	install_configuration_table(ql.loader.dxe_context, "HOB_LIST", None)
	install_configuration_table(ql.loader.dxe_context, "DXE_SERVICE_TABLE", gDS)

__all__ = [
	'initialize'
]