#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import logging

from qiling.os.uefi import bs, rt, ds
from qiling.os.uefi.utils import CoreInstallConfigurationTable
from qiling.os.uefi.UefiSpec import EFI_SYSTEM_TABLE, EFI_BOOT_SERVICES, EFI_RUNTIME_SERVICES

# static mem layout:
#
#		+-- EFI_SYSTEM_TABLE ---------+
#		|                             |
#		| ...                         |
#		| RuntimeServices      -> (1) |
#		| BootServices         -> (2) |
#		| NumberOfTableEntries        |
#		| ConfigurationTable   -> (4) |
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
#		| VendorTable          -> (?) |
#		+-----------------------------+
#		+-- EFI_CONFIGURATION_TABLE --+		of DXE_SERVICE_TABLE
#		| VendorGuid                  |
#		| VendorTable          -> (3) |
#		+-----------------------------+
#
#	(?)	Address is read from profile
#
#		... the remainder of the 256 KiB chunk may be used for EFI_CONFIGURATION_TABLE entries

def install_configuration_table(ql, key: str, table: int):
	cfgtable = ql.os.profile[key]
	guid = cfgtable['Guid']

	if table is None:
		table = int(cfgtable['Table'], 0)

	CoreInstallConfigurationTable(ql, guid, table)

def initialize(ql, gST : int):
	gBS = gST + EFI_SYSTEM_TABLE.sizeof()		# boot services
	gRT = gBS + EFI_BOOT_SERVICES.sizeof()		# runtime services
	gDS = gRT + EFI_RUNTIME_SERVICES.sizeof()	# dxe services
	cfg = gDS + ds.EFI_DXE_SERVICES.sizeof()	# configuration tables array

	logging.info(f'Global tables:')
	logging.info(f' | gST   {gST:#010x}')
	logging.info(f' | gBS   {gBS:#010x}')
	logging.info(f' | gRT   {gRT:#010x}')
	logging.info(f' | gDS   {gDS:#010x}')
	logging.info(f'')

	bs.initialize(ql, gBS)
	rt.initialize(ql, gRT)
	ds.initialize(ql, gDS)

	# configuration tables bookkeeping
	confs = []

	# these are needed for utils.CoreInstallConfigurationTable
	ql.loader.efi_configuration_table = confs
	ql.loader.efi_configuration_table_ptr = cfg

	install_configuration_table(ql, "HOB_LIST", None)
	install_configuration_table(ql, "DXE_SERVICE_TABLE", gDS)

	instance = EFI_SYSTEM_TABLE()
	instance.RuntimeServices = gRT
	instance.BootServices = gBS
	instance.NumberOfTableEntries = len(confs)	# HOB_LIST and DXE_SERVICES
	instance.ConfigurationTable = cfg

	instance.saveTo(ql, gST)

__all__ = [
	'initialize'
]