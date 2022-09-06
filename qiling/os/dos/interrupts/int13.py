#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct
from enum import IntEnum

from qiling import Qiling

from .. import utils

class DiskError(IntEnum):
    NoError							= 0
    BadCommand						= 1
    AddressNotFound					= 2
    DiskWriteProtectError			= 3
    SectorNotFound					= 4
    FixedDiskResetFailed			= 5
    DiskChangedOrRemoved			= 6
    BadFixedDiskParameterTable		= 7
    DMAOverrun						= 8
    DMAAcessAcrossBoundary			= 9
    BadFixedDiskSectorFlag			= 10
    BadFixedDiskCylinder			= 11
    UnsupportedTrack				= 12
    InvalidNumberofSectors			= 13
    FixedDiskControlledDataAdressDetected = 14
    FixedDiskDMAArbitrationLevelOutofRange = 15
    ECCErrorOnRead					= 16
    RecoverableFixedDiskDataError	= 17
    ControllerError					= 32
    SeekFailure						= 64
    Timeout							= 128
    FixedDiskDriveNotReady			= 170
    FixedDiskUndefinedError			= 187
    FixedDiskWriteFault				= 204
    FixedDiskStatusError			= 224
    SenseOperationFailed			= 255

def parse_dap(dapbs):
	return struct.unpack("<BBHHHQ", dapbs)

def __leaf_00(ql: Qiling):
	ql.os.clear_cf()

def __leaf_02(ql: Qiling):
	idx = ql.reg.dl

	if not ql.os.fs_mapper.has_mapping(idx):
		ql.log.warning(f'Warning: No such disk: {idx:#x}')
		ql.reg.ah = DiskError.BadCommand.value
		ql.os.set_cf()
		return

	cylinder = ((ql.reg.cx & 0xff00) >> 8) | ((ql.reg.cx & 0xC0) << 2)
	head = ql.reg.dh
	sector = ql.reg.cx & 63
	cnt = ql.reg.al

	disk = ql.os.fs_mapper.open(idx, None)
	content = disk.read_chs(cylinder, head, sector, cnt)

	ql.mem.write(utils.linaddr(ql.reg.es, ql.reg.bx), content)
	ql.os.clear_cf()
	ql.reg.ah = 0
	ql.reg.al = sector

# @see: https://stanislavs.org/helppc/int_13-8.html
def __leaf_08(ql: Qiling):
	idx = ql.reg.dl

	if not ql.os.fs_mapper.has_mapping(idx):
		ql.log.warning(f'Warning: No such disk: {idx:#x}')
		ql.reg.ah = DiskError.BadCommand.value
		ql.os.set_cf()
		return

	disk = ql.os.fs_mapper.open(idx, None)
	ql.reg.dl = ql.os.fs_mapper.mapping_count()
	ql.reg.dh = disk.n_heads - 1
	ql.reg.bl = 0x4
	ql.reg.di = 0
	ql.reg.ds = 0

	n_sectors = min(disk.n_sectors, 63)
	n_cylinders = min(disk.n_cylinders, 1023)

	cx = (n_sectors & 0b111111)
	cx |= ((n_cylinders & 0b11) << 6)
	cx |= (((n_cylinders & 0b1111111100) >> 2) << 8)

	ql.reg.cx = cx
	ql.reg.ah = 0
	ql.os.clear_cf()

def __leaf_41(ql: Qiling):
	ql.reg.ah = 0
	# 1 -> Device Access using the packet structure.
	# 2 -> Drive locking and ejecting.
	# 4 -> Enhanced Disk Drive Support.
	ql.reg.bx = 0xaa55
	ql.reg.cx = 7

def __leaf_42(ql: Qiling):
	idx = ql.reg.dl

	if not ql.os.fs_mapper.has_mapping(idx):
		ql.log.warning(f'Warning: No such disk: {idx:#x}')
		ql.reg.ah = DiskError.BadCommand.value
		ql.os.set_cf()
		return

	dapbs = ql.mem.read(utils.linaddr(ql.reg.ds, ql.reg.si), 16)
	_, _, cnt, offset, segment, lba = parse_dap(dapbs)
	ql.log.info(f'Reading {cnt} sectors from disk {idx:#x} with LBA {lba}')

	disk = ql.os.fs_mapper.open(idx, None)
	content = disk.read_sectors(lba, cnt)
	ql.mem.write(utils.linaddr(segment, offset), content)

	ql.os.clear_cf()
	ql.reg.ah = 0

def __leaf_43(ql: Qiling):
	idx = ql.reg.dl

	if not ql.os.fs_mapper.has_mapping(idx):
		ql.log.info(f"Warning: No such disk: {hex(idx)}")
		ql.reg.ah = DiskError.BadCommand.value
		ql.os.set_cf()
		return

	dapbs = ql.mem.read(utils.linaddr(ql.reg.ds, ql.reg.si), 16)
	_, _, cnt, offset, segment, lba = parse_dap(dapbs)
	ql.log.info(f'Writing {cnt} sectors to disk {idx:#x} with LBA {lba}')

	disk = ql.os.fs_mapper.open(idx, None)
	buffer = ql.mem.read(utils.linaddr(segment, offset), cnt * disk.sector_size)
	disk.write_sectors(lba, cnt, buffer)

	ql.os.clear_cf()
	ql.reg.ah = 0

# @see: https://en.wikipedia.org/wiki/INT_13H
def handler(ql: Qiling):
	ah = ql.reg.ah

	leaffunc = {
		0x00 : __leaf_00,
		0x02 : __leaf_02,
		0x08 : __leaf_08,
		0x41 : __leaf_41,
		0x42 : __leaf_42,
		0x43 : __leaf_43
	}.get(ah)

	if leaffunc is None:
		ql.log.exception(f'leaf {ah:02x}h of INT 13h is not implemented')
		raise NotImplementedError()

	leaffunc(ql)
