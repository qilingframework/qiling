# The following formula shows how the alias region maps onto the bit-band region:
#       bit_word_offset = (byte_offset x 32) + (bit_number x 4)
#       bit_word_addr = bit_band_base + bit_word_offset


# https://github.com/qemu/qemu/blob/453d9c61dd5681159051c6e4d07e7b2633de2e70/hw/arm/armv7m.c


# peripheral_base | (offset & 0x1ffffff) >> 5

# 0x40000000 | (0x1c & 0x1ffffff) >> 5


def alias_to_bitband(peripheral_base, alias_offset):
    return peripheral_base | (alias_offset & 0x1ffffff) >> 5

