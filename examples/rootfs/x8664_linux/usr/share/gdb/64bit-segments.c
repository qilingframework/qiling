/* THIS FILE IS GENERATED.  -*- buffer-read-only: t -*- vi:set ro:
  Original: 64bit-segments.xml */

#include "gdbsupport/tdesc.h"

static int
create_feature_i386_64bit_segments (struct target_desc *result, long regnum)
{
  struct tdesc_feature *feature;

  feature = tdesc_create_feature (result, "org.gnu.gdb.i386.segments");
  tdesc_create_reg (feature, "fs_base", regnum++, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "gs_base", regnum++, 1, NULL, 64, "int");
  return regnum;
}
