/* THIS FILE IS GENERATED.  -*- buffer-read-only: t -*- vi:set ro:
  Original: 64bit-mpx.xml */

#include "gdbsupport/tdesc.h"

static int
create_feature_i386_64bit_mpx (struct target_desc *result, long regnum)
{
  struct tdesc_feature *feature;

  feature = tdesc_create_feature (result, "org.gnu.gdb.i386.mpx");
  tdesc_type_with_fields *type_with_fields;
  type_with_fields = tdesc_create_struct (feature, "br128");
  tdesc_type *field_type;
  field_type = tdesc_named_type (feature, "uint64");
  tdesc_add_field (type_with_fields, "lbound", field_type);
  field_type = tdesc_named_type (feature, "uint64");
  tdesc_add_field (type_with_fields, "ubound_raw", field_type);

  type_with_fields = tdesc_create_struct (feature, "_bndstatus");
  tdesc_set_struct_size (type_with_fields, 8);
  tdesc_add_bitfield (type_with_fields, "bde", 2, 63);
  tdesc_add_bitfield (type_with_fields, "error", 0, 1);

  type_with_fields = tdesc_create_union (feature, "status");
  field_type = tdesc_named_type (feature, "data_ptr");
  tdesc_add_field (type_with_fields, "raw", field_type);
  field_type = tdesc_named_type (feature, "_bndstatus");
  tdesc_add_field (type_with_fields, "status", field_type);

  type_with_fields = tdesc_create_struct (feature, "_bndcfgu");
  tdesc_set_struct_size (type_with_fields, 8);
  tdesc_add_bitfield (type_with_fields, "base", 12, 63);
  tdesc_add_bitfield (type_with_fields, "reserved", 2, 11);
  tdesc_add_bitfield (type_with_fields, "preserved", 1, 1);
  tdesc_add_bitfield (type_with_fields, "enabled", 0, 0);

  type_with_fields = tdesc_create_union (feature, "cfgu");
  field_type = tdesc_named_type (feature, "data_ptr");
  tdesc_add_field (type_with_fields, "raw", field_type);
  field_type = tdesc_named_type (feature, "_bndcfgu");
  tdesc_add_field (type_with_fields, "config", field_type);

  tdesc_create_reg (feature, "bnd0raw", regnum++, 1, NULL, 128, "br128");
  tdesc_create_reg (feature, "bnd1raw", regnum++, 1, NULL, 128, "br128");
  tdesc_create_reg (feature, "bnd2raw", regnum++, 1, NULL, 128, "br128");
  tdesc_create_reg (feature, "bnd3raw", regnum++, 1, NULL, 128, "br128");
  tdesc_create_reg (feature, "bndcfgu", regnum++, 1, NULL, 64, "cfgu");
  tdesc_create_reg (feature, "bndstatus", regnum++, 1, NULL, 64, "status");
  return regnum;
}
