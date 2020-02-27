/* THIS FILE IS GENERATED.  -*- buffer-read-only: t -*- vi:set ro:
  Original: 64bit-sse.xml */

#include "gdbsupport/tdesc.h"

static int
create_feature_i386_64bit_sse (struct target_desc *result, long regnum)
{
  struct tdesc_feature *feature;

  feature = tdesc_create_feature (result, "org.gnu.gdb.i386.sse");
  tdesc_type *element_type;
  element_type = tdesc_named_type (feature, "ieee_single");
  tdesc_create_vector (feature, "v4f", element_type, 4);

  element_type = tdesc_named_type (feature, "ieee_double");
  tdesc_create_vector (feature, "v2d", element_type, 2);

  element_type = tdesc_named_type (feature, "int8");
  tdesc_create_vector (feature, "v16i8", element_type, 16);

  element_type = tdesc_named_type (feature, "int16");
  tdesc_create_vector (feature, "v8i16", element_type, 8);

  element_type = tdesc_named_type (feature, "int32");
  tdesc_create_vector (feature, "v4i32", element_type, 4);

  element_type = tdesc_named_type (feature, "int64");
  tdesc_create_vector (feature, "v2i64", element_type, 2);

  tdesc_type_with_fields *type_with_fields;
  type_with_fields = tdesc_create_union (feature, "vec128");
  tdesc_type *field_type;
  field_type = tdesc_named_type (feature, "v4f");
  tdesc_add_field (type_with_fields, "v4_float", field_type);
  field_type = tdesc_named_type (feature, "v2d");
  tdesc_add_field (type_with_fields, "v2_double", field_type);
  field_type = tdesc_named_type (feature, "v16i8");
  tdesc_add_field (type_with_fields, "v16_int8", field_type);
  field_type = tdesc_named_type (feature, "v8i16");
  tdesc_add_field (type_with_fields, "v8_int16", field_type);
  field_type = tdesc_named_type (feature, "v4i32");
  tdesc_add_field (type_with_fields, "v4_int32", field_type);
  field_type = tdesc_named_type (feature, "v2i64");
  tdesc_add_field (type_with_fields, "v2_int64", field_type);
  field_type = tdesc_named_type (feature, "uint128");
  tdesc_add_field (type_with_fields, "uint128", field_type);

  type_with_fields = tdesc_create_flags (feature, "i386_mxcsr", 4);
  tdesc_add_flag (type_with_fields, 0, "IE");
  tdesc_add_flag (type_with_fields, 1, "DE");
  tdesc_add_flag (type_with_fields, 2, "ZE");
  tdesc_add_flag (type_with_fields, 3, "OE");
  tdesc_add_flag (type_with_fields, 4, "UE");
  tdesc_add_flag (type_with_fields, 5, "PE");
  tdesc_add_flag (type_with_fields, 6, "DAZ");
  tdesc_add_flag (type_with_fields, 7, "IM");
  tdesc_add_flag (type_with_fields, 8, "DM");
  tdesc_add_flag (type_with_fields, 9, "ZM");
  tdesc_add_flag (type_with_fields, 10, "OM");
  tdesc_add_flag (type_with_fields, 11, "UM");
  tdesc_add_flag (type_with_fields, 12, "PM");
  tdesc_add_flag (type_with_fields, 15, "FZ");

  regnum = 40;
  tdesc_create_reg (feature, "xmm0", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm1", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm2", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm3", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm4", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm5", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm6", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm7", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm8", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm9", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm10", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm11", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm12", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm13", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm14", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm15", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "mxcsr", regnum++, 1, "vector", 32, "i386_mxcsr");
  return regnum;
}
