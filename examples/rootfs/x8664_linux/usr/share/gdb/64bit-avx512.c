/* THIS FILE IS GENERATED.  -*- buffer-read-only: t -*- vi:set ro:
  Original: 64bit-avx512.xml */

#include "gdbsupport/tdesc.h"

static int
create_feature_i386_64bit_avx512 (struct target_desc *result, long regnum)
{
  struct tdesc_feature *feature;

  feature = tdesc_create_feature (result, "org.gnu.gdb.i386.avx512");
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

  element_type = tdesc_named_type (feature, "uint128");
  tdesc_create_vector (feature, "v2ui128", element_type, 2);

  tdesc_create_reg (feature, "xmm16", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm17", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm18", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm19", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm20", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm21", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm22", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm23", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm24", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm25", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm26", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm27", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm28", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm29", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm30", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "xmm31", regnum++, 1, NULL, 128, "vec128");
  tdesc_create_reg (feature, "ymm16h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm17h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm18h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm19h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm20h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm21h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm22h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm23h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm24h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm25h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm26h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm27h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm28h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm29h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm30h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "ymm31h", regnum++, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "k0", regnum++, 1, NULL, 64, "uint64");
  tdesc_create_reg (feature, "k1", regnum++, 1, NULL, 64, "uint64");
  tdesc_create_reg (feature, "k2", regnum++, 1, NULL, 64, "uint64");
  tdesc_create_reg (feature, "k3", regnum++, 1, NULL, 64, "uint64");
  tdesc_create_reg (feature, "k4", regnum++, 1, NULL, 64, "uint64");
  tdesc_create_reg (feature, "k5", regnum++, 1, NULL, 64, "uint64");
  tdesc_create_reg (feature, "k6", regnum++, 1, NULL, 64, "uint64");
  tdesc_create_reg (feature, "k7", regnum++, 1, NULL, 64, "uint64");
  tdesc_create_reg (feature, "zmm0h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm1h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm2h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm3h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm4h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm5h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm6h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm7h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm8h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm9h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm10h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm11h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm12h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm13h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm14h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm15h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm16h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm17h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm18h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm19h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm20h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm21h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm22h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm23h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm24h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm25h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm26h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm27h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm28h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm29h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm30h", regnum++, 1, NULL, 256, "v2ui128");
  tdesc_create_reg (feature, "zmm31h", regnum++, 1, NULL, 256, "v2ui128");
  return regnum;
}
