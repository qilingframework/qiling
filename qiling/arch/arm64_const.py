#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn.arm64_const import *

reg_map = {
    "x0":  UC_ARM64_REG_X0,
    "x1":  UC_ARM64_REG_X1,
    "x2":  UC_ARM64_REG_X2,
    "x3":  UC_ARM64_REG_X3,
    "x4":  UC_ARM64_REG_X4,
    "x5":  UC_ARM64_REG_X5,
    "x6":  UC_ARM64_REG_X6,
    "x7":  UC_ARM64_REG_X7,
    "x8":  UC_ARM64_REG_X8,
    "x9":  UC_ARM64_REG_X9,
    "x10": UC_ARM64_REG_X10,
    "x11": UC_ARM64_REG_X11,
    "x12": UC_ARM64_REG_X12,
    "x13": UC_ARM64_REG_X13,
    "x14": UC_ARM64_REG_X14,
    "x15": UC_ARM64_REG_X15,
    "x16": UC_ARM64_REG_X16,
    "x17": UC_ARM64_REG_X17,
    "x18": UC_ARM64_REG_X18,
    "x19": UC_ARM64_REG_X19,
    "x20": UC_ARM64_REG_X20,
    "x21": UC_ARM64_REG_X21,
    "x22": UC_ARM64_REG_X22,
    "x23": UC_ARM64_REG_X23,
    "x24": UC_ARM64_REG_X24,
    "x25": UC_ARM64_REG_X25,
    "x26": UC_ARM64_REG_X26,
    "x27": UC_ARM64_REG_X27,
    "x28": UC_ARM64_REG_X28,
    "x29": UC_ARM64_REG_X29,
    "x30": UC_ARM64_REG_X30,
    "sp": UC_ARM64_REG_SP,
    "pc": UC_ARM64_REG_PC,
    "lr": UC_ARM64_REG_LR,
    "cpacr_el1": UC_ARM64_REG_CPACR_EL1,
    "tpidr_el0": UC_ARM64_REG_TPIDR_EL0,
    "pstate": UC_ARM64_REG_PSTATE
}

reg_map_b = {
    "b0":  UC_ARM64_REG_B0,
    "b1":  UC_ARM64_REG_B1,
    "b2":  UC_ARM64_REG_B2,
    "b3":  UC_ARM64_REG_B3,
    "b4":  UC_ARM64_REG_B4,
    "b5":  UC_ARM64_REG_B5,
    "b6":  UC_ARM64_REG_B6,
    "b7":  UC_ARM64_REG_B7,
    "b8":  UC_ARM64_REG_B8,
    "b9":  UC_ARM64_REG_B9,
    "b10": UC_ARM64_REG_B10,
    "b11": UC_ARM64_REG_B11,
    "b12": UC_ARM64_REG_B12,
    "b13": UC_ARM64_REG_B13,
    "b14": UC_ARM64_REG_B14,
    "b15": UC_ARM64_REG_B15,
    "b16": UC_ARM64_REG_B16,
    "b17": UC_ARM64_REG_B17,
    "b18": UC_ARM64_REG_B18,
    "b19": UC_ARM64_REG_B19,
    "b20": UC_ARM64_REG_B20,
    "b21": UC_ARM64_REG_B21,
    "b22": UC_ARM64_REG_B22,
    "b23": UC_ARM64_REG_B23,
    "b24": UC_ARM64_REG_B24,
    "b25": UC_ARM64_REG_B25,
    "b26": UC_ARM64_REG_B26,
    "b27": UC_ARM64_REG_B27,
    "b28": UC_ARM64_REG_B28,
    "b29": UC_ARM64_REG_B29,
    "b30": UC_ARM64_REG_B30,
    "b31": UC_ARM64_REG_B31
}

reg_map_d = {
    "d0":  UC_ARM64_REG_D0,
    "d1":  UC_ARM64_REG_D1,
    "d2":  UC_ARM64_REG_D2,
    "d3":  UC_ARM64_REG_D3,
    "d4":  UC_ARM64_REG_D4,
    "d5":  UC_ARM64_REG_D5,
    "d6":  UC_ARM64_REG_D6,
    "d7":  UC_ARM64_REG_D7,
    "d8":  UC_ARM64_REG_D8,
    "d9":  UC_ARM64_REG_D9,
    "d10": UC_ARM64_REG_D10,
    "d11": UC_ARM64_REG_D11,
    "d12": UC_ARM64_REG_D12,
    "d13": UC_ARM64_REG_D13,
    "d14": UC_ARM64_REG_D14,
    "d15": UC_ARM64_REG_D15,
    "d16": UC_ARM64_REG_D16,
    "d17": UC_ARM64_REG_D17,
    "d18": UC_ARM64_REG_D18,
    "d19": UC_ARM64_REG_D19,
    "d20": UC_ARM64_REG_D20,
    "d21": UC_ARM64_REG_D21,
    "d22": UC_ARM64_REG_D22,
    "d23": UC_ARM64_REG_D23,
    "d24": UC_ARM64_REG_D24,
    "d25": UC_ARM64_REG_D25,
    "d26": UC_ARM64_REG_D26,
    "d27": UC_ARM64_REG_D27,
    "d28": UC_ARM64_REG_D28,
    "d29": UC_ARM64_REG_D29,
    "d30": UC_ARM64_REG_D30,
    "d31": UC_ARM64_REG_D31
}

reg_map_h = {
    "h0":  UC_ARM64_REG_H0,
    "h1":  UC_ARM64_REG_H1,
    "h2":  UC_ARM64_REG_H2,
    "h3":  UC_ARM64_REG_H3,
    "h4":  UC_ARM64_REG_H4,
    "h5":  UC_ARM64_REG_H5,
    "h6":  UC_ARM64_REG_H6,
    "h7":  UC_ARM64_REG_H7,
    "h8":  UC_ARM64_REG_H8,
    "h9":  UC_ARM64_REG_H9,
    "h10": UC_ARM64_REG_H10,
    "h11": UC_ARM64_REG_H11,
    "h12": UC_ARM64_REG_H12,
    "h13": UC_ARM64_REG_H13,
    "h14": UC_ARM64_REG_H14,
    "h15": UC_ARM64_REG_H15,
    "h16": UC_ARM64_REG_H16,
    "h17": UC_ARM64_REG_H17,
    "h18": UC_ARM64_REG_H18,
    "h19": UC_ARM64_REG_H19,
    "h20": UC_ARM64_REG_H20,
    "h21": UC_ARM64_REG_H21,
    "h22": UC_ARM64_REG_H22,
    "h23": UC_ARM64_REG_H23,
    "h24": UC_ARM64_REG_H24,
    "h25": UC_ARM64_REG_H25,
    "h26": UC_ARM64_REG_H26,
    "h27": UC_ARM64_REG_H27,
    "h28": UC_ARM64_REG_H28,
    "h29": UC_ARM64_REG_H29,
    "h30": UC_ARM64_REG_H30,
    "h31": UC_ARM64_REG_H31
}

reg_map_q = {
    "q0":  UC_ARM64_REG_Q0,
    "q1":  UC_ARM64_REG_Q1,
    "q2":  UC_ARM64_REG_Q2,
    "q3":  UC_ARM64_REG_Q3,
    "q4":  UC_ARM64_REG_Q4,
    "q5":  UC_ARM64_REG_Q5,
    "q6":  UC_ARM64_REG_Q6,
    "q7":  UC_ARM64_REG_Q7,
    "q8":  UC_ARM64_REG_Q8,
    "q9":  UC_ARM64_REG_Q9,
    "q10": UC_ARM64_REG_Q10,
    "q11": UC_ARM64_REG_Q11,
    "q12": UC_ARM64_REG_Q12,
    "q13": UC_ARM64_REG_Q13,
    "q14": UC_ARM64_REG_Q14,
    "q15": UC_ARM64_REG_Q15,
    "q16": UC_ARM64_REG_Q16,
    "q17": UC_ARM64_REG_Q17,
    "q18": UC_ARM64_REG_Q18,
    "q19": UC_ARM64_REG_Q19,
    "q20": UC_ARM64_REG_Q20,
    "q21": UC_ARM64_REG_Q21,
    "q22": UC_ARM64_REG_Q22,
    "q23": UC_ARM64_REG_Q23,
    "q24": UC_ARM64_REG_Q24,
    "q25": UC_ARM64_REG_Q25,
    "q26": UC_ARM64_REG_Q26,
    "q27": UC_ARM64_REG_Q27,
    "q28": UC_ARM64_REG_Q28,
    "q29": UC_ARM64_REG_Q29,
    "q30": UC_ARM64_REG_Q30,
    "q31": UC_ARM64_REG_Q31
}

reg_map_s = {
    "s0":  UC_ARM64_REG_S0,
    "s1":  UC_ARM64_REG_S1,
    "s2":  UC_ARM64_REG_S2,
    "s3":  UC_ARM64_REG_S3,
    "s4":  UC_ARM64_REG_S4,
    "s5":  UC_ARM64_REG_S5,
    "s6":  UC_ARM64_REG_S6,
    "s7":  UC_ARM64_REG_S7,
    "s8":  UC_ARM64_REG_S8,
    "s9":  UC_ARM64_REG_S9,
    "s10": UC_ARM64_REG_S10,
    "s11": UC_ARM64_REG_S11,
    "s12": UC_ARM64_REG_S12,
    "s13": UC_ARM64_REG_S13,
    "s14": UC_ARM64_REG_S14,
    "s15": UC_ARM64_REG_S15,
    "s16": UC_ARM64_REG_S16,
    "s17": UC_ARM64_REG_S17,
    "s18": UC_ARM64_REG_S18,
    "s19": UC_ARM64_REG_S19,
    "s20": UC_ARM64_REG_S20,
    "s21": UC_ARM64_REG_S21,
    "s22": UC_ARM64_REG_S22,
    "s23": UC_ARM64_REG_S23,
    "s24": UC_ARM64_REG_S24,
    "s25": UC_ARM64_REG_S25,
    "s26": UC_ARM64_REG_S26,
    "s27": UC_ARM64_REG_S27,
    "s28": UC_ARM64_REG_S28,
    "s29": UC_ARM64_REG_S29,
    "s30": UC_ARM64_REG_S30,
    "s31": UC_ARM64_REG_S31
}

reg_map_w = {
    "w0":  UC_ARM64_REG_W0,
    "w1":  UC_ARM64_REG_W1,
    "w2":  UC_ARM64_REG_W2,
    "w3":  UC_ARM64_REG_W3,
    "w4":  UC_ARM64_REG_W4,
    "w5":  UC_ARM64_REG_W5,
    "w6":  UC_ARM64_REG_W6,
    "w7":  UC_ARM64_REG_W7,
    "w8":  UC_ARM64_REG_W8,
    "w9":  UC_ARM64_REG_W9,
    "w10": UC_ARM64_REG_W10,
    "w11": UC_ARM64_REG_W11,
    "w12": UC_ARM64_REG_W12,
    "w13": UC_ARM64_REG_W13,
    "w14": UC_ARM64_REG_W14,
    "w15": UC_ARM64_REG_W15,
    "w16": UC_ARM64_REG_W16,
    "w17": UC_ARM64_REG_W17,
    "w18": UC_ARM64_REG_W18,
    "w19": UC_ARM64_REG_W19,
    "w20": UC_ARM64_REG_W20,
    "w21": UC_ARM64_REG_W21,
    "w22": UC_ARM64_REG_W22,
    "w23": UC_ARM64_REG_W23,
    "w24": UC_ARM64_REG_W24,
    "w25": UC_ARM64_REG_W25,
    "w26": UC_ARM64_REG_W26,
    "w27": UC_ARM64_REG_W27,
    "w28": UC_ARM64_REG_W28,
    "w29": UC_ARM64_REG_W29,
    "w30": UC_ARM64_REG_W30
}

reg_map_v = {
    "v0":  UC_ARM64_REG_V0,
    "v1":  UC_ARM64_REG_V1,
    "v2":  UC_ARM64_REG_V2,
    "v3":  UC_ARM64_REG_V3,
    "v4":  UC_ARM64_REG_V4,
    "v5":  UC_ARM64_REG_V5,
    "v6":  UC_ARM64_REG_V6,
    "v7":  UC_ARM64_REG_V7,
    "v8":  UC_ARM64_REG_V8,
    "v9":  UC_ARM64_REG_V9,
    "v10": UC_ARM64_REG_V10,
    "v11": UC_ARM64_REG_V11,
    "v12": UC_ARM64_REG_V12,
    "v13": UC_ARM64_REG_V13,
    "v14": UC_ARM64_REG_V14,
    "v15": UC_ARM64_REG_V15,
    "v16": UC_ARM64_REG_V16,
    "v17": UC_ARM64_REG_V17,
    "v18": UC_ARM64_REG_V18,
    "v19": UC_ARM64_REG_V19,
    "v20": UC_ARM64_REG_V20,
    "v21": UC_ARM64_REG_V21,
    "v22": UC_ARM64_REG_V22,
    "v23": UC_ARM64_REG_V23,
    "v24": UC_ARM64_REG_V24,
    "v25": UC_ARM64_REG_V25,
    "v26": UC_ARM64_REG_V26,
    "v27": UC_ARM64_REG_V27,
    "v28": UC_ARM64_REG_V28,
    "v29": UC_ARM64_REG_V29,
    "v30": UC_ARM64_REG_V30,
    "v31": UC_ARM64_REG_V31
}
