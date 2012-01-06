/*
 * libdasm -- simple x86 disassembly library
 * (c) 2004 - 2006  jt / nologin.org
 *
 * opcode_tables.h:
 * Opcode tables for FPU, 1, 2 and 3-byte opcodes and
 * extensions.
 *
 */

#ifndef _OPCODE_TABLES_H
#define _OPCODE_TABLES_H

extern const char *rep_table[3];

extern const char *reg_table[11][8];

// Name table index
#define REG_GEN_DWORD 0
#define REG_GEN_WORD  1
#define REG_GEN_BYTE  2
#define REG_SEGMENT   3
#define REG_DEBUG     4
#define REG_CONTROL   5
#define REG_TEST      6
#define REG_XMM       7 
#define REG_MMX       8 
#define REG_FPU       9
#define REG_BRANCH    10	// Not registers strictly speaking..

extern INST inst_table1[256];
extern INST inst_table2[256];
extern INST inst_table3_66[256];
extern INST inst_table3_f2[256];
extern INST inst_table3_f3[256];
extern INST inst_table_ext1_1[8];
extern INST inst_table_ext1_2[8];
extern INST inst_table_ext1_3[8];
extern INST inst_table_ext2_1[8];
extern INST inst_table_ext2_2[8];
extern INST inst_table_ext2_3[8];
extern INST inst_table_ext2_4[8];
extern INST inst_table_ext2_5[8];
extern INST inst_table_ext2_6[8];
extern INST inst_table_ext3_1[8];
extern INST inst_table_ext3_2[8];
extern INST inst_table_ext4[8];
extern INST inst_table_ext5[8];
extern INST inst_table_ext6[8];
extern INST inst_table_ext7[8];
extern INST inst_monitor;
extern INST inst_mwait;
extern INST inst_table_ext8[8];
extern INST inst_table_ext9[8];
extern INST inst_table_ext10[8];
extern INST inst_table_ext11[8];
extern INST inst_table_ext12[8];
extern INST inst_table_ext12_66[8];
extern INST inst_table_ext13[8];
extern INST inst_table_ext13_66[8];
extern INST inst_table_ext14[8];
extern INST inst_table_ext14_66[8];
extern INST inst_table_ext15[8];
extern INST inst_table_ext16[8];
extern INST * inst_table_ext[25];
extern INST inst_table_fpu_d8[72];
extern INST inst_table_fpu_d9[72];
extern INST inst_table_fpu_da[72];
extern INST inst_table_fpu_db[72];
extern INST inst_table_fpu_dc[72];
extern INST inst_table_fpu_dd[72];
extern INST inst_table_fpu_de[72];
extern INST inst_table_fpu_df[72];
extern INST * inst_table4[8];

#endif
