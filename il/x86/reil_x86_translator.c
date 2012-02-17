/*
Copyright (c) 2011, Remco Vermeulen
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    *   Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
    *   Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
    *   Neither the name of the VU Amsterdam nor the
        names of its contributors may be used to endorse or promote products
        derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Remco Vermeulen  BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../reil.h"
#include "../reil_instruction_table.h"
#include "libdasm.h"
#include "opcode_tables.h"
#include "reil_x86_translator.h"

/* Check for address/operand size override, copied from libdasm.c */

static __inline__ enum Mode MODE_CHECK_ADDR(enum Mode mode, int flags) 
{
	if (((mode == MODE_32) && (MASK_PREFIX_ADDR(flags) == 0)) ||
    	    ((mode == MODE_16) && (MASK_PREFIX_ADDR(flags) == 1)))
		return MODE_32;
	else 
		return MODE_16;
}

static __inline__ enum Mode MODE_CHECK_OPERAND(enum Mode mode, int flags) 
{
	if (((mode == MODE_32) && (MASK_PREFIX_OPERAND(flags) == 0)) ||
    	    ((mode == MODE_16) && (MASK_PREFIX_OPERAND(flags) == 1)))
		return MODE_32;
	else 
		return MODE_16;
}

/* The rows containing the registers is equal to the reg_table defined
 * in opcode_tables.c ( part of libdasm ).
 * The other rows contain registers modeling the EFLAGS bits
 */
static const char * x86reg_table[14][8] =
{
	{ "eax",  "ecx",  "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi"  },
	{ "ax",   "cx",   "dx",   "bx",   "sp",   "bp",   "si",   "di"   },
	{ "al",   "cl",   "dl",   "bl",   "ah",   "ch",   "dh",   "bh"   },
	{ "es",   "cs",   "ss",   "ds",   "fs",   "gs",   "??",   "??"   },
	{ "dr0",  "dr1",  "dr2",  "dr3",  "dr4",  "dr5",  "dr6",  "dr7"  },
	{ "cr0",  "cr1",  "cr2",  "cr3",  "cr4",  "cr5",  "cr6",  "cr7"  },
	{ "tr0",  "tr1",  "tr2",  "tr3",  "tr4",  "tr5",  "tr6",  "tr7"  },
	{ "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7" },
	{ "mm0",  "mm1",  "mm2",  "mm3",  "mm4",  "mm5",  "mm6",  "mm7"  },
    /* EFLAGS */
	{ "cf",   "??",   "pf",   "??",   "af",   "??",   "zf",   "sf"   },
	{ "tf",   "if",   "df",   "of",   "iopl", "nt",   "??",   "rf"   },
	{ "vm",   "ac",   "vif",  "vip",  "id",   "??",   "??",   "??"   },
	{ "??",   "??",   "??",   "??",   "??",   "??",   "??",   "??"   },
	{ "eip", },
};

#define X86_REG_EAX     0x0
#define X86_REG_AX      0x8
#define X86_REG_AL      0x10
#define X86_REG_AH      0x14 

#define X86_REG_EDX     0x2
#define X86_REG_DX      0xA
#define X86_REG_DL      0x12
#define X86_REG_DH      0x16 

#define X86_REG_ESP	0x4
#define X86_REG_EBP	0x5

#define EFLAG_NOT_IMPL  0x0
#define EFLAG_BLANK     0x0
#define EFLAG_TEST      0x1
#define EFLAG_MODIFY    0x2
#define EFLAG_RESET     0x4
#define EFLAG_SET       0x8
#define EFLAG_UNDEF     0xc
#define EFLAG_RESTORE   0x10

#define X86_REG_EIP	0x68

typedef struct _eflag_affect_reference
{
    unsigned char ef_of;
    unsigned char ef_sf;
    unsigned char ef_zf;
    unsigned char ef_af;
    unsigned char ef_pf;
    unsigned char ef_cf;
    unsigned char ef_tf;
    unsigned char ef_if;
    unsigned char ef_df;
    unsigned char ef_nt;
    unsigned char ef_rf;
} eflag_affect_reference;

/* Implements the EFLAGS cross-reference table from Vol. 1 A-1
 * index on the libdasm instruction types for fast indexing. */
static eflag_affect_reference eflags_cross_reference[] =
{
	/* INSTRUCTION_TYPE_ASC */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_DCL */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_MOV */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_MOVSR */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_ADD */  {EFLAG_MODIFY, EFLAG_MODIFY, EFLAG_MODIFY,EFLAG_MODIFY, EFLAG_MODIFY, EFLAG_MODIFY},
	/* INSTRUCTION_TYPE_XADD */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_ADC */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_SUB */ {EFLAG_MODIFY, EFLAG_MODIFY, EFLAG_MODIFY,EFLAG_MODIFY, EFLAG_MODIFY, EFLAG_MODIFY},
	/* INSTRUCTION_TYPE_SBB */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_INC */ {EFLAG_MODIFY, EFLAG_MODIFY, EFLAG_MODIFY,EFLAG_MODIFY},
	/* INSTRUCTION_TYPE_DEC */ {EFLAG_MODIFY, EFLAG_MODIFY, EFLAG_MODIFY,EFLAG_MODIFY},
	/* INSTRUCTION_TYPE_DIV */ {EFLAG_UNDEF, EFLAG_UNDEF, EFLAG_UNDEF,EFLAG_UNDEF, EFLAG_UNDEF, EFLAG_UNDEF},
	/* INSTRUCTION_TYPE_IDIV */ {EFLAG_UNDEF, EFLAG_UNDEF, EFLAG_UNDEF,EFLAG_UNDEF, EFLAG_UNDEF, EFLAG_UNDEF},
	/* INSTRUCTION_TYPE_NOT */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_NEG */ {EFLAG_MODIFY, EFLAG_MODIFY, EFLAG_MODIFY,EFLAG_MODIFY, EFLAG_MODIFY, EFLAG_MODIFY},
	/* INSTRUCTION_TYPE_STOS */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_LODS */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_SCAS */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_MOVS */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_MOVSX */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_MOVZX */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_CMPS */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_SHX */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_ROX, */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_MUL */ {EFLAG_MODIFY, EFLAG_UNDEF, EFLAG_UNDEF,EFLAG_UNDEF, EFLAG_UNDEF, EFLAG_MODIFY},
	/* INSTRUCTION_TYPE_IMUL */ {EFLAG_MODIFY, EFLAG_UNDEF, EFLAG_UNDEF,EFLAG_UNDEF, EFLAG_UNDEF, EFLAG_MODIFY},
	/* INSTRUCTION_TYPE_EIMUL, */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_XOR */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_LEA */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_XCHG */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_CMP */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_TEST */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_PUSH */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_AND */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_OR */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_POP */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_JMP */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_JMPC */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_JECXZ */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_SETC */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_MOVC */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_LOOP */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_CALL */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_RET */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_ENTER */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_INT */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_BT */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_BTS */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_BTR */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_BTC */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_BSF */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_BSR */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_BSWAP */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_SGDT */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_SIDT */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_SLDT */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_LFP */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_CLD */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_STD */ {EFLAG_NOT_IMPL},
	/* INSTRUCTION_TYPE_XLAT */ {EFLAG_NOT_IMPL},
}; 

#define MAX(X, Y) (((X) > (Y))?(X):(Y))
/* Index + 1 of the last element in the x86reg_table */
#define SCRATCH_REGISTER_BASE (sizeof(x86reg_table)/sizeof(x86reg_table[0][0]))
/* First element of the 9th row in x86reg_table */
#define EFLAGS_REGISTER_BASE 9*8 
/* The explicit eflags registers have a size of one byte */
#define EFLAGS_REGISTER_SIZE 1
#define MAX_SCRATCH_REGISTERS 256

static reil_register REG_CF = { .index = EFLAGS_REGISTER_BASE, .size = EFLAGS_REGISTER_SIZE};
static reil_register REG_PF = { .index = EFLAGS_REGISTER_BASE + 2, .size = EFLAGS_REGISTER_SIZE};
static reil_register REG_AF = { .index = EFLAGS_REGISTER_BASE + 4, .size = EFLAGS_REGISTER_SIZE};
static reil_register REG_ZF = { .index = EFLAGS_REGISTER_BASE + 6, .size = EFLAGS_REGISTER_SIZE};
static reil_register REG_SF = { .index = EFLAGS_REGISTER_BASE + 7, .size = EFLAGS_REGISTER_SIZE};
static reil_register REG_OF = { .index = EFLAGS_REGISTER_BASE + 11, .size = EFLAGS_REGISTER_SIZE};

typedef struct _translation_context
{
    /* The instruction being translated */
    INSTRUCTION * x86instruction;
    unsigned long base;
    unsigned long offset;
    /* Buffer used to store intermediate result of the translation process. */
    reil_instruction instruction_buffer[REIL_MAX_INSTRUCTIONS];
    reil_instruction * instruction_sort_buffer[REIL_MAX_INSTRUCTIONS];
    size_t num_of_instructions;
    /* Last reil instruction offset */
    size_t last_offset;
    size_t next_free_register;
} translation_context;

typedef enum 
{
    INTEGER_OFFSET,
    REGISTER_OFFSET
} memory_offset_type;

typedef struct
{
    memory_offset_type type;
    union
    {
        reil_register reg;
        reil_integer integer;
    };
} memory_offset;

static size_t get_x86operand_size(INSTRUCTION * x86instruction, OPERAND * x86operand);
static void get_x86operand_basereg(PINSTRUCTION x86instruction, POPERAND x86operand, reil_register * base);
static void get_x86operand_indexreg(PINSTRUCTION x86instruction, POPERAND x86operand, reil_register * index);
static void init_translation_context(translation_context * context, INSTRUCTION * x86instruction, unsigned long base, unsigned long offset);
static void calculate_memory_offset(translation_context * context, POPERAND x86operand, memory_offset * offset);
static void alloc_temp_reg(translation_context * context, size_t size, reil_register * temp_reg);
static reil_instruction * alloc_reil_instruction(translation_context * context, reil_instruction_index index);
static void get_reil_reg_from_x86_op(translation_context * context, POPERAND op, reil_register * reg);
static unsigned char get_reil_int_from_x86_op(translation_context * context, POPERAND op, reil_integer * integer);

static void assign_operand_register(reil_operand * operand, reil_register * reg);
static void assign_operand_integer(reil_operand * operand, reil_integer * integer);
static void assign_reg_reg(reil_register * src, reil_register * dest);

/* Basic REIL instruction generation functions */
static void gen_unknown(translation_context * context);
static void gen_undef_reg(translation_context * context, reil_register * reg);
static void gen_mov_reg_reg(translation_context * context, reil_register * src, reil_register * dest);
static void gen_mov_int_reg(translation_context * context, reil_integer * src, reil_register * dest);
static void gen_set_reg(translation_context * context , reil_register * reg);
static void gen_reset_reg(translation_context * context , reil_register * reg);
static void gen_store_reg_reg(translation_context * context, reil_register * value, reil_register * address);
static void gen_store_reg_int(translation_context * context, reil_register * value, reil_integer * address);
static void gen_load_reg_reg(translation_context * context, reil_register * address, reil_register * value);
static void gen_load_int_reg(translation_context * context, reil_integer * address, reil_register * value);
static void gen_add_reg_int_reg(translation_context * context, reil_register * addend1, reil_integer * addend2, reil_register * result);
static void gen_add_reg_reg_reg(translation_context * context, reil_register * addend1, reil_register * addend2, reil_register * result);
static void gen_multiply_reg_int_reg(translation_context * context, reil_register * multiplicand, reil_integer * multiplier, reil_register * result);
static void gen_reduce_reg_int_reg(translation_context * context, reil_register * reg, reil_integer * size, reil_register * result);
static void gen_shx_reg_int_reg(translation_context * context, reil_instruction_index shift_op, reil_register * src, reil_integer * shifts, reil_register * result);
static void gen_shx_reg_reg_reg(translation_context * context, reil_instruction_index shift_op, reil_register * src, reil_register * shifts, reil_register * result);
static void gen_shl_reg_int_reg(translation_context * context, reil_register * src, reil_integer * shifts, reil_register * result);
static void gen_shr_reg_int_reg(translation_context * context, reil_register * src, reil_integer * shifts, reil_register * result);
static void gen_shl_reg_reg_reg(translation_context * context, reil_register * src, reil_register * shifts, reil_register * result);
static void gen_shr_reg_reg_reg(translation_context * context, reil_register * src, reil_register * shifts, reil_register * result);
static void gen_and_reg_reg_reg(translation_context * context, reil_register * reg1, reil_register * reg2, reil_register * result);
static void gen_and_reg_int_reg(translation_context * context, reil_register * reg, reil_integer * integer, reil_register * result);
static void gen_xor_reg_int_reg(translation_context * context, reil_register * input1, reil_integer * input2, reil_register * result);
static void gen_xor_reg_reg_reg(translation_context * context, reil_register * input1, reil_register * input2, reil_register * result);
static void gen_or_reg_reg_reg(translation_context * context, reil_register * input1, reil_register * input2, reil_register * result);

static void gen_is_zero_reg_reg(translation_context * context, reil_register * input, reil_register * output);
static void gen_is_not_zero_reg_reg(translation_context * context, reil_register * input, reil_register * output);

static void gen_eflags_update(translation_context * context, reil_operand * op1, reil_operand * op2, reil_operand * op3);

/* REIL instruction group generation functions */
static void gen_arithmetic_instr(translation_context * context, reil_instruction_index index);
static void gen_mov_instr(translation_context *ctx);
static void gen_push_instr(translation_context * context);
static void gen_pop_instr(translation_context * context);
static void gen_ret_instr(translation_context * context);
static void gen_call_instr(translation_context *ctx);

reil_instructions * reil_translate_from_x86(unsigned long base, unsigned long offset, INSTRUCTION * x86instruction)
{
    translation_context context;
    init_translation_context(&context, x86instruction, base, offset);

    reil_instructions * instructions = NULL;

    switch (x86instruction->type)
    {
        case INSTRUCTION_TYPE_ADD:
            {
                gen_arithmetic_instr(&context, REIL_ADD);
            }
            break;
        case INSTRUCTION_TYPE_SUB:
            {
                gen_arithmetic_instr(&context, REIL_SUB);
            }
            break;
        case INSTRUCTION_TYPE_MUL:
            {
                gen_arithmetic_instr(&context, REIL_MUL);
            }
            break;
        case INSTRUCTION_TYPE_IMUL:
            {
                gen_arithmetic_instr(&context, REIL_MUL);
            }
            break;
        case INSTRUCTION_TYPE_DIV:
            {
                gen_arithmetic_instr(&context, REIL_DIV);
            }
            break;
        case INSTRUCTION_TYPE_IDIV:
            {
                gen_arithmetic_instr(&context, REIL_DIV);
            }
            break;
        case INSTRUCTION_TYPE_MOV:
		gen_mov_instr(&context);
		break;
        case INSTRUCTION_TYPE_CALL:
		gen_call_instr(&context);
		break;
        case INSTRUCTION_TYPE_PUSH:
		gen_push_instr(&context);
		break;
        case INSTRUCTION_TYPE_POP:
		gen_pop_instr(&context);
		break;
        case INSTRUCTION_TYPE_RET:
		gen_ret_instr(&context);
		break;
        default:
            {
                gen_unknown(&context);
            }
            break;
    }

    if ( context.num_of_instructions > 0)
    {
        instructions = malloc(sizeof(reil_instructions) + context.num_of_instructions * sizeof(reil_instruction));
        if (!instructions)
        {
            fprintf(stderr, "Failed to allocate memory for translated instructions!");
            exit(EXIT_FAILURE);
        }
        instructions->size = context.num_of_instructions;

        size_t i, j;
        /* Prepare sort buffer for sorting */
        for ( i = 0; i < context.num_of_instructions; i++)
        {
            context.instruction_sort_buffer[i] = &context.instruction_buffer[i];
        }

        /* Bubblesort the sort buffer. */
        for ( i = 0; i < context.num_of_instructions - 1; i++)
        {
            for ( j = i+1; j < context.num_of_instructions; j++ )
            {
                if ( context.instruction_sort_buffer[i]->offset > context.instruction_sort_buffer[j]->offset)
                {
                    reil_instruction * tmp = context.instruction_sort_buffer[i];
                    context.instruction_sort_buffer[i] = context.instruction_sort_buffer[j];
                    context.instruction_sort_buffer[j] = tmp;
                }
            }
        }

        /* Copy the sorted instructions */
        for ( i = 0; i < context.num_of_instructions; i++)
        {
            memcpy(&instructions->instruction[i], context.instruction_sort_buffer[i], sizeof(reil_instruction));
        }
    }
    else
    {
        fprintf(stderr, "Failed to translate instruction!");
        exit(EXIT_FAILURE);
    }

    return instructions;
}

size_t get_x86operand_size(INSTRUCTION * x86instruction, OPERAND * x86operand)
{
    size_t size = 0;
    switch (MASK_OT(x86operand->flags)) {
        case OT_b:
            size = 1;
            break;
        case OT_v:
            {
                enum Mode mode = MODE_CHECK_OPERAND(x86instruction->mode, x86instruction->flags);
                size = (mode == MODE_32)?4:2;
            }
            break;
        case OT_w:
            size = 2;
            break;
        case OT_d:
            size = 4;
            break;
    }
    return size;
}

static void get_x86operand_basereg(PINSTRUCTION x86instruction, POPERAND x86operand, reil_register * base)
{
    int basereg = get_operand_basereg(x86operand);
    if ( basereg == REG_NOP )
    {
        base->size = 0;
        return;
    }
    base->index = (REG_GEN_DWORD << 3) + basereg;
    /* Use the size of the operand for the correct size, instead of using
     * the size of the register. */
    base->size = get_x86operand_size(x86instruction, x86operand);
}

static void get_x86operand_indexreg(PINSTRUCTION x86instruction, POPERAND x86operand, reil_register * index)
{
    int indexreg = get_operand_indexreg(x86operand);
    if ( indexreg == REG_NOP )
    {
        index->size = 0;
        return;
    }
    index->index = (REG_GEN_DWORD << 3) + indexreg;
    /* Use the size of the operand for the correct size, instead of using
     * the size of the register. */
    index->size = get_x86operand_size(x86instruction, x86operand);
}

static void init_translation_context(translation_context * context, INSTRUCTION * x86instruction, unsigned long base, unsigned long offset)
{
    memset(context, 0, sizeof(*context));
    context->x86instruction = x86instruction;
    context->next_free_register = SCRATCH_REGISTER_BASE;
    context->base= base;
    context->offset= offset;
}

static void alloc_temp_reg(translation_context * context, size_t size, reil_register * temp_reg)
{
    temp_reg->index = context->next_free_register++;
    temp_reg->size = size;
}

static reil_instruction * alloc_reil_instruction(translation_context * context, reil_instruction_index index)
{
    reil_instruction * allocated_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(allocated_instruction, &reil_instruction_table[index], sizeof(*allocated_instruction));
    allocated_instruction->address = REIL_ADDRESS(context->base, context->offset);
    allocated_instruction->offset = context->last_offset++;

    return allocated_instruction;
}

static void gen_unknown(translation_context * context)
{
    reil_instruction * unknown_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(unknown_instruction, &reil_instruction_table[REIL_UNKN], sizeof(reil_instruction));

    unknown_instruction->address = REIL_ADDRESS(context->base, context->offset);
    unknown_instruction->offset = context->last_offset++;
}

static void gen_undef_reg(translation_context * context, reil_register * reg)
{
    reil_instruction * undef = alloc_reil_instruction(context, REIL_UNDEF);

    assign_operand_register(&undef->operands[2], reg);
}

static void gen_mov_reg_reg(translation_context * context, reil_register * src, reil_register * dest)
{
    reil_instruction * store_instruction = alloc_reil_instruction(context, REIL_STR);

    assign_operand_register(&store_instruction->operands[0], src);
    assign_operand_register(&store_instruction->operands[2], dest);
}

static void gen_mov_int_reg(translation_context * context, reil_integer * src, reil_register * dest)
{
    reil_instruction * store_instruction = alloc_reil_instruction(context, REIL_STR);

    assign_operand_integer(&store_instruction->operands[0], src);
    assign_operand_register(&store_instruction->operands[2], dest);
}

static void gen_set_reg(translation_context * context , reil_register * reg)
{
    reil_integer one = {.value = 1, .size = reg->size};
    gen_mov_int_reg(context, &one, reg);
}

static void gen_reset_reg(translation_context * context , reil_register * reg)
{
    reil_integer zero = {.value = 0, .size = reg->size};
    gen_mov_int_reg(context, &zero, reg);
}

static void gen_store_reg_reg(translation_context * context, reil_register * value, reil_register * address)
{
    reil_instruction * store_instruction = alloc_reil_instruction(context, REIL_STM);

    assign_operand_register(&store_instruction->operands[0], value);
    assign_operand_register(&store_instruction->operands[2], address);
}

static void gen_store_reg_int(translation_context * context, reil_register * value, reil_integer * address)
{
    reil_instruction * store_instruction = alloc_reil_instruction(context, REIL_STM);

    assign_operand_register(&store_instruction->operands[0], value);
    assign_operand_integer(&store_instruction->operands[2], address);
}

static void gen_load_reg_reg(translation_context * context, reil_register * address, reil_register * value)
{
    reil_instruction * load_instruction = alloc_reil_instruction(context, REIL_LDM);

    assign_operand_register(&load_instruction->operands[0], address);

    if ( !value->size )
    {
        alloc_temp_reg(context, address->size, value);
    }
    assign_operand_register(&load_instruction->operands[2], value);
}

static void gen_load_int_reg(translation_context * context, reil_integer * address, reil_register * value)
{
    reil_instruction * load_instruction = alloc_reil_instruction(context, REIL_LDM);

    assign_operand_integer(&load_instruction->operands[0], address);
    
    if ( !value->size )
    {
        alloc_temp_reg(context, address->size, value);
    }
    assign_operand_register(&load_instruction->operands[2], value);
}

static void gen_add_reg_int_reg(translation_context * context, reil_register * addend1, reil_integer * addend2, reil_register * result)
{
    reil_instruction * add_instruction = alloc_reil_instruction(context, REIL_ADD);

    assign_operand_register(&add_instruction->operands[0], addend1);
    assign_operand_integer(&add_instruction->operands[1], addend2);

    if ( !result->size )
    {
        alloc_temp_reg(context, 2 * MAX(addend1->size, addend2->size), result);
    }
    assign_operand_register(&add_instruction->operands[2], result);
}

static void gen_add_reg_reg_reg(translation_context * context, reil_register * addend1, reil_register * addend2, reil_register * result)
{
    reil_instruction * add_instruction = alloc_reil_instruction(context, REIL_ADD);

    assign_operand_register(&add_instruction->operands[0], addend1);
    assign_operand_register(&add_instruction->operands[1], addend2);

    if ( !result->size )
    {
        alloc_temp_reg(context, 2 * MAX(addend1->size, addend2->size), result);
    }
    assign_operand_register(&add_instruction->operands[2], result);
}

static void gen_multiply_reg_int_reg(translation_context * context, reil_register * multiplicand, reil_integer * multiplier, reil_register * result)
{
    reil_instruction * multiply_instruction = alloc_reil_instruction(context, REIL_MUL);

    assign_operand_register(&multiply_instruction->operands[0], multiplicand);
    assign_operand_integer(&multiply_instruction->operands[1], multiplier);

    if ( !result->size )
    {
        alloc_temp_reg(context,2 * MAX(multiplicand->size, multiplier->size), result);
    }
    assign_operand_register(&multiply_instruction->operands[2], result);
}

static void gen_reduce_reg_int_reg(translation_context * context, reil_register * reg, reil_integer * size, reil_register * result)
{
    reil_instruction * reduce  = alloc_reil_instruction(context, REIL_AND);

    assign_operand_register(&reduce->operands[0], reg);

    reil_integer mask = {.value = (((1 << ((size->value << 3) - 1)) - 1) << 1) | 1, .size = size->value};

    assign_operand_integer(&reduce->operands[1], &mask);
    
    alloc_temp_reg(context, size->value, result);

    assign_operand_register(&reduce->operands[2], result);
}

static void gen_shx_reg_int_reg(translation_context * context, reil_instruction_index shift_op, reil_register * src, reil_integer * shifts, reil_register * result)
{
    reil_instruction * shift = alloc_reil_instruction(context, shift_op);

    assign_operand_register(&shift->operands[0], src);
    assign_operand_integer(&shift->operands[1], shifts);

    if ( !result->size )
    {
        alloc_temp_reg(context, src->size, result);
    }
    assign_operand_register(&shift->operands[2], result);
}

static void gen_shx_reg_reg_reg(translation_context * context, reil_instruction_index shift_op, reil_register * src, reil_register * shifts, reil_register * result)
{
    reil_instruction * shift = alloc_reil_instruction(context, shift_op);

    assign_operand_register(&shift->operands[0], src);
    assign_operand_register(&shift->operands[1], shifts);

    if ( !result->size )
    {
        alloc_temp_reg(context, src->size, result);
    }
    assign_operand_register(&shift->operands[2], result);
}

static void gen_shl_reg_int_reg(translation_context * context, reil_register * src, reil_integer * shifts, reil_register * result)
{
    return gen_shx_reg_int_reg(context, REIL_LSH, src, shifts, result);
}

static void gen_shr_reg_int_reg(translation_context * context, reil_register * src, reil_integer * shifts, reil_register * result)
{
    return gen_shx_reg_int_reg(context, REIL_RSH, src, shifts, result);
}

static void gen_shl_reg_reg_reg(translation_context * context, reil_register * src, reil_register * shifts, reil_register * result)
{
    return gen_shx_reg_reg_reg(context, REIL_LSH, src, shifts, result);
}

static void gen_shr_reg_reg_reg(translation_context * context, reil_register * src, reil_register * shifts, reil_register * result)
{
    return gen_shx_reg_reg_reg(context, REIL_RSH, src, shifts, result);
}

static void gen_and_reg_reg_reg(translation_context * context, reil_register * reg1, reil_register * reg2, reil_register * result)
{
    reil_instruction * and = alloc_reil_instruction(context, REIL_AND);

    assign_operand_register(&and->operands[0], reg1);
    assign_operand_register(&and->operands[1], reg2);
    
    if (!result->index && !result->size)
    {
        alloc_temp_reg(context, MAX(reg1->size, reg2->size), result);
    }

    assign_operand_register(&and->operands[2], result);
}

static void gen_and_reg_int_reg(translation_context * context, reil_register * reg, reil_integer * integer, reil_register * result)
{
    reil_instruction * and = alloc_reil_instruction(context, REIL_AND);

    assign_operand_register(&and->operands[0], reg);
    assign_operand_integer(&and->operands[1], integer);

    if (!result->index && !result->size)
    {
        alloc_temp_reg(context, reg->size, result);
    }

    assign_operand_register(&and->operands[2], result);
}

static void gen_xor_reg_int_reg(translation_context * context, reil_register * input1, reil_integer * input2, reil_register * result)
{
    reil_instruction * xor = alloc_reil_instruction(context, REIL_XOR);

    assign_operand_register(&xor->operands[0], input1);
    assign_operand_integer(&xor->operands[1], input2);
    
    if (!result->index && !result->size)
    {
        alloc_temp_reg(context, input1->size, result);
    }
    
    assign_operand_register(&xor->operands[2], result);
}

static void gen_xor_reg_reg_reg(translation_context * context, reil_register * input1, reil_register * input2, reil_register * result)
{
    reil_instruction * xor = alloc_reil_instruction(context, REIL_XOR);

    assign_operand_register(&xor->operands[0], input1);
    assign_operand_register(&xor->operands[1], input2);
    
    if (!result->index && !result->size)
    {
        alloc_temp_reg(context, MAX(input1->size, input2->size), result);
    }
    
    assign_operand_register(&xor->operands[2], result);
}

static void gen_or_reg_reg_reg(translation_context * context, reil_register * input1, reil_register * input2, reil_register * result)
{
    reil_instruction * or = alloc_reil_instruction(context, REIL_OR);

    assign_operand_register(&or->operands[0], input1);
    assign_operand_register(&or->operands[1], input2);
    
    if (!result->index && !result->size)
    {
        alloc_temp_reg(context, MAX(input1->size, input2->size), result);
    }
    
    assign_operand_register(&or->operands[2], result);
}

static void gen_is_zero_reg_reg(translation_context * context, reil_register * input, reil_register * output)
{
    reil_instruction * is_zero = alloc_reil_instruction(context, REIL_BISZ);

    assign_operand_register(&is_zero->operands[0], input);
    assign_operand_register(&is_zero->operands[2], output);
}

static void gen_is_not_zero_reg_reg(translation_context * context, reil_register * input, reil_register * output)
{
    reil_instruction * is_zero = alloc_reil_instruction(context, REIL_BISZ);

    assign_operand_register(&is_zero->operands[0], input);

    reil_register temp_output;
    alloc_temp_reg(context, output->size, &temp_output);
    
    assign_operand_register(&is_zero->operands[2], &temp_output);

    reil_integer mask= {.value = 1, .size = 1};
    reil_register xor_result = {.index = 0, .size = 0};
    gen_xor_reg_int_reg(context, &temp_output, &mask, &xor_result);
    gen_mov_reg_reg(context, &xor_result, output);
}

static void gen_eflags_update(translation_context * context, reil_operand * op1, reil_operand * op2, reil_operand * op3)
{
    if (eflags_cross_reference[context->x86instruction->type].ef_cf & EFLAG_MODIFY)
    {
        reil_integer shifts = {.value = (op3->reg.size << 2) - 1, .size = 1};
        reil_register shifted = {.index = 0, .size = 0};
        gen_shr_reg_int_reg(context, &op3->reg, &shifts, &shifted);

        reil_integer size = {.value = EFLAGS_REGISTER_SIZE, .size = 1};
        reil_register carry;

        gen_reduce_reg_int_reg(context, &shifted, &size, &carry);
        gen_mov_reg_reg(context, &carry, &REG_CF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_cf & EFLAG_UNDEF)
    {
        gen_undef_reg(context, &REG_CF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_cf & EFLAG_RESET)
    {
        gen_reset_reg(context, &REG_CF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_cf & EFLAG_SET)
    {
        gen_set_reg(context, &REG_CF);
    }

    /* Source: http://graphics.stanford.edu/~seander/bithacks.html#ParityParallel 
     * unsigned char byte;
     * byte ^= byte >> 4;
     * byte &= 0xf;
     * unsigned char parity = (0x6996 >> byte) & 1;
     * */
    if (eflags_cross_reference[context->x86instruction->type].ef_pf & EFLAG_MODIFY)
    {
        /* Get the least-significant byte of the result */
        reil_integer lsb_size = {.value = 1, .size = 1};
        reil_register lsb;
        gen_reduce_reg_int_reg(context, &op3->reg, &lsb_size, &lsb);
        /* Shift the lsb by four bytes */
        reil_integer shifts = {.value = 4, .size = 1};
        reil_register shifted_lsb = {.index = 0, .size = 0};
        gen_shr_reg_int_reg(context, &lsb, &shifts, &shifted_lsb);
        /* XOR the lower and higher nibles to compress the output in the lower nibble */
        reil_register compressed_lsb = {.index = 0, .size = 0};
        gen_xor_reg_reg_reg(context, &lsb, &shifted_lsb, &compressed_lsb);
        /* Obtain an index into the parity lookup table by removing the higher nibble */
        reil_integer lower_nibble_mask = {.value = 0xf, .size = 1};
        reil_register parity_index = {.index = 0, .size = 0};
        gen_and_reg_int_reg(context, &compressed_lsb, &lower_nibble_mask, &parity_index);
        /* Store the parity lookup table into a temporary register */
        reil_register parity_lookup_table;
        alloc_temp_reg(context, 2, &parity_lookup_table);

        reil_integer parity_lookup_table_value = {.value = 0x6996, .size = 2};
        gen_mov_int_reg(context, &parity_lookup_table_value, &parity_lookup_table);
        /* Lookup the parity value in the lookup table */
        reil_register parity_lookup_table_entry = {.index = 0, .size = 0};
        gen_shr_reg_reg_reg(context, &parity_lookup_table, &parity_index, &parity_lookup_table_entry);

        reil_integer parity_mask = {.value = 1, .size = 1};
        reil_register parity = {.index = 0, .size = 0};
        gen_and_reg_int_reg(context, &parity_lookup_table_entry, &parity_mask, &parity);

        reil_integer eflags_reg_size = {.value = EFLAGS_REGISTER_SIZE, .size = 1};
        reil_register reduced_parity;
        gen_reduce_reg_int_reg(context, &parity, &eflags_reg_size, &reduced_parity);

        gen_mov_reg_reg(context, &reduced_parity, &REG_PF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_pf & EFLAG_UNDEF)
    {
        gen_undef_reg(context, &REG_PF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_pf & EFLAG_RESET)
    {
        gen_reset_reg(context, &REG_PF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_pf & EFLAG_SET)
    {
        gen_set_reg(context, &REG_PF);
    }

    if (eflags_cross_reference[context->x86instruction->type].ef_af & EFLAG_MODIFY)
    {
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_af & EFLAG_UNDEF)
    {
        gen_undef_reg(context, &REG_AF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_af & EFLAG_RESET)
    {
        gen_reset_reg(context, &REG_AF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_af & EFLAG_SET)
    {
        gen_set_reg(context, &REG_AF);
    }

    if (eflags_cross_reference[context->x86instruction->type].ef_zf & EFLAG_MODIFY)
    {
        gen_is_zero_reg_reg(context, &op3->reg, &REG_ZF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_zf & EFLAG_UNDEF)
    {
        gen_undef_reg(context, &REG_ZF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_zf & EFLAG_RESET)
    {
        gen_reset_reg(context, &REG_ZF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_zf & EFLAG_SET)
    {
        gen_set_reg(context, &REG_ZF);
    }

    if (eflags_cross_reference[context->x86instruction->type].ef_sf & EFLAG_MODIFY)
    {
        /* Shift the MSB to the LSB */
        reil_integer shifts = {.value = (op3->reg.size << 3) - 1, .size = 1};
        reil_register sign_status = {.index = 0, .size = 0};
        gen_shr_reg_int_reg(context, &op3->reg, &shifts, &sign_status);

        reil_integer size = {.value = EFLAGS_REGISTER_SIZE, .size = 1};
        reil_register sign_flag;
        gen_reduce_reg_int_reg(context, &sign_status, &size, &sign_flag);

        gen_mov_reg_reg(context, &sign_flag, &REG_SF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_sf & EFLAG_UNDEF)
    {
        gen_undef_reg(context, &REG_SF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_sf & EFLAG_RESET)
    {
        gen_reset_reg(context, &REG_SF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_sf & EFLAG_SET)
    {
        gen_set_reg(context, &REG_SF);
    }

    if (eflags_cross_reference[context->x86instruction->type].ef_of & EFLAG_MODIFY)
    {
        /* For addition we can use the formula !(INPUT1_SIGN ^ INPUT2_SIGN) && (INPUT1_SIGN ^ OUTPUT_SIGN),
         * which generates the following truth table.
         *
         * INPUT1 | INPUT2 | OUTPUT | OF
         * -------#--------#--------#---
         *      0 |      0 |      0 |  0
         * -------#--------#--------#---
         *      0 |      0 |      1 |  1
         * -------#--------#--------#---
         *      0 |      1 |      0 |  0
         * -------#--------#--------#---
         *      0 |      1 |      1 |  0
         * -------#--------#--------#---
         *      1 |      0 |      0 |  0
         * -------#--------#--------#---
         *      1 |      0 |      1 |  0
         * -------#--------#--------#---
         *      1 |      1 |      0 |  1
         * -------#--------#--------#---
         *      1 |      1 |      1 |  0
         * -------#--------#--------#---
         *
         * */
        if (context->x86instruction->type == INSTRUCTION_TYPE_ADD )
        {
            reil_register xored_inputs = {.index = 0, .size = 0};
            if ( op2->type == REIL_OPERAND_TYPE_REGISTER )
            {
                gen_xor_reg_reg_reg(context, &op1->reg, &op2->reg, &xored_inputs);
            }
            else /* REIL_OPERAND_TYPE_INTEGER */
            {
                gen_xor_reg_int_reg(context, &op1->reg, &op2->integer, &xored_inputs);
            }

            reil_integer mask = {.value = -1, .size = xored_inputs.size};
            reil_register neg_xored_inputs = {.index = 0, .size = 0};
            gen_xor_reg_int_reg(context, &xored_inputs, &mask, &neg_xored_inputs);

            reil_register xored_input1_output = {.index = 0, .size = 0};
            gen_xor_reg_reg_reg(context, &op1->reg, &op3->reg, &xored_input1_output);

            reil_register anded_result = {.index = 0, .size = 0};
            gen_and_reg_reg_reg(context, &neg_xored_inputs, &xored_input1_output, &anded_result);

            /* The value of the OF flag is now in the sign bit of the anded result */
            reil_integer shifts = {.value = (anded_result.size << 3) - 1, .size = 1};
            reil_register overflow_status = {.index = 0, .size = 0};
            gen_shr_reg_int_reg(context, &anded_result, &shifts, &overflow_status);

            /* Reduce the size */
            reil_integer size = {.value = EFLAGS_REGISTER_SIZE, .size = 1};
            reil_register overflow_flag = {0};
            gen_reduce_reg_int_reg(context, &overflow_status, &size, &overflow_flag);

            gen_mov_reg_reg(context, &overflow_flag, &REG_OF);

        }

        /* For substraction we can use the formula (INPUT1_SIGN ^ INPUT2_SIGN) && (INPUT1_SIGN ^ OUTPUT_SIGN),
         * which generates the following truth table.
         *
         * INPUT1 | INPUT2 | OUTPUT | OF
         * -------#--------#--------#---
         *      0 |      0 |      0 |  0
         * -------#--------#--------#---
         *      0 |      0 |      1 |  0
         * -------#--------#--------#---
         *      0 |      1 |      0 |  0
         * -------#--------#--------#---
         *      0 |      1 |      1 |  1
         * -------#--------#--------#---
         *      1 |      0 |      0 |  1
         * -------#--------#--------#---
         *      1 |      0 |      1 |  0
         * -------#--------#--------#---
         *      1 |      1 |      0 |  0
         * -------#--------#--------#---
         *      1 |      1 |      1 |  0
         * -------#--------#--------#---
         *
         * */
        if (context->x86instruction->type == INSTRUCTION_TYPE_SUB)
        {
            reil_register xored_inputs = {.index = 0, .size = 0};
            if ( op2->type == REIL_OPERAND_TYPE_REGISTER )
            {
                gen_xor_reg_reg_reg(context, &op1->reg, &op2->reg, &xored_inputs);
            }
            else /* REIL_OPERAND_TYPE_INTEGER */
            {
                gen_xor_reg_int_reg(context, &op1->reg, &op2->integer, &xored_inputs);
            }

            reil_register xored_input1_output = {.index = 0, .size = 0};
            gen_xor_reg_reg_reg(context, &op1->reg, &op3->reg, &xored_input1_output);

            reil_register anded_result = {.index = 0, .size = 0};
            gen_and_reg_reg_reg(context, &xored_inputs, &xored_input1_output, &anded_result);

            /* The value of the OF flag is now in the sign bit of the anded result */
            reil_integer shifts = {.value = (anded_result.size << 3) - 1, .size = 1};
            reil_register overflow_status = {0};
            gen_shr_reg_int_reg(context, &anded_result, &shifts, &overflow_status);

            /* Reduce the size */
            reil_integer size = {.value = EFLAGS_REGISTER_SIZE, .size = 1};
            reil_register overflow_flag;
            gen_reduce_reg_int_reg(context, &overflow_status, &size, &overflow_flag);

            gen_mov_reg_reg(context, &overflow_flag, &REG_OF);

        }
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_of & EFLAG_UNDEF)
    {
        gen_undef_reg(context, &REG_OF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_of & EFLAG_RESET)
    {
        gen_reset_reg(context, &REG_OF);
    }
    else if (eflags_cross_reference[context->x86instruction->type].ef_of & EFLAG_SET)
    {
        gen_set_reg(context, &REG_OF);
    }
}

static void calculate_memory_offset(translation_context * context, POPERAND x86operand, memory_offset * offset)
{
    /* Offset = Base + (Index * Scale) + Displacement */
    size_t operand_size = get_x86operand_size(context->x86instruction, x86operand);
    reil_register base = {0};
    get_x86operand_basereg(context->x86instruction, x86operand, &base);
    reil_register index = {0};
    get_x86operand_indexreg(context->x86instruction, x86operand, &index);
    reil_integer scale = {.value = get_operand_scale(x86operand), .size = operand_size};
    reil_integer displacement = { .value = 0, .size = operand_size};
    int has_displacement = get_operand_displacement(x86operand, (unsigned int*)&displacement.value);

    memset(offset, 0, sizeof(*offset));
    /* We assume it is a register, because this is the most common case. */
    offset->type = REGISTER_OFFSET;

    if ( index.size != 0 )
    {
        if ( scale.value )
        {
            gen_multiply_reg_int_reg(context, &index, &scale, &offset->reg);
        }
        else
        {
            offset->reg.index = index.index;
            offset->reg.size = index.size;
        }
    }

    if ( base.size != 0)
    {
        if ( offset->reg.size )
        {
            reil_register new_offset = {0};
            gen_add_reg_reg_reg(context, &base, &offset->reg, &new_offset);
            assign_reg_reg(&new_offset, &offset->reg);
        }
        else
        {
            offset->reg.index = base.index;
            offset->reg.size = base.size;
        }
    }

    if ( has_displacement )
    {
        if ( offset->reg.size )
        {
            reil_register displaced_offset = {0};
            gen_add_reg_int_reg(context, &offset->reg, &displacement, &displaced_offset);
            assign_reg_reg(&displaced_offset, &offset->reg);
        }
        else
        {
            offset->type = INTEGER_OFFSET;
            offset->integer.value = displacement.value;
            offset->integer.size = displacement.size;
        }
    }
}

/*
 * Get this operand in a register. If it's an immediate, load the immediate. If
 * it's a register, get a reil register for it. If it's a memory address, load
 * the _address_ in a register.
 */
static void get_reil_reg_for_op(translation_context *ctx, POPERAND op, reil_register *r)
{
	memory_offset offset;

	if (op->type == OPERAND_TYPE_NONE)
		errx(3, "can't get a register for non-existing operand");

	if (op->type == OPERAND_TYPE_REGISTER) {
		get_reil_reg_from_x86_op(ctx, op, r);
		return;
	}
	if (op->type == OPERAND_TYPE_IMMEDIATE) {
		reil_integer imm;
		get_reil_int_from_x86_op(ctx, op, &imm);
		gen_load_int_reg(ctx, &imm, r);
		return;
	}
	calculate_memory_offset(ctx, op, &offset);
	if (offset.type == REGISTER_OFFSET) {
		memcpy(r, &offset.reg, sizeof(*r));
	} else {	/* INTEGER_OFFSET */
		gen_load_int_reg(ctx, &offset.integer, r);
	}
}

static void gen_mov_instr(translation_context *ctx)
{
	INSTRUCTION *x86_insn = ctx->x86instruction;

	if (x86_insn->op1.type == OPERAND_TYPE_REGISTER && x86_insn->op2.type == OPERAND_TYPE_REGISTER) {
		reil_register src, dest;
		get_reil_reg_from_x86_op(ctx, &x86_insn->op2, &src);
		get_reil_reg_from_x86_op(ctx, &x86_insn->op1, &dest);
		gen_mov_reg_reg(ctx, &src, &dest);
	} else if ( x86_insn->op1.type == OPERAND_TYPE_MEMORY && x86_insn->op2.type == OPERAND_TYPE_REGISTER) {
		memory_offset offset;
		calculate_memory_offset(ctx, &x86_insn->op1, &offset);

		if ( offset.type == REGISTER_OFFSET ) {
                        reil_register value;
                        get_reil_reg_from_x86_op(ctx, &x86_insn->op2, &value);
                        gen_store_reg_reg(ctx, &value, &offset.reg);
		} else { /* INTEGER_OFFSET */
                        reil_register value;
                        get_reil_reg_from_x86_op(ctx, &x86_insn->op2, &value);
                        gen_store_reg_int(ctx, &value, &offset.integer);
		}
	} else if (x86_insn->op1.type == OPERAND_TYPE_REGISTER && x86_insn->op2.type == OPERAND_TYPE_MEMORY) {
		memory_offset offset;
		calculate_memory_offset(ctx, &x86_insn->op2, &offset);

		if (offset.type == REGISTER_OFFSET) {
                        reil_register value = {.index = 0, .size = 0};
                        gen_load_reg_reg(ctx, &offset.reg, &value);

                        reil_register dest;
                        get_reil_reg_from_x86_op(ctx, &x86_insn->op1, &dest);
                        gen_mov_reg_reg(ctx, &value, &dest);
		} else { /* INTEGER_OFFSET */
                        reil_register value = {.index = 0, .size = 0};
                        gen_load_int_reg(ctx, &offset.integer, &value);
                        reil_register dest;
                        get_reil_reg_from_x86_op(ctx, &x86_insn->op1, &dest);
                        gen_mov_reg_reg(ctx, &value, &dest);
		}
	} else if (x86_insn->op1.type == OPERAND_TYPE_REGISTER && x86_insn->op2.type == OPERAND_TYPE_IMMEDIATE) {
		reil_integer immediate;
		if (get_reil_int_from_x86_op(ctx, &x86_insn->op2, &immediate)) {
                        reil_register dest;
                        get_reil_reg_from_x86_op(ctx, &x86_insn->op1, &dest);
                        gen_mov_int_reg(ctx, &immediate, &dest);
		} else {
                        gen_unknown(ctx);
		}
	} else if (x86_insn->op1.type == OPERAND_TYPE_MEMORY && x86_insn->op2.type == OPERAND_TYPE_IMMEDIATE) {
		reil_integer imm;
		reil_register value, dst;

		alloc_temp_reg(ctx, 4, &value);
		get_reil_int_from_x86_op(ctx, &x86_insn->op2, &imm);
		gen_mov_int_reg(ctx, &imm, &value);

		alloc_temp_reg(ctx, 4, &dst);
		get_reil_reg_for_op(ctx, &x86_insn->op1, &dst);

		gen_store_reg_reg(ctx, &value, &dst);
	} else {
		gen_unknown(ctx);
	}
}

static void gen_arithmetic_instr(translation_context * context, reil_instruction_index index)
{
    if ( context->x86instruction->op1.type == OPERAND_TYPE_REGISTER && context->x86instruction->op2.type == OPERAND_TYPE_IMMEDIATE)
    {
        reil_integer immediate;
        if ( get_reil_int_from_x86_op(context, &context->x86instruction->op2, &immediate))
        {
            reil_register op1_reg;
            get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &op1_reg);
            
            reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);

            assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_INPUT1], &op1_reg);
            assign_operand_integer(&arithmetic_instr->operands[REIL_OPERAND_INPUT2], &immediate);

            unsigned int reg_scale;
            if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
                reg_scale = 2;
            else
                reg_scale = 1;
            
            reil_register output; 
            alloc_temp_reg(context, reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg.size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].integer.size), &output);

            assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_OUTPUT], &output);

            reil_integer size = {.value = op1_reg.size, .size = 1};
            reil_register reduced_output;
            gen_reduce_reg_int_reg(context, &output, &size, &reduced_output);

            /* Update eflags here, so we have all the results intact without copying stuff. */
            reil_operand *op1, *op2, op3;
            op1 = &arithmetic_instr->operands[0];
            op2 = &arithmetic_instr->operands[1];
            assign_operand_register(&op3, &reduced_output);

            gen_eflags_update(context, op1, op2, &op3);

            gen_mov_reg_reg(context, &reduced_output, &op1_reg);
        }
        else
        {
            gen_unknown(context);
        }
    }
    else if ( context->x86instruction->op1.type == OPERAND_TYPE_REGISTER && context->x86instruction->op2.type == OPERAND_TYPE_REGISTER)
    {
        reil_register op1_reg, op2_reg;
        get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &op1_reg);
        get_reil_reg_from_x86_op(context, &context->x86instruction->op2, &op2_reg);

        reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);

        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_INPUT1], &op1_reg);
        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_INPUT2], &op2_reg);
        
        unsigned int reg_scale;
        if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
            reg_scale = 2;
        else
            reg_scale = 1;
        reil_register output;
        alloc_temp_reg(context, reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg.size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].reg.size), &output);

        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_OUTPUT], &output);
            
        reil_integer size = {.value = op1_reg.size, .size = 1};
        reil_register reduced_output;
        gen_reduce_reg_int_reg(context, &output, &size, &reduced_output);

        /* Update eflags here, so we have all the results intact without copying stuff. */
        reil_operand *op1, *op2, op3;
        op1 = &arithmetic_instr->operands[0];
        op2 = &arithmetic_instr->operands[1];
        assign_operand_register(&op3, &reduced_output);

        gen_eflags_update(context, op1, op2, &op3);

        gen_mov_reg_reg(context, &reduced_output, &op1_reg);
    }
    else if ( context->x86instruction->op1.type == OPERAND_TYPE_REGISTER && context->x86instruction->op2.type == OPERAND_TYPE_MEMORY)
    {
        memory_offset offset;

        calculate_memory_offset(context, &context->x86instruction->op2, &offset);

        reil_register value = {.index = 0, .size = 0};
        if (offset.type == REGISTER_OFFSET )
        {
            if ( context->x86instruction->mode == MODE_32 && offset.reg.size > 4 )
            {
                reil_integer size = {.value = 4, .size = 1};
                reil_register reduced_offset;
                gen_reduce_reg_int_reg(context, &offset.reg, &size, &reduced_offset);
                assign_reg_reg(&reduced_offset, &offset.reg);
            }

            if ( context->x86instruction->mode == MODE_16 && offset.reg.size > 2 )
            {
                reil_integer size = {.value = 2, .size = 1};
                reil_register reduced_offset;
                gen_reduce_reg_int_reg(context, &offset.reg, &size, &reduced_offset);
                assign_reg_reg(&reduced_offset, &offset.reg);
            }

            gen_load_reg_reg(context, &offset.reg, &value);
        }
        else /* REIL_OPERAND_INTEGER */
        {
            gen_load_int_reg(context, &offset.integer, &value);
        }

        reil_register op1_reg;
        get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &op1_reg);

        reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);
        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_INPUT1], &op1_reg);
        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_INPUT2], &value);
        
        unsigned int reg_scale;
        if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
            reg_scale = 2;
        else
            reg_scale = 1;
        reil_register output = {0};
        alloc_temp_reg(context, reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg.size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].reg.size), &output);

        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_OUTPUT], &output);

        reil_integer size = {.value = op1_reg.size, .size = 1};
        reil_register reduced_output = {0};
        gen_reduce_reg_int_reg(context, &output, &size, &reduced_output);

        /* Update eflags here, so we have all the results intact without copying stuff. */
        reil_operand *op1, *op2, op3;
        op1 = &arithmetic_instr->operands[0];
        op2 = &arithmetic_instr->operands[1];
        assign_operand_register(&op3, &reduced_output);

        gen_eflags_update(context, op1, op2, &op3);

        gen_mov_reg_reg(context, &reduced_output, &op1_reg);
    }
    else if (context->x86instruction->op1.type == OPERAND_TYPE_MEMORY && context->x86instruction->op2.type == OPERAND_TYPE_IMMEDIATE)
    {
        memory_offset offset;

        calculate_memory_offset(context, &context->x86instruction->op1, &offset);

        reil_register value = {0};
        if (offset.type == REGISTER_OFFSET )
        {
            gen_load_reg_reg(context, &offset.reg, &value);
        }
        else /* REIL_OPERAND_INTEGER */
        {
            gen_load_int_reg(context, &offset.integer, &value);
        }

        reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);

        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_INPUT1], &value);

        reil_integer immediate;
        if ( get_reil_int_from_x86_op(context, &context->x86instruction->op2, &immediate))
        {
            assign_operand_integer(&arithmetic_instr->operands[REIL_OPERAND_INPUT2], &immediate);

            unsigned int reg_scale;
            if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
                reg_scale = 2;
            else
                reg_scale = 1;
            reil_register output;
            alloc_temp_reg(context, reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg.size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].integer.size), &output);

            assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_OUTPUT], &output);

            reil_integer size = {.value = get_x86operand_size(context->x86instruction, &context->x86instruction->op1), .size = 1};
            reil_register reduced_output = {0};
            gen_reduce_reg_int_reg(context, &output, &size, &reduced_output);

            /* Update eflags here, so we have all the results intact without copying stuff. */
            reil_operand *op1, *op2, op3;
            op1 = &arithmetic_instr->operands[0];
            op2 = &arithmetic_instr->operands[1];
            assign_operand_register(&op3, &reduced_output);

            gen_eflags_update(context, op1, op2, &op3);

            if (offset.type == REGISTER_OFFSET)
                gen_store_reg_reg(context, &reduced_output, &offset.reg);
            else
                gen_store_reg_int(context, &reduced_output, &offset.integer);

        }
        else
        {
            gen_unknown(context);
        }
    }
    else if (context->x86instruction->op1.type == OPERAND_TYPE_MEMORY && context->x86instruction->op2.type == OPERAND_TYPE_REGISTER)
    {
        memory_offset offset;

        calculate_memory_offset(context, &context->x86instruction->op1, &offset);

        reil_register value = {0};
        if (offset.type == REGISTER_OFFSET )
        {
            if ( context->x86instruction->mode == MODE_32 && offset.reg.size > 4 )
            {
                reil_integer size = {.value = 4, .size = 1};
                reil_register reduced_offset;
                gen_reduce_reg_int_reg(context, &offset.reg, &size, &reduced_offset);
                assign_reg_reg(&reduced_offset, &offset.reg);

            }

            if ( context->x86instruction->mode == MODE_16 && offset.reg.size > 2 )
            {
                reil_integer size = {.value = 2, .size = 1};
                reil_register reduced_offset;
                gen_reduce_reg_int_reg(context, &offset.reg, &size, &reduced_offset);
                assign_reg_reg(&reduced_offset, &offset.reg);
            }

            gen_load_reg_reg(context, &offset.reg, &value);
        }
        else /* INTEGER_OFFSET */
        {
            gen_load_int_reg(context, &offset.integer, &value);
        }

        reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);

        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_INPUT1], &value);

        reil_register input2 = {0};
        get_reil_reg_from_x86_op(context, &context->x86instruction->op2, &input2);
        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_INPUT2], &input2);

        unsigned int reg_scale;
        if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
            reg_scale = 2;
        else
            reg_scale = 1;
        reil_register output;
        alloc_temp_reg(context, reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg.size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].reg.size), &output);
        assign_operand_register(&arithmetic_instr->operands[REIL_OPERAND_OUTPUT], &output);

        reil_integer size = {.value = get_x86operand_size(context->x86instruction, &context->x86instruction->op1), .size = 1};
        reil_register reduced_output = {0};
        gen_reduce_reg_int_reg(context, &output, &size, &reduced_output);

        /* Update eflags here, so we have all the results intact without copying stuff. */
        reil_operand *op1, *op2, op3;
        op1 = &arithmetic_instr->operands[0];
        op2 = &arithmetic_instr->operands[1];
        assign_operand_register(&op3, &reduced_output);

        gen_eflags_update(context, op1, op2, &op3);

        if (offset.type == REGISTER_OFFSET)
            gen_store_reg_reg(context, &reduced_output, &offset.reg);
        else
            gen_store_reg_int(context, &reduced_output, &offset.integer);
    }
    /* The (I)MUL and (I)DIV instructions take one operand. */
    else if ((context->x86instruction->op1.type == OPERAND_TYPE_REGISTER || 
               context->x86instruction->op1.type == OPERAND_TYPE_MEMORY) && context->x86instruction->op2.type == OPERAND_TYPE_NONE)
    {
        if (context->x86instruction->type == INSTRUCTION_TYPE_DIV)
        {
            /* The registers used to store the quotient and the remainder depend on the mode and operand size. */
            size_t operand_size = get_x86operand_size(context->x86instruction, &context->x86instruction->op1);
            reil_register dividend = {0}, divider = {0}, quotient = {0}, remainder = {0};
            unsigned char divider_is_reg = context->x86instruction->op1.type == OPERAND_TYPE_REGISTER;

            if (!divider_is_reg)
            {
                memory_offset offset;
                calculate_memory_offset(context, &context->x86instruction->op1, &offset);

                if ( offset.type == REGISTER_OFFSET )
                {
                    if ( context->x86instruction->mode == MODE_32 && offset.reg.size > 4 )
                    {
                        reil_integer size = {.value = 4, .size = 1};
                        reil_register reduced_offset;
                        gen_reduce_reg_int_reg(context, &offset.reg, &size, &reduced_offset);
                        assign_reg_reg(&reduced_offset, &offset.reg);
                    }

                    if ( context->x86instruction->mode == MODE_16 && offset.reg.size > 2 )
                    {
                        reil_integer size = {.value = 2, .size = 1};
                        reil_register reduced_offset;
                        gen_reduce_reg_int_reg(context, &offset.reg, &size, &reduced_offset);
                        assign_reg_reg(&reduced_offset, &offset.reg);
                    }
                    gen_load_reg_reg(context, &offset.reg, &divider);
                }
                else /* INTEGER_OFFSET */
                {
                    gen_load_int_reg(context, &offset.integer, &divider);
                }
            }

            switch(operand_size)
            {
                case 1:
                    {
                        dividend.index = X86_REG_AX;
                        dividend.size = 2;
                        if (divider_is_reg)
                        {
                            get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &divider);
                            /* Correct to our used register table */
                            // divider.index += 16;
                        }

                        quotient.index = X86_REG_AL;
                        quotient.size = 1;
                        remainder.index = X86_REG_AH;
                        remainder.size = 1;
                    }
                    break;
                case 2:
                    {
                        if (divider_is_reg)
                        {
                            get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &divider);
                            /* Correct to our used register table */
                            /* divider.index += 8; */
                        }

                        reil_register highpart_dividend; 
                        alloc_temp_reg(context, 4, &highpart_dividend);
                        reil_register src = {.index = X86_REG_DX, .size = 2};
                        gen_mov_reg_reg(context, &src, &highpart_dividend);

                        reil_integer shifts = {.value = 16, .size = 1};
                        reil_register shifted_highpart_dividend = {.index = 0, .size = 0};
                        gen_shl_reg_int_reg(context, &highpart_dividend, &shifts, &shifted_highpart_dividend);

                        reil_register or_with_reg = {.index = X86_REG_AX, .size = 2};
                        gen_or_reg_reg_reg(context, &shifted_highpart_dividend, &or_with_reg, &dividend);

                        quotient.index = X86_REG_AX;
                        quotient.size = 2;
                        remainder.index = X86_REG_DX;
                        remainder.size = 2;
                    }
                    break;
                case 4:
                    {
                        if (divider_is_reg)
                        {
                            get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &divider);
                        }

                        reil_register highpart_dividend; 
                        alloc_temp_reg(context, 8, &highpart_dividend);
                        reil_register src = {.index = X86_REG_EDX, .size = 4};
                        gen_mov_reg_reg(context, &src, &highpart_dividend);
                        reil_integer shifts = {.value = 32, .size = 1};
                        reil_register shifted_highpart_dividend = {.index = 0, .size = 0};
                        gen_shr_reg_int_reg(context, &highpart_dividend, &shifts, &shifted_highpart_dividend);
                        
                        reil_register or_with_reg = {.index = X86_REG_EAX, .size = 4};
                        gen_or_reg_reg_reg(context, &shifted_highpart_dividend, &or_with_reg, &dividend);

                        quotient.index = X86_REG_EAX;
                        quotient.size = 4;
                        remainder.index = X86_REG_EDX;
                        remainder.size = 4;
                    }
                    break;
                default:
                    break;
            }

            reil_instruction * div = alloc_reil_instruction(context, REIL_DIV);
            assign_operand_register(&div->operands[REIL_OPERAND_INPUT1], &dividend);
            assign_operand_register(&div->operands[REIL_OPERAND_INPUT2], &divider);
            
            reil_register temp;
            alloc_temp_reg(context, operand_size, &temp);

            assign_operand_register(&div->operands[REIL_OPERAND_OUTPUT], &temp);
            
            reil_instruction * mod = alloc_reil_instruction(context, REIL_MOD);
            assign_operand_register(&mod->operands[REIL_OPERAND_INPUT1], &dividend);
            assign_operand_register(&mod->operands[REIL_OPERAND_INPUT2], &divider);
            assign_operand_register(&mod->operands[REIL_OPERAND_OUTPUT], &remainder);

            gen_mov_reg_reg(context, &temp, &quotient);

            /* The DIV instruction leaves status registers in an undefined state, so we do not
             * need to access the operands */
            gen_eflags_update(context, NULL, NULL, NULL);
        }
        else if (context->x86instruction->type == INSTRUCTION_TYPE_MUL)
        {
            /* The registers used to store the quotient and the remainder depend on the mode and operand size. */
            size_t operand_size = get_x86operand_size(context->x86instruction, &context->x86instruction->op1);
            reil_register multiplicand = {0} , multiplier = {0};
            unsigned char multiplier_is_reg = context->x86instruction->op1.type == OPERAND_TYPE_REGISTER;

            if (!multiplier_is_reg)
            {
                memory_offset offset;
                calculate_memory_offset(context, &context->x86instruction->op1, &offset);

                if ( offset.type == REGISTER_OFFSET )
                {
                    if ( context->x86instruction->mode == MODE_32 && offset.reg.size > 4 )
                    {
                        reil_integer size = {.value = 4, .size = 1};
                        reil_register reduced_offset;
                        gen_reduce_reg_int_reg(context, &offset.reg, &size, &reduced_offset);
                        assign_reg_reg(&reduced_offset, &offset.reg);
                    }

                    if ( context->x86instruction->mode == MODE_16 && offset.reg.size > 2 )
                    {
                        reil_integer size = {.value = 2, .size = 1};
                        reil_register reduced_offset;
                        gen_reduce_reg_int_reg(context, &offset.reg, &size, &reduced_offset);
                        assign_reg_reg(&reduced_offset, &offset.reg);
                    }
                    gen_load_reg_reg(context, &offset.reg, &multiplier);
                }
                else /* INTEGER_OFFSET */
                {
                    gen_load_int_reg(context, &offset.integer, &multiplier);
                }
            }

            reil_instruction * mul = alloc_reil_instruction(context, REIL_MUL);
            switch(operand_size)
            {
                case 1:
                    {
                        multiplicand.index = X86_REG_AL;
                        multiplicand.size = 1;
                        if (multiplier_is_reg)
                        {
                            get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &multiplier);
                        }

                        assign_operand_register(&mul->operands[REIL_OPERAND_INPUT1], &multiplicand);
                        assign_operand_register(&mul->operands[REIL_OPERAND_INPUT2], &multiplier);
                        
                        reil_register output = {.index = X86_REG_AX, .size = 2};
                        assign_operand_register(&mul->operands[REIL_OPERAND_OUTPUT], &output);

                        reil_register high_byte= {.index = X86_REG_AH, .size = 1};
                        gen_is_not_zero_reg_reg(context, &high_byte, &REG_CF);
                        gen_is_not_zero_reg_reg(context, &high_byte, &REG_OF);
                    }
                    break;
                case 2:
                    {
                        multiplicand.index = X86_REG_AX;
                        multiplicand.size = 2;
                        if (multiplier_is_reg)
                        {
                            get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &multiplier);
                        }

                        assign_operand_register(&mul->operands[REIL_OPERAND_INPUT1], &multiplicand);
                        assign_operand_register(&mul->operands[REIL_OPERAND_INPUT2], &multiplier);
                        
                        reil_register product;
                        alloc_temp_reg(context, 4, &product);

                        assign_operand_register(&mul->operands[2], &product);

                        reil_integer shifts = {.value = 16, .size = 1};
                        reil_register high_word = {.index = 0, .size = 0};
                        gen_shr_reg_int_reg(context, &product, &shifts, &high_word);
                        reil_integer word_size = {.value = 2, .size = 1};
                        reil_register reduced_high_word;
                        gen_reduce_reg_int_reg(context, &high_word, &word_size, &reduced_high_word);
                        reil_register dest_high_word = {.index = X86_REG_DX, .size = 2};
                        gen_mov_reg_reg(context, &reduced_high_word, &dest_high_word);

                        reil_register reduced_low_word;
                        gen_reduce_reg_int_reg(context, &product, &word_size, &reduced_low_word);
                        reil_register dest_low_word = {.index = X86_REG_AX, .size = 2};
                        gen_mov_reg_reg(context, &reduced_low_word, &dest_low_word);

                        gen_is_not_zero_reg_reg(context, &dest_high_word, &REG_CF);
                        gen_is_not_zero_reg_reg(context, &dest_high_word, &REG_OF);
                    }
                    break;
                case 4:
                    {
                        multiplicand.index = X86_REG_EAX;
                        multiplicand.size = 4;
                        if (multiplier_is_reg)
                        {
                            get_reil_reg_from_x86_op(context, &context->x86instruction->op1, &multiplier);
                        }

                        assign_operand_register(&mul->operands[REIL_OPERAND_INPUT1], &multiplicand);
                        assign_operand_register(&mul->operands[REIL_OPERAND_INPUT2], &multiplier);
                        
                        reil_register product;
                        alloc_temp_reg(context, 8, &product);

                        assign_operand_register(&mul->operands[2], &product);

                        reil_integer shifts = {.value = 32, .size = 1};
                        reil_register high_dword = {.index = 0, .size = 0};
                        gen_shr_reg_int_reg(context, &product, &shifts, &high_dword);
                        reil_integer dword_size = {.value = 4, .size = 1};
                        reil_register reduced_high_dword;
                        gen_reduce_reg_int_reg(context, &high_dword, &dword_size, &reduced_high_dword);
                        
                        reil_register dest_high_dword = {.index = X86_REG_EDX, .size = 4};
                        gen_mov_reg_reg(context, &reduced_high_dword, &dest_high_dword);
                        
                        reil_register reduced_low_dword;
                        gen_reduce_reg_int_reg(context, &product, &dword_size, &reduced_low_dword);
                        reil_register dest_low_dword = {.index = X86_REG_EAX, .size = 4};
                        gen_mov_reg_reg(context, &reduced_low_dword, &dest_low_dword);

                        gen_is_not_zero_reg_reg(context, &dest_high_dword, &REG_CF);
                        gen_is_not_zero_reg_reg(context, &dest_high_dword, &REG_OF);
                    }
                    break;
                default:
                    gen_unknown(context);
                    break;
            }
        }
        else
        {
            gen_unknown(context);
        }
    }
    else
    {
        gen_unknown(context);
    }
}

static void gen_push_reg(translation_context *ctx, reil_register *r)
{
		reil_instruction *insn_sub, *insn_stm, *insn_str;
		reil_register nesp, esp = {
			.index = X86_REG_ESP,
			.size = 4,
		};
		reil_integer sz = {
			.value = r->size,
			.size = 1,
		};
		alloc_temp_reg(ctx, 4, &nesp);
		/* sub esp, sizeof(r), nesp */
		insn_sub = alloc_reil_instruction(ctx, REIL_SUB);
		assign_operand_register(&insn_sub->operands[REIL_OPERAND_INPUT1], &esp);
		assign_operand_integer(&insn_sub->operands[REIL_OPERAND_INPUT2], &sz);
		assign_operand_register(&insn_sub->operands[REIL_OPERAND_OUTPUT], &nesp);

		/* str nesp, , esp */
		insn_str = alloc_reil_instruction(ctx, REIL_STR);
		assign_operand_register(&insn_str->operands[REIL_OPERAND_INPUT1], &nesp);
		assign_operand_register(&insn_str->operands[REIL_OPERAND_OUTPUT], &esp);

		/* stm r, , nesp */
		insn_stm = alloc_reil_instruction(ctx, REIL_STM);
		assign_operand_register(&insn_stm->operands[REIL_OPERAND_INPUT1], r);
		assign_operand_register(&insn_stm->operands[REIL_OPERAND_OUTPUT], &esp);
}

static void gen_push_instr(translation_context *ctx)
{
	if (ctx->x86instruction->op1.type == OPERAND_TYPE_REGISTER) {
		reil_register opnd, size, nesp;

		alloc_temp_reg(ctx, 4, &size);
		alloc_temp_reg(ctx, 4, &nesp);
		get_reil_reg_from_x86_op(ctx, &ctx->x86instruction->op1, &opnd);

		gen_push_reg(ctx, &opnd);
	} else {	/* XXX: TBD */
		gen_unknown(ctx);
	}
}

static void gen_call_instr(translation_context *ctx)
{
	reil_integer insn_len = {
		.value = ctx->x86instruction->length,
		.size = 8,
	};
	reil_register ret_addr, jmp_addr, eip = {
		.index = X86_REG_EIP,
		.size = 4,
	};

	/* add esp, $insn_len, ret_addr */
	alloc_temp_reg(ctx, 4, &ret_addr);
	gen_add_reg_int_reg(ctx, &eip, &insn_len, &ret_addr);

	gen_push_reg(ctx, &ret_addr);

	if (ctx->x86instruction->op1.type == OPERAND_TYPE_IMMEDIATE) {	/* PC-relative */
		reil_integer offset;

		alloc_temp_reg(ctx, 4, &jmp_addr);
		get_reil_int_from_x86_op(ctx, &ctx->x86instruction->op1, &offset);
		gen_add_reg_int_reg(ctx, &eip, &offset, &jmp_addr);
		gen_mov_reg_reg(ctx, &jmp_addr, &eip);
	} else if (ctx->x86instruction->op1.type == OPERAND_TYPE_REGISTER) {
		/* absolute address */
		alloc_temp_reg(ctx, 4, &jmp_addr);
		get_reil_reg_from_x86_op(ctx, &ctx->x86instruction->op1, &jmp_addr);
	} else if (ctx->x86instruction->op1.type == OPERAND_TYPE_MEMORY) {
		reil_register ptr;
		get_reil_reg_for_op(ctx, &ctx->x86instruction->op1, &ptr);
		gen_load_reg_reg(ctx, &ptr, &eip);
	}
}

static void gen_pop_instr(translation_context *ctx)
{
	reil_register esp = {
		.index = X86_REG_ESP,
		.size = 4,
	}, ebp = {
		.index = X86_REG_EBP,
		.size = 4,
	};

	if (ctx->x86instruction->op1.type == OPERAND_TYPE_NONE) { /* leave */
		gen_mov_reg_reg(ctx, &ebp, &esp);
		gen_load_reg_reg(ctx, &esp, &ebp);
	} else
		gen_unknown(ctx);
}

static void gen_ret_instr(translation_context *ctx)
{
	reil_integer imm;
	reil_register esp = {
		.index = X86_REG_ESP,
		.size = 4,
	}, eip = {
		.index = X86_REG_EIP,
		.size = 4,
	}, tmp, nesp;

	if ((ctx->x86instruction->op1.type != OPERAND_TYPE_NONE) &&
	    (ctx->x86instruction->op1.type != OPERAND_TYPE_IMMEDIATE)) {
		    gen_unknown(ctx);
		    return;
	}

	/* ldm esp, , eip */
	gen_load_reg_reg(ctx, &esp, &eip);

	if (ctx->x86instruction->op1.type != OPERAND_TYPE_IMMEDIATE)
		return;

	/* str op1, , tmp */
	get_reil_int_from_x86_op(ctx, &ctx->x86instruction->op1, &imm);
	alloc_temp_reg(ctx, 4, &tmp);
	gen_mov_int_reg(ctx, &imm, &tmp);

	/* add tmp, esp, nesp */
	alloc_temp_reg(ctx, 4, &nesp);
	gen_add_reg_reg_reg(ctx, &tmp, &esp, &nesp);

	/* str nesp, , esp */
	gen_mov_reg_reg(ctx, &nesp, &esp);
}

static void get_reil_reg_from_x86_op(translation_context * context, POPERAND op, reil_register * reg)
{
	int regtype = 0;
    size_t regsize = 0;
    // Determine register type
    switch (MASK_AM(op->flags)) {
        case AM_REG:
            if (MASK_FLAGS(op->flags) == F_r)
            {
                regtype = REG_SEGMENT;
                regsize = 2;
            }
            else if (MASK_FLAGS(op->flags) == F_f)
                regtype = REG_FPU;
            else
                regtype = REG_GEN_DWORD;
            break;
        case AM_E:
        case AM_G:
        case AM_R:
            regtype = REG_GEN_DWORD;
            break;
            // control register encoded in MODRM
        case AM_C:
            regtype = REG_CONTROL;
            break;
            // debug register encoded in MODRM
        case AM_D:
            regtype = REG_DEBUG;
            break;
            // Segment register encoded in MODRM
        case AM_S:
            regtype = REG_SEGMENT;
            break;
            // TEST register encoded in MODRM
        case AM_T:
            regtype = REG_TEST;
            break;
            // MMX register encoded in MODRM
        case AM_P:
        case AM_Q:
            regtype = REG_MMX;
            break;
            // XMM register encoded in MODRM
        case AM_V:
        case AM_W:
            regtype = REG_XMM;
            break;
    }

    if (regtype == REG_GEN_DWORD) 
    {
        enum Mode operand_mode = MODE_CHECK_OPERAND(context->x86instruction->mode, context->x86instruction->flags);
        switch (MASK_OT(op->flags)) 
        {
            case OT_b:
                reg->index = (REG_GEN_BYTE << 3) + op->reg;
                reg->size = 1;
                break;
            case OT_v:
                reg->index = (operand_mode == MODE_32)?(REG_GEN_DWORD << 3) + op->reg:(REG_GEN_WORD << 3) + op->reg;
                reg->size = (operand_mode == MODE_32)?4:2;
                break;
            case OT_w:
                reg->index = (REG_GEN_WORD << 3) + op->reg;
                reg->size = 2;
                break;
            case OT_d:
                reg->index = (REG_GEN_DWORD << 3) + op->reg;
                reg->size = 4;
                break;
        }
    } 
    else
    {
        reg->size = 0;
    }
}

const char *reil_register_x86_formatter(reil_operand * register_operand)
{
    /* strlen("xword Txxx") + 1 == 11*/
    static char format_buffer[11];
    if ( register_operand->reg.index >= SCRATCH_REGISTER_BASE )
    {
        const char * size_prefix;
        switch (register_operand->reg.size)
        {
            case 1:
                size_prefix = "byte";
                break;
            case 2:
                size_prefix = "word";
                break;
            case 4:
                size_prefix = "dword";
                break;
            case 8:
                size_prefix = "qword";
                break;
            case 16:
                size_prefix = "oword";
                break;
            case 32:
                size_prefix = "hword";
                break;
            default:
                size_prefix = "???";
                break;

        }
        snprintf(format_buffer, sizeof(format_buffer), "%s T%i", size_prefix, register_operand->reg.index);
    }
    else
    {
        snprintf(format_buffer, sizeof(format_buffer), "%s", ((const char**)x86reg_table)[register_operand->reg.index]);
    }
    return format_buffer;
}

static unsigned char get_reil_int_from_x86_op(translation_context * context, POPERAND op, reil_integer * integer)
{
    unsigned int imm;
    if ( get_operand_immediate(op, &imm) )
    {
        integer->value = imm;
        integer->size = get_x86operand_size(context->x86instruction, op);
        return 1;
    }
    /* XXX: return void */
    errx(3, "tried to get immediate from operand of type %d", op->type);
}

static void assign_operand_register(reil_operand * operand, reil_register * reg)
{
    operand->type = REIL_OPERAND_TYPE_REGISTER;
    operand->reg.index = reg->index;
    operand->reg.size = reg->size;
}

static void assign_operand_integer(reil_operand * operand, reil_integer * integer)
{
    operand->type = REIL_OPERAND_TYPE_INTEGER;
    operand->integer.value = integer->value;
    operand->integer.size = integer->size;
}

static void assign_reg_reg(reil_register * src, reil_register * dest)
{
    dest->index = src->index;
    dest->size = src->size;
}
