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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libdasm.h"
#include "opcode_tables.h"
#include "reil.h"
#include "reil_instruction_table.h"
#include "reil_x86_translator.h"

/* Check for address/operand size override, copied from libdasm.c */

static __inline__ enum Mode MODE_CHECK_ADDR(enum Mode mode, int flags) {
	if (((mode == MODE_32) && (MASK_PREFIX_ADDR(flags) == 0)) ||
    	    ((mode == MODE_16) && (MASK_PREFIX_ADDR(flags) == 1)))
		return MODE_32;
	else 
		return MODE_16;
}

static __inline__ enum Mode MODE_CHECK_OPERAND(enum Mode mode, int flags) {
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
static const char * x86reg_table[13][8] = 
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
};

#define MAX(X, Y) (((X) > (Y))?(X):(Y))
/* Index + 1 of the last element in the x86reg_table */
#define SCRATCH_REGISTER_BASE (sizeof(x86reg_table)/sizeof(x86reg_table[0][0]))
/* First element of the 9th row in x86reg_table */
#define EFLAGS_REGISTER_BASE 9*8 
/* The explicit eflags registers have a size of one byte */
#define EFLAGS_REGISTER_SIZE 1
#define MAX_SCRATCH_REGISTERS 256

#define REG_CF (EFLAGS_REGISTER_BASE)
#define REG_PF (EFLAGS_REGISTER_BASE + 2)
#define REG_AF (EFLAGS_REGISTER_BASE + 4)
#define REG_ZF (EFLAGS_REGISTER_BASE + 6)
#define REG_SF (EFLAGS_REGISTER_BASE + 7)
#define REG_OF (EFLAGS_REGISTER_BASE + 11)

typedef struct _scratch_register
{
    size_t size;
} scratch_register;

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
    reil_register next_free_register;
    scratch_register scratch_registers[MAX_SCRATCH_REGISTERS];
} translation_context;

static size_t get_operand_size(INSTRUCTION * x86instruction, OPERAND * x86operand);
static void init_translation_context(translation_context * context, INSTRUCTION * x86instruction, unsigned long base, unsigned long offset);
static scratch_register * alloc_scratch_reg(translation_context * context);
static void calculate_memory_offset(translation_context * context, POPERAND x86operand, int * offset, size_t * offset_size, reil_operand_type * offset_type);
static reil_instruction * alloc_reil_instruction(translation_context * context, reil_instruction_index index);
static reil_register get_reil_reg_from_scratch_reg(translation_context * context, scratch_register * reg);
static scratch_register * get_scratch_reg_from_reil_reg(translation_context * context, reil_register reg);
static reil_register x86regop_to_reilreg(translation_context * context, POPERAND op);

/* Basic REIL instruction generation functions */
static void gen_unknown(translation_context * context);
static void gen_storereg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size);
static void gen_storereg_int(translation_context * context, reil_integer integer, size_t integer_size, reil_register reg, size_t reg_size);
static void gen_store_reg_reg(translation_context * context, reil_register address, size_t address_size, reil_register value, size_t value_size);
static void gen_store_int_reg(translation_context * context, reil_integer address, size_t address_size, reil_register value, size_t value_size);
static scratch_register * gen_load_reg(translation_context * context, reil_register reg, size_t reg_size);
static scratch_register * gen_load_int(translation_context * context, reil_integer integer, size_t integer_size);
static scratch_register * gen_add_reg_int(translation_context * context, reil_register reg, size_t reg_size, int integer, size_t integer_size);
static scratch_register * gen_multiply_reg_int(translation_context * context, reil_register multiplicand, size_t multiplicand_size, int multiplier, size_t multiplier_size);
static scratch_register * gen_add_reg_reg(translation_context * context, reil_register addend1, size_t addend1_size, reil_register addend2, size_t addend2_size);
static scratch_register * gen_reduce(translation_context * context, reil_register reg, size_t reg_size, size_t reduced_size);
static scratch_register * gen_shx_int(translation_context * context, reil_register reg, size_t reg_size, reil_instruction_index shift_index, reil_integer shifts);
static scratch_register * gen_shx_reg(translation_context * context, reil_register reg, size_t reg_size, reil_instruction_index shift_index, reil_register shifts_reg, size_t shifts_reg_size);
static scratch_register * gen_shl_int(translation_context * context, reil_register reg, size_t reg_size, reil_integer shifts);
static scratch_register * gen_shr_int(translation_context * context, reil_register reg, size_t reg_size, reil_integer shifts);
static scratch_register * gen_shl_reg(translation_context * context, reil_register reg, size_t reg_size, reil_register shifts_reg, size_t shifts_reg_size);
static scratch_register * gen_shr_reg(translation_context * context, reil_register reg, size_t reg_size, reil_register shifts_reg, size_t shifts_reg_size);
static scratch_register * gen_and_reg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size);
static scratch_register * gen_and_reg_int(translation_context * context, reil_register reg, size_t reg_size, reil_integer integer);
static scratch_register * gen_xor_reg_int(translation_context * context, reil_register reg, size_t reg_size, reil_integer integer);
static scratch_register * gen_xor_reg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size);

static void gen_eflags_update(translation_context * context, reil_instruction_index index, reil_operand * op1, reil_operand * op2, reil_operand * op3);

/* static void gen_setc_cf(translation_context * context, reil_register reg, size_t reg_size); */
/* static void gen_setc_pf(translation_context * context, reil_register reg, size_t reg_size); */
/* static void gen_setc_sf(translation_context * context, reil_register reg, size_t reg_size); */
static void gen_setc_zf(translation_context * context, reil_register reg, size_t reg_size);
/* REIL instruction group generation functions */
static void gen_arithmetic_instr(translation_context * context, reil_instruction_index index);

reil_instructions * reil_translate(unsigned long base, unsigned long offset, INSTRUCTION * x86instruction)
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
            {
                if ( x86instruction->op1.type == OPERAND_TYPE_REGISTER && x86instruction->op2.type == OPERAND_TYPE_REGISTER)
                {
                    gen_storereg_reg(&context, x86regop_to_reilreg(&context, &x86instruction->op2),
                            get_operand_size(x86instruction, &x86instruction->op2),
                            x86regop_to_reilreg(&context, &x86instruction->op1),
                            get_operand_size(x86instruction, &x86instruction->op1));
                }
                else if ( x86instruction->op1.type == OPERAND_TYPE_MEMORY && x86instruction->op2.type == OPERAND_TYPE_REGISTER)
                {
                    int offset;
                    size_t offset_size;
                    reil_operand_type offset_type;

                    calculate_memory_offset(&context, &x86instruction->op1, &offset, &offset_size, &offset_type);

                    if ( offset_type == REIL_OPERAND_TYPE_REGISTER )
                    {
                        gen_store_reg_reg(&context, (reil_register)offset, offset_size,
                                x86regop_to_reilreg(&context, &x86instruction->op2),
                                get_operand_size(x86instruction, &x86instruction->op2));
                    }
                    else /* REIL_OPERAND_TYPE_INTEGER */
                    {
                        gen_store_int_reg(&context, (reil_integer)offset, offset_size,
                                x86regop_to_reilreg(&context, &x86instruction->op2),
                                get_operand_size(x86instruction, &x86instruction->op2));
                    }
                }
                else if ( x86instruction->op1.type == OPERAND_TYPE_REGISTER && x86instruction->op2.type == OPERAND_TYPE_MEMORY)
                {
                    int offset;
                    size_t offset_size;
                    reil_operand_type offset_type;

                    calculate_memory_offset(&context, &x86instruction->op2, &offset, &offset_size, &offset_type);

                    if ( offset_type == REIL_OPERAND_TYPE_REGISTER )
                    {
                        scratch_register * result_reg = gen_load_reg(&context, (reil_register)offset, offset_size);
                        gen_storereg_reg(&context, get_reil_reg_from_scratch_reg(&context, result_reg), result_reg->size, 
                                x86regop_to_reilreg(&context, &x86instruction->op1),
                                get_operand_size(x86instruction, &x86instruction->op1));
                    }
                    else /* REIL_OPERAND_TYPE_INTEGER */
                    {
                        scratch_register * result_reg = gen_load_int(&context, (reil_integer)offset, offset_size);
                        gen_storereg_reg(&context, get_reil_reg_from_scratch_reg(&context, result_reg), result_reg->size, 
                                x86regop_to_reilreg(&context, &x86instruction->op1),
                                get_operand_size(x86instruction, &x86instruction->op1));
                    }

                }
                else if ( x86instruction->op1.type == OPERAND_TYPE_REGISTER && x86instruction->op2.type == OPERAND_TYPE_IMMEDIATE)
                {
                    unsigned int imm;
                    if ( get_operand_immediate(&x86instruction->op2, &imm) )
                    {
                        gen_storereg_int(&context, (reil_integer)imm, 
                                get_operand_size(x86instruction, &x86instruction->op2),
                                x86regop_to_reilreg(&context, &x86instruction->op1),
                                get_operand_size(x86instruction, &x86instruction->op1));
                    }
                    else
                    {
                        gen_unknown(&context);
                    }
                }
                else
                {
                    gen_unknown(&context);
                }
            }
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

size_t get_operand_size(INSTRUCTION * x86instruction, OPERAND * x86operand)
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

static void init_translation_context(translation_context * context, INSTRUCTION * x86instruction, unsigned long base, unsigned long offset)
{
    memset(context, 0, sizeof(*context));
    context->x86instruction = x86instruction;
    context->next_free_register = SCRATCH_REGISTER_BASE;
    context->base= base;
    context->offset= offset;
}

/* TODO: Check bounds of scratch_registers array */
static scratch_register * alloc_scratch_reg(translation_context * context)
{
    scratch_register * reg = &context->scratch_registers[context->next_free_register - SCRATCH_REGISTER_BASE];
    context->next_free_register++;

    return reg;
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

static void gen_storereg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size)
{
    reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(store_instruction, &reil_instruction_table[REIL_STR], sizeof(reil_instruction));

    store_instruction->address = REIL_ADDRESS(context->base, context->offset);
    store_instruction->offset = context->last_offset++; 

    store_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    store_instruction->operands[0].reg = reg1;
    store_instruction->operands[0].size = reg1_size;

    store_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    store_instruction->operands[2].reg = reg2;
    store_instruction->operands[2].size = reg2_size;
}

static void gen_storereg_int(translation_context * context, reil_integer integer, size_t integer_size, reil_register reg, size_t reg_size)
{
    reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(store_instruction, &reil_instruction_table[REIL_STR], sizeof(reil_instruction));

    store_instruction->address = REIL_ADDRESS(context->base, context->offset);
    store_instruction->offset = context->last_offset++; 

    store_instruction->operands[0].type = REIL_OPERAND_TYPE_INTEGER;
    store_instruction->operands[0].integer = integer;
    store_instruction->operands[0].size = integer_size;

    store_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    store_instruction->operands[2].reg = reg;
    store_instruction->operands[2].size = reg_size;
}

static void gen_store_reg_reg(translation_context * context, reil_register address, size_t address_size, reil_register value, size_t value_size)
{
    reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(store_instruction, &reil_instruction_table[REIL_STM], sizeof(reil_instruction));

    store_instruction->address = REIL_ADDRESS(context->base, context->offset);
    store_instruction->offset = context->last_offset++; 

    store_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    store_instruction->operands[0].reg = value;
    store_instruction->operands[0].size = value_size;
    
    store_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    store_instruction->operands[2].reg = address;
    store_instruction->operands[2].size = address_size;
}

static void gen_store_int_reg(translation_context * context, reil_integer address, size_t address_size, reil_register value, size_t value_size)
{
    reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(store_instruction, &reil_instruction_table[REIL_STM], sizeof(reil_instruction));

    store_instruction->address = REIL_ADDRESS(context->base, context->offset);
    store_instruction->offset = context->last_offset++; 

    store_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    store_instruction->operands[0].reg = value;
    store_instruction->operands[0].size = value_size;
    
    store_instruction->operands[2].type = REIL_OPERAND_TYPE_INTEGER;
    store_instruction->operands[2].integer = address;
    store_instruction->operands[2].size = address_size;
}

static scratch_register * gen_load_reg(translation_context * context, reil_register reg, size_t reg_size)
{
    reil_instruction * load_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(load_instruction, &reil_instruction_table[REIL_LDM], sizeof(reil_instruction));

    load_instruction->address = REIL_ADDRESS(context->base, context->offset);
    load_instruction->offset = context->last_offset++;

    load_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    load_instruction->operands[0].reg = reg;
    load_instruction->operands[0].size = reg_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    load_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    load_instruction->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    load_instruction->operands[2].size = output->size;

    return output;
}

static scratch_register * gen_load_int(translation_context * context, reil_integer integer, size_t integer_size)
{
    reil_instruction * load_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(load_instruction, &reil_instruction_table[REIL_LDM], sizeof(reil_instruction));

    load_instruction->address = REIL_ADDRESS(context->base, context->offset);
    load_instruction->offset = context->last_offset++;

    load_instruction->operands[0].type = REIL_OPERAND_TYPE_INTEGER;
    load_instruction->operands[0].integer = integer;
    load_instruction->operands[0].size = integer_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = integer_size;

    load_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    load_instruction->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    load_instruction->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_add_reg_int(translation_context * context, reil_register reg, size_t reg_size, int integer, size_t integer_size)
{
    reil_instruction * add_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(add_instruction, &reil_instruction_table[REIL_ADD], sizeof(reil_instruction));

    add_instruction->address = REIL_ADDRESS(context->base, context->offset);
    add_instruction->offset = context->last_offset++;

    add_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    add_instruction->operands[0].reg = reg;
    add_instruction->operands[0].size = reg_size;

    add_instruction->operands[1].type = REIL_OPERAND_TYPE_INTEGER;
    add_instruction->operands[1].integer = integer;
    add_instruction->operands[1].size = integer_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = 2 * MAX(add_instruction->operands[0].size, add_instruction->operands[1].size);

    add_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    add_instruction->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    add_instruction->operands[2].size = output->size; 
    
    return output;
}

static scratch_register * gen_multiply_reg_int(translation_context * context, reil_register multiplicand, size_t multiplicand_size, int multiplier, size_t multiplier_size)
{
    reil_instruction * multiply_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(multiply_instruction, &reil_instruction_table[REIL_MUL], sizeof(reil_instruction));

    multiply_instruction->address = REIL_ADDRESS(context->base, context->offset);
    multiply_instruction->offset = context->last_offset++;

    multiply_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    multiply_instruction->operands[0].reg = multiplicand;
    multiply_instruction->operands[0].size = multiplicand_size;

    multiply_instruction->operands[1].type = REIL_OPERAND_TYPE_INTEGER;
    multiply_instruction->operands[1].integer = multiplier;
    multiply_instruction->operands[1].size = multiplier_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = 2 * MAX(multiply_instruction->operands[0].size, multiply_instruction->operands[1].size);

    multiply_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    multiply_instruction->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    multiply_instruction->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_add_reg_reg(translation_context * context, reil_register addend1, size_t addend1_size, reil_register addend2, size_t addend2_size)
{
    reil_instruction * add_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(add_instruction, &reil_instruction_table[REIL_ADD], sizeof(reil_instruction));

    add_instruction->address = REIL_ADDRESS(context->base, context->offset);
    add_instruction->offset = context->last_offset++;

    add_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    add_instruction->operands[0].reg = addend1;
    add_instruction->operands[0].size = addend1_size;

    add_instruction->operands[1].type = REIL_OPERAND_TYPE_REGISTER;
    add_instruction->operands[1].reg = addend2;
    add_instruction->operands[1].size = addend2_size;
    
    scratch_register * output = alloc_scratch_reg(context);
    output->size = 2 * MAX(add_instruction->operands[0].size, add_instruction->operands[1].size);

    add_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    add_instruction->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    add_instruction->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_reduce(translation_context * context, reil_register reg, size_t reg_size, size_t reduced_size)
{
    reil_instruction * reduce  = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(reduce, &reil_instruction_table[REIL_AND], sizeof(reil_instruction));

    reduce->address = REIL_ADDRESS(context->base, context->offset);
    reduce->offset = context->last_offset++;

    reduce->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    reduce->operands[0].reg = reg;
    reduce->operands[0].size = reg_size;
    
    reduce->operands[1].type = REIL_OPERAND_TYPE_INTEGER;
    reduce->operands[1].integer= (((1 << ((reduced_size << 3) - 1)) - 1) << 1) | 1;
    reduce->operands[1].size = reduced_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = reduced_size;

    reduce->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    reduce->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    reduce->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_shx_int(translation_context * context, reil_register reg, size_t reg_size, reil_instruction_index shift_index, reil_integer shifts)
{
    reil_instruction * shift = alloc_reil_instruction(context, shift_index);

    shift->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    shift->operands[0].reg = reg;
    shift->operands[0].size = reg_size;
    
    shift->operands[1].type = REIL_OPERAND_TYPE_INTEGER;
    shift->operands[1].integer = shifts;
    shift->operands[1].size = reg_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    shift->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    shift->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    shift->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_shx_reg(translation_context * context, reil_register reg, size_t reg_size, reil_instruction_index shift_index, reil_register shifts_reg,
        size_t shifts_reg_size)
{
    reil_instruction * shift = alloc_reil_instruction(context, shift_index);

    shift->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    shift->operands[0].reg = reg;
    shift->operands[0].size = reg_size;
    
    shift->operands[1].type = REIL_OPERAND_TYPE_REGISTER;
    shift->operands[1].reg = shifts_reg;
    shift->operands[1].size = shifts_reg_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    shift->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    shift->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    shift->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_shl_int(translation_context * context, reil_register reg, size_t reg_size, reil_integer shifts)
{
    return gen_shx_int(context, reg, reg_size, REIL_LSH, shifts);
}

static scratch_register * gen_shr_int(translation_context * context, reil_register reg, size_t reg_size, reil_integer shifts)
{
    return gen_shx_int(context, reg, reg_size, REIL_RSH, shifts);
}

static scratch_register * gen_shl_reg(translation_context * context, reil_register reg, size_t reg_size, reil_register shifts_reg, size_t shifts_reg_size)
{
    return gen_shx_reg(context, reg, reg_size, REIL_LSH, shifts_reg, shifts_reg_size);
}

static scratch_register * gen_shr_reg(translation_context * context, reil_register reg, size_t reg_size, reil_register shifts_reg, size_t shifts_reg_size)
{
    return gen_shx_reg(context, reg, reg_size, REIL_RSH, shifts_reg, shifts_reg_size);
}

static scratch_register * gen_and_reg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size)
{
    reil_instruction * and = alloc_reil_instruction(context, REIL_AND);

    and->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    and->operands[0].reg = reg1;
    and->operands[0].size = reg1_size;
    
    and->operands[1].type = REIL_OPERAND_TYPE_REGISTER;
    and->operands[1].integer = reg2;
    and->operands[1].size = reg2_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = MAX(reg1_size, reg2_size);

    and->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    and->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    and->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_and_reg_int(translation_context * context, reil_register reg, size_t reg_size, reil_integer integer)
{
    reil_instruction * and = alloc_reil_instruction(context, REIL_AND);

    and->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    and->operands[0].reg = reg;
    and->operands[0].size = reg_size;
    
    and->operands[1].type = REIL_OPERAND_TYPE_INTEGER;
    and->operands[1].integer = integer;
    and->operands[1].size = reg_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    and->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    and->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    and->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_xor_reg_int(translation_context * context, reil_register reg, size_t reg_size, reil_integer integer)
{
    reil_instruction * xor = alloc_reil_instruction(context, REIL_XOR);

    xor->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    xor->operands[0].reg = reg;
    xor->operands[0].size = reg_size;
    
    xor->operands[1].type = REIL_OPERAND_TYPE_INTEGER;
    xor->operands[1].integer = integer;
    xor->operands[1].size = reg_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    xor->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    xor->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    xor->operands[2].size = output->size;
    
    return output;
}

static scratch_register * gen_xor_reg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size)
{
    reil_instruction * xor = alloc_reil_instruction(context, REIL_XOR);

    xor->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    xor->operands[0].reg = reg1;
    xor->operands[0].size = reg1_size;

    xor->operands[1].type = REIL_OPERAND_TYPE_REGISTER;
    xor->operands[1].reg = reg2;
    xor->operands[1].size = reg2_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = MAX(reg1_size, reg2_size);

    xor->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    xor->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    xor->operands[2].size = output->size;

    return output;
}

static void gen_eflags_update(translation_context * context, reil_instruction_index index, reil_operand * op1, reil_operand * op2, reil_operand * op3)
{
    if (context->x86instruction->eflags_affected & EFL_CF)
    {
        scratch_register * shifted_output = gen_shr_int(context, op3->reg, op3->size, (op3->size << 2) - 1);
        scratch_register * carry = gen_reduce(context, get_reil_reg_from_scratch_reg(context, shifted_output), shifted_output->size, EFLAGS_REGISTER_SIZE);
        gen_storereg_reg(context, get_reil_reg_from_scratch_reg(context, carry), carry->size, REG_CF, EFLAGS_REGISTER_SIZE);
    }

    /* Source: http://graphics.stanford.edu/~seander/bithacks.html#ParityParallel 
     * unsigned char byte;
     * byte ^= byte >> 4;
     * byte &= 0xf;
     * unsigned char parity = (0x6996 >> byte) & 1;
     * */
    if (context->x86instruction->eflags_affected & EFL_PF)
    {
        /* Get the least-significant byte of the result */
        scratch_register * lsb = gen_reduce(context, op3->reg, op3->size, 1);
        /* Shift the lsb by four bytes */
        scratch_register * shifted_lsb = gen_shr_int(context, get_reil_reg_from_scratch_reg(context, lsb), lsb->size, 4);
        /* XOR the lower and higher nibles to compress the output in the lower nibble */
        scratch_register * compressed_lsb = gen_xor_reg_reg(context, get_reil_reg_from_scratch_reg(context, lsb), lsb->size, get_reil_reg_from_scratch_reg(context, shifted_lsb), shifted_lsb->size);
        /* Obtain an index into the parity lookup table by removing the higher nibble */
        scratch_register * parity_index = gen_and_reg_int(context, get_reil_reg_from_scratch_reg(context, compressed_lsb), compressed_lsb->size, 0xf);
        /* Store the parity lookup table into a temporary register */
        scratch_register * parity_lookup_table = alloc_scratch_reg(context);
        parity_lookup_table->size = 2;
        gen_storereg_int(context, 0x6996, 2, get_reil_reg_from_scratch_reg(context, parity_lookup_table), parity_lookup_table->size);
        /* Lookup the parity value in the lookup table */
        scratch_register * parity_lookup_table_entry = gen_shr_reg(context, get_reil_reg_from_scratch_reg(context, parity_lookup_table), parity_lookup_table->size, 
                get_reil_reg_from_scratch_reg(context, parity_index), parity_index->size);
        scratch_register * parity = gen_and_reg_int(context, get_reil_reg_from_scratch_reg(context, parity_lookup_table_entry), parity_lookup_table_entry->size, 1);
        scratch_register * reduced_parity = gen_reduce(context, get_reil_reg_from_scratch_reg(context, parity), parity->size, EFLAGS_REGISTER_SIZE);

        gen_storereg_reg(context, get_reil_reg_from_scratch_reg(context, reduced_parity), reduced_parity->size, REG_PF, EFLAGS_REGISTER_SIZE);
    }

    if (context->x86instruction->eflags_affected & EFL_AF)
    {
    }

    if (context->x86instruction->eflags_affected & EFL_ZF)
    {
        gen_setc_zf(context, op3->reg, op3->size);
    }

    if (context->x86instruction->eflags_affected & EFL_SF)
    {
        /* Shift the MSB to the LSB */
        scratch_register * sign = gen_shr_int(context, op3->reg, op3->size, (op3->size << 3) - 1);
        scratch_register * sign_flag = gen_reduce(context, get_reil_reg_from_scratch_reg(context, sign), sign->size, EFLAGS_REGISTER_SIZE);

        gen_storereg_reg(context, get_reil_reg_from_scratch_reg(context, sign_flag), sign_flag->size, REG_SF, EFLAGS_REGISTER_SIZE);
    }

    if (context->x86instruction->eflags_affected & EFL_OF)
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
        if (index == REIL_ADD)
        {
            scratch_register * xored_inputs;
            if ( op2->type == REIL_OPERAND_TYPE_REGISTER )
                xored_inputs = gen_xor_reg_reg(context, op1->reg, op1->size, op2->reg, op2->size);
            else /* REIL_OPERAND_TYPE_INTEGER */
                xored_inputs = gen_xor_reg_int(context, op1->reg, op1->size, op2->integer);

            scratch_register * neg_xored_inputs = gen_xor_reg_int(context, get_reil_reg_from_scratch_reg(context, xored_inputs), xored_inputs->size, -1);

            scratch_register * xored_input1_output =  gen_xor_reg_reg(context, op1->reg, op1->size, op3->reg, op3->size);

            scratch_register * anded_result = gen_and_reg_reg(context, get_reil_reg_from_scratch_reg(context, neg_xored_inputs), 
                    neg_xored_inputs->size, get_reil_reg_from_scratch_reg(context, xored_input1_output), xored_input1_output->size);

            /* The value of the OF flag is now in the sign bit of the anded result */
            scratch_register * overflow_status = gen_shr_int(context, get_reil_reg_from_scratch_reg(context, anded_result), 
                    anded_result->size, (anded_result->size << 3) - 1);

            /* Reduce the size */
            scratch_register * reduced_overflow_status = gen_reduce(context, get_reil_reg_from_scratch_reg(context, overflow_status),
                    overflow_status->size, 1);

            gen_storereg_reg(context, get_reil_reg_from_scratch_reg(context, reduced_overflow_status), reduced_overflow_status->size,
                    REG_OF, EFLAGS_REGISTER_SIZE);

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
        if (index == REIL_ADD)
        {
            scratch_register * xored_inputs;
            if ( op2->type == REIL_OPERAND_TYPE_REGISTER )
                xored_inputs = gen_xor_reg_reg(context, op1->reg, op1->size, op2->reg, op2->size);
            else /* REIL_OPERAND_TYPE_INTEGER */
                xored_inputs = gen_xor_reg_int(context, op1->reg, op1->size, op2->integer);

            scratch_register * xored_input1_output =  gen_xor_reg_reg(context, op1->reg, op1->size, op3->reg, op3->size);

            scratch_register * anded_result = gen_and_reg_reg(context, get_reil_reg_from_scratch_reg(context, xored_inputs), 
                    xored_inputs->size, get_reil_reg_from_scratch_reg(context, xored_input1_output), xored_input1_output->size);

            /* The value of the OF flag is now in the sign bit of the anded result */
            scratch_register * overflow_status = gen_shr_int(context, get_reil_reg_from_scratch_reg(context, anded_result), 
                    anded_result->size, (anded_result->size << 3) - 1);

            /* Reduce the size */
            scratch_register * reduced_overflow_status = gen_reduce(context, get_reil_reg_from_scratch_reg(context, overflow_status),
                    overflow_status->size, 1);

            gen_storereg_reg(context, get_reil_reg_from_scratch_reg(context, reduced_overflow_status), reduced_overflow_status->size,
                    REG_OF, EFLAGS_REGISTER_SIZE);

        }
    }
}

#if 0
static void gen_setc_cf(translation_context * context, reil_register reg, size_t reg_size)
{
    reil_instruction * bool_is_zero = alloc_reil_instruction(context, REIL_BISZ);

    bool_is_zero->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    bool_is_zero->operands[0].reg = reg;
    bool_is_zero->operands[0].size = reg_size;
    
    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    bool_is_zero->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    bool_is_zero->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    bool_is_zero->operands[2].size = output->size;

    scratch_register * xored_output = gen_xor_reg_int(context, get_reil_reg_from_scratch_reg(context, output), output->size, -1);
    scratch_register * anded_output = gen_and_reg_int(context, get_reil_reg_from_scratch_reg(context, xored_output), xored_output->size, 1);

    scratch_register * reduced_output = gen_reduce(context, get_reil_reg_from_scratch_reg(context, anded_output), anded_output->size, EFLAGS_REGISTER_SIZE);
    gen_storereg_reg(context, get_reil_reg_from_scratch_reg(context, reduced_output), reduced_output->size, REG_CF, EFLAGS_REGISTER_SIZE);
}

static void gen_setc_pf(translation_context * context, reil_register reg, size_t reg_size)
{
    reil_instruction * bool_is_zero = alloc_reil_instruction(context, REIL_BISZ);

    bool_is_zero->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    bool_is_zero->operands[0].reg = reg;
    bool_is_zero->operands[0].size = reg_size;
    
    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    bool_is_zero->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    bool_is_zero->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    bool_is_zero->operands[2].size = output->size;

    scratch_register * xored_output = gen_xor_reg_int(context, get_reil_reg_from_scratch_reg(context, output), output->size, -1);
    scratch_register * anded_output = gen_and_reg_int(context, get_reil_reg_from_scratch_reg(context, xored_output), xored_output->size, 1);

    scratch_register * reduced_output = gen_reduce(context, get_reil_reg_from_scratch_reg(context, anded_output), anded_output->size, EFLAGS_REGISTER_SIZE);
    gen_storereg_reg(context, get_reil_reg_from_scratch_reg(context, reduced_output), reduced_output->size, REG_PF, EFLAGS_REGISTER_SIZE);
}

static void gen_setc_sf(translation_context * context, reil_register reg, size_t reg_size)
{
    reil_instruction * bool_is_zero = alloc_reil_instruction(context, REIL_BISZ);

    bool_is_zero->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    bool_is_zero->operands[0].reg = reg;
    bool_is_zero->operands[0].size = reg_size;
    
    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    bool_is_zero->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    bool_is_zero->operands[2].reg = get_reil_reg_from_scratch_reg(context, output);
    bool_is_zero->operands[2].size = output->size;

    scratch_register * xored_output = gen_xor_reg_int(context, get_reil_reg_from_scratch_reg(context, output), output->size, -1);
    scratch_register * anded_output = gen_and_reg_int(context, get_reil_reg_from_scratch_reg(context, xored_output), xored_output->size, 1);

    scratch_register * reduced_output = gen_reduce(context, get_reil_reg_from_scratch_reg(context, anded_output), anded_output->size, EFLAGS_REGISTER_SIZE);
    gen_storereg_reg(context, get_reil_reg_from_scratch_reg(context, reduced_output), reduced_output->size, REG_SF, EFLAGS_REGISTER_SIZE);
}
#endif

static void gen_setc_zf(translation_context * context, reil_register reg, size_t reg_size)
{
    reil_instruction * bool_is_zero = alloc_reil_instruction(context, REIL_BISZ);

    bool_is_zero->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    bool_is_zero->operands[0].reg = reg;
    bool_is_zero->operands[0].size = reg_size;

    bool_is_zero->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    bool_is_zero->operands[2].reg = REG_ZF;
    bool_is_zero->operands[2].size = EFLAGS_REGISTER_SIZE;
}

static void calculate_memory_offset(translation_context * context, POPERAND x86operand, int * offset, size_t * offset_size, reil_operand_type * offset_type)
{
    /* Offset = Base + (Index * Scale) + Displacement */
    reil_register base = get_operand_basereg(x86operand);
    reil_register index = get_operand_indexreg(x86operand);
    reil_integer scale = get_operand_scale(x86operand);
    reil_integer displacement = 0;
    int has_displacement = get_operand_displacement(x86operand, (unsigned int*)&displacement);

    *offset = 0;
    *offset_size = 0;
    /* We assume it is a register, because this is the most common case. */
    *offset_type = REIL_OPERAND_TYPE_REGISTER;

    if ( index != REG_NOP )
    {
        if ( scale )
        {
            reil_register multiplicand = index;
            int multiplier = scale;
            size_t multiplicands_size = get_operand_size(context->x86instruction, x86operand);

            scratch_register * result = gen_multiply_reg_int(context, multiplicand, multiplicands_size, multiplier, multiplicands_size);
            *offset = get_reil_reg_from_scratch_reg(context, result);
            *offset_size = result->size;
        }
        else
        {
            *offset = index;
            *offset_size = get_operand_size(context->x86instruction, x86operand);
        }
    }

    if (base != REG_NOP )
    {
        if ( *offset_size )
        {
            reil_register addend1, addend2;
            addend1 = base;
            addend2 = *offset;

            size_t addend1_size = get_operand_size(context->x86instruction, x86operand);
            size_t addend2_size = *offset_size;

            scratch_register * result = gen_add_reg_reg(context, addend1, addend1_size, addend2, addend2_size);
            *offset = get_reil_reg_from_scratch_reg(context, result);
            *offset_size = result->size;
        }
        else
        {
            *offset = base;
            *offset_size = get_operand_size(context->x86instruction, x86operand);
        }
    }

    if ( has_displacement )
    {
        if ( *offset_size )
        {
            reil_register addend1 = *offset;
            reil_integer  addend2 = displacement;

            size_t addend1_size = *offset_size;
            size_t addend2_size = get_operand_size(context->x86instruction, x86operand);

            scratch_register * result = gen_add_reg_int(context, addend1, addend1_size, addend2, addend2_size);
            *offset = get_reil_reg_from_scratch_reg(context, result);
            *offset_size = result->size;
        }
        else
        {
            *offset = displacement;
            *offset_size = get_operand_size(context->x86instruction, x86operand);
            *offset_type = REIL_OPERAND_TYPE_INTEGER;
        }
    }
}

static reil_register get_reil_reg_from_scratch_reg(translation_context * context, scratch_register * reg)
{
    return ((unsigned long)reg - (unsigned long)&context->scratch_registers[0]) / sizeof(context->scratch_registers[0]) + SCRATCH_REGISTER_BASE;
}

static void gen_arithmetic_instr(translation_context * context, reil_instruction_index index)
{
    if ( context->x86instruction->op1.type == OPERAND_TYPE_REGISTER && context->x86instruction->op2.type == OPERAND_TYPE_IMMEDIATE)
    {
        unsigned int imm;
        if ( get_operand_immediate(&context->x86instruction->op2, &imm))
        {
            reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);
            reil_register op1_reg = x86regop_to_reilreg(context, &context->x86instruction->op1);
            size_t op1_reg_size = get_operand_size(context->x86instruction, &context->x86instruction->op1);

            arithmetic_instr->operands[REIL_OPERAND_INPUT1].type = REIL_OPERAND_TYPE_REGISTER;
            arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg = op1_reg;
            arithmetic_instr->operands[REIL_OPERAND_INPUT1].size = op1_reg_size;

            arithmetic_instr->operands[REIL_OPERAND_INPUT2].type = REIL_OPERAND_TYPE_INTEGER;
            arithmetic_instr->operands[REIL_OPERAND_INPUT2].integer = imm;
            arithmetic_instr->operands[REIL_OPERAND_INPUT2].size = get_operand_size(context->x86instruction, &context->x86instruction->op2);

            scratch_register * output = alloc_scratch_reg(context);
            unsigned int reg_scale;
            if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
                reg_scale = 2;
            else
                reg_scale = 1;
            output->size = reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].size);

            arithmetic_instr->operands[REIL_OPERAND_OUTPUT].type = REIL_OPERAND_TYPE_REGISTER;
            arithmetic_instr->operands[REIL_OPERAND_OUTPUT].reg = get_reil_reg_from_scratch_reg(context, output);
            arithmetic_instr->operands[REIL_OPERAND_OUTPUT].size = output->size;

            scratch_register * reduced_output = gen_reduce(context, get_reil_reg_from_scratch_reg(context, output), output->size, op1_reg_size);

            /* Update eflags here, so we have all the results intact without copying stuff. */
            reil_operand *op1, *op2, op3;
            op1 = &arithmetic_instr->operands[0];
            op2 = &arithmetic_instr->operands[1];
            op3.type = REIL_OPERAND_TYPE_REGISTER;
            op3.reg = get_reil_reg_from_scratch_reg(context, reduced_output);
            op3.size = reduced_output->size;

            gen_eflags_update(context, index, op1, op2, &op3);

            gen_storereg_reg(context, op3.reg, op3.size, op1_reg, op1_reg_size);
        }
        else
        {
            gen_unknown(context);
        }
    }
    else if ( context->x86instruction->op1.type == OPERAND_TYPE_REGISTER && context->x86instruction->op2.type == OPERAND_TYPE_REGISTER)
    {
        reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);
        reil_register op1_reg = x86regop_to_reilreg(context, &context->x86instruction->op1);
        size_t op1_reg_size = get_operand_size(context->x86instruction, &context->x86instruction->op1);

        arithmetic_instr->operands[REIL_OPERAND_INPUT1].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg = op1_reg;
        arithmetic_instr->operands[REIL_OPERAND_INPUT1].size = op1_reg_size;
        
        arithmetic_instr->operands[REIL_OPERAND_INPUT2].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_INPUT2].reg = x86regop_to_reilreg(context, &context->x86instruction->op2);
        arithmetic_instr->operands[REIL_OPERAND_INPUT2].size = get_operand_size(context->x86instruction, &context->x86instruction->op2);
        
        scratch_register * output = alloc_scratch_reg(context);
        unsigned int reg_scale;
        if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
            reg_scale = 2;
        else
            reg_scale = 1;
        output->size = reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].size);

        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].reg = get_reil_reg_from_scratch_reg(context, output);
        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].size = output->size;

        scratch_register * reduced_output = gen_reduce(context, get_reil_reg_from_scratch_reg(context, output), output->size, op1_reg_size);

        /* Update eflags here, so we have all the results intact without copying stuff. */
        reil_operand *op1, *op2, op3;
        op1 = &arithmetic_instr->operands[0];
        op2 = &arithmetic_instr->operands[1];
        op3.type = REIL_OPERAND_TYPE_REGISTER;
        op3.reg = get_reil_reg_from_scratch_reg(context, reduced_output);
        op3.size = reduced_output->size;

        gen_eflags_update(context, index, op1, op2, &op3);

        gen_storereg_reg(context, op3.reg, op3.size, op1_reg, op1_reg_size);
    }
    else if ( context->x86instruction->op1.type == OPERAND_TYPE_REGISTER && context->x86instruction->op2.type == OPERAND_TYPE_MEMORY)
    {
        int offset;
        size_t offset_size;
        reil_operand_type offset_type;

        calculate_memory_offset(context, &context->x86instruction->op2, &offset, &offset_size, &offset_type);

        scratch_register * value;
        if (offset_type == REIL_OPERAND_TYPE_REGISTER )
        {
            if ( context->x86instruction->mode == MODE_32 && offset_size > 4 )
            {
                scratch_register * reduced_offset = gen_reduce(context, offset, offset_size, 4);
                offset = get_reil_reg_from_scratch_reg(context, reduced_offset);
                offset_size = reduced_offset->size;
            }

            if ( context->x86instruction->mode == MODE_16 && offset_size > 2 )
            {
                scratch_register * reduced_offset = gen_reduce(context, offset, offset_size, 2);
                offset = get_reil_reg_from_scratch_reg(context, reduced_offset);
                offset_size = reduced_offset->size;
            }
            value = gen_load_reg(context, (reil_register)offset, offset_size);
        }
        else /* REIL_OPERAND_INTEGER */
        {
            value = gen_load_int(context, (reil_integer)offset, offset_size);
        }

        reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);
        reil_register op1_reg = x86regop_to_reilreg(context, &context->x86instruction->op1);
        size_t op1_reg_size = get_operand_size(context->x86instruction, &context->x86instruction->op1);

        arithmetic_instr->operands[REIL_OPERAND_INPUT1].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg = op1_reg;
        arithmetic_instr->operands[REIL_OPERAND_INPUT1].size = op1_reg_size;
        
        arithmetic_instr->operands[REIL_OPERAND_INPUT2].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_INPUT2].reg = get_reil_reg_from_scratch_reg(context, value);
        arithmetic_instr->operands[REIL_OPERAND_INPUT2].size = value->size;

        scratch_register * output = alloc_scratch_reg(context);
        unsigned int reg_scale;
        if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
            reg_scale = 2;
        else
            reg_scale = 1;
        output->size = reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].size);

        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].reg = get_reil_reg_from_scratch_reg(context, output);
        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].size = output->size;

        scratch_register * reduced_output = gen_reduce(context, get_reil_reg_from_scratch_reg(context, output), output->size, op1_reg_size);

        /* Update eflags here, so we have all the results intact without copying stuff. */
        reil_operand *op1, *op2, op3;
        op1 = &arithmetic_instr->operands[0];
        op2 = &arithmetic_instr->operands[1];
        op3.type = REIL_OPERAND_TYPE_REGISTER;
        op3.reg = get_reil_reg_from_scratch_reg(context, reduced_output);
        op3.size = reduced_output->size;

        gen_eflags_update(context, index, op1, op2, &op3);

        gen_storereg_reg(context, op3.reg, op3.size, op1_reg, op1_reg_size);
    }
    else if (context->x86instruction->op1.type == OPERAND_TYPE_MEMORY && context->x86instruction->op2.type == OPERAND_TYPE_IMMEDIATE)
    {
        int offset;
        size_t offset_size;
        reil_operand_type offset_type;

        calculate_memory_offset(context, &context->x86instruction->op1, &offset, &offset_size, &offset_type);

        scratch_register * value;
        if (offset_type == REIL_OPERAND_TYPE_REGISTER )
        {
            value = gen_load_reg(context, (reil_register)offset, offset_size);
        }
        else /* REIL_OPERAND_INTEGER */
        {
            value = gen_load_int(context, (reil_integer)offset, offset_size);
        }

        reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);

        arithmetic_instr->operands[REIL_OPERAND_INPUT1].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg = get_reil_reg_from_scratch_reg(context, value);
        arithmetic_instr->operands[REIL_OPERAND_INPUT1].size = value->size;

        unsigned int imm;
        if ( get_operand_immediate(&context->x86instruction->op2, &imm))
        {
            arithmetic_instr->operands[REIL_OPERAND_INPUT2].type = REIL_OPERAND_TYPE_INTEGER;
            arithmetic_instr->operands[REIL_OPERAND_INPUT2].integer = (reil_integer)imm;
            arithmetic_instr->operands[REIL_OPERAND_INPUT2].size = get_operand_size(context->x86instruction, &context->x86instruction->op2);

            scratch_register * output = alloc_scratch_reg(context);
            unsigned int reg_scale;
            if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
                reg_scale = 2;
            else
                reg_scale = 1;
            output->size = reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].size);

            arithmetic_instr->operands[REIL_OPERAND_OUTPUT].type = REIL_OPERAND_TYPE_REGISTER;
            arithmetic_instr->operands[REIL_OPERAND_OUTPUT].reg = get_reil_reg_from_scratch_reg(context, output);
            arithmetic_instr->operands[REIL_OPERAND_OUTPUT].size = output->size;

            scratch_register * reduced_output = gen_reduce(context, get_reil_reg_from_scratch_reg(context, output), output->size,  get_operand_size(context->x86instruction, &context->x86instruction->op1));

            /* Update eflags here, so we have all the results intact without copying stuff. */
            reil_operand *op1, *op2, op3;
            op1 = &arithmetic_instr->operands[0];
            op2 = &arithmetic_instr->operands[1];
            op3.type = REIL_OPERAND_TYPE_REGISTER;
            op3.reg = get_reil_reg_from_scratch_reg(context, reduced_output);
            op3.size = reduced_output->size;

            gen_eflags_update(context, index, op1, op2, &op3);

            gen_store_reg_reg(context, offset, offset_size, op3.reg, op3.size);
        }
        else
        {
            gen_unknown(context);
        }
    }
    else if (context->x86instruction->op1.type == OPERAND_TYPE_MEMORY && context->x86instruction->op2.type == OPERAND_TYPE_REGISTER)
    {
        int offset;
        size_t offset_size;
        reil_operand_type offset_type;

        calculate_memory_offset(context, &context->x86instruction->op1, &offset, &offset_size, &offset_type);

        scratch_register * value;
        if (offset_type == REIL_OPERAND_TYPE_REGISTER )
        {
            if ( context->x86instruction->mode == MODE_32 && offset_size > 4 )
            {
                scratch_register * reduced_offset = gen_reduce(context, offset, offset_size, 4);
                offset = get_reil_reg_from_scratch_reg(context, reduced_offset);
                offset_size = reduced_offset->size;
            }

            if ( context->x86instruction->mode == MODE_16 && offset_size > 2 )
            {
                scratch_register * reduced_offset = gen_reduce(context, offset, offset_size, 2);
                offset = get_reil_reg_from_scratch_reg(context, reduced_offset);
                offset_size = reduced_offset->size;
            }

            value = gen_load_reg(context, (reil_register)offset, offset_size);
        }
        else /* REIL_OPERAND_INTEGER */
        {
            value = gen_load_int(context, (reil_integer)offset, offset_size);
        }

        reil_instruction * arithmetic_instr = alloc_reil_instruction(context, index);

        arithmetic_instr->operands[REIL_OPERAND_INPUT1].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_INPUT1].reg = get_reil_reg_from_scratch_reg(context, value);
        arithmetic_instr->operands[REIL_OPERAND_INPUT1].size = value->size;

        arithmetic_instr->operands[REIL_OPERAND_INPUT2].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_INPUT2].reg = x86regop_to_reilreg(context, &context->x86instruction->op2);
        arithmetic_instr->operands[REIL_OPERAND_INPUT2].size = get_operand_size(context->x86instruction, &context->x86instruction->op2);

        scratch_register * output = alloc_scratch_reg(context);
        unsigned int reg_scale;
        if ( index != REIL_DIV || index != REIL_MOD || index != REIL_RSH )
            reg_scale = 2;
        else
            reg_scale = 1;
        output->size = reg_scale*MAX(arithmetic_instr->operands[REIL_OPERAND_INPUT1].size, arithmetic_instr->operands[REIL_OPERAND_INPUT2].size);

        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].type = REIL_OPERAND_TYPE_REGISTER;
        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].reg = get_reil_reg_from_scratch_reg(context, output);
        arithmetic_instr->operands[REIL_OPERAND_OUTPUT].size = output->size;

        scratch_register * reduced_output = gen_reduce(context, get_reil_reg_from_scratch_reg(context, output), output->size,  get_operand_size(context->x86instruction, &context->x86instruction->op1));

        /* Update eflags here, so we have all the results intact without copying stuff. */
        reil_operand *op1, *op2, op3;
        op1 = &arithmetic_instr->operands[0];
        op2 = &arithmetic_instr->operands[1];
        op3.type = REIL_OPERAND_TYPE_REGISTER;
        op3.reg = get_reil_reg_from_scratch_reg(context, reduced_output);
        op3.size = reduced_output->size;

        gen_eflags_update(context, index, op1, op2, &op3);

        gen_store_reg_reg(context, offset, offset_size, op3.reg, op3.size);
    }
    else
    {
        gen_unknown(context);
    }
}

static reil_register x86regop_to_reilreg(translation_context * context, POPERAND op)
{
    reil_register reg = -1;
	int regtype = 0;
    // Determine register type
    switch (MASK_AM(op->flags)) {
        case AM_REG:
            if (MASK_FLAGS(op->flags) == F_r)
                regtype = REG_SEGMENT;
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
        switch (MASK_OT(op->flags)) 
        {
            case OT_b:
                reg = (REG_GEN_BYTE << 8) + op->reg;
                break;
            case OT_v:
                reg = (MODE_CHECK_OPERAND(context->x86instruction->mode, context->x86instruction->flags) == MODE_32) ?  (REG_GEN_DWORD << 3) + op->reg : (REG_GEN_WORD << 8) + op->reg;
                break;
            case OT_w:
                reg = (REG_GEN_WORD << 8) + op->reg;
                break;
            case OT_d:
                reg = (REG_GEN_DWORD << 8) + op->reg;
                break;
        }
    } 
    else
    {
        reg = (regtype << 8) + op->reg;
    }

    return reg;
}

const char *reil_register_x86_formatter(reil_operand * register_operand)
{
    static char format_buffer[strlen("xword Txxx")+1];
    if ( register_operand->reg >= SCRATCH_REGISTER_BASE )
    {
        const char * size_prefix;
        switch (register_operand->size)
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
        snprintf(format_buffer, sizeof(format_buffer), "%s T%i", size_prefix, register_operand->reg);
    }
    else
    {
        snprintf(format_buffer, sizeof(format_buffer), "%s", ((const char**)x86reg_table)[register_operand->reg]);
    }
    return format_buffer;
}

static scratch_register * get_scratch_reg_from_reil_reg(translation_context * context, reil_register reg)
{
    if ( reg >= SCRATCH_REGISTER_BASE )
    {
        return &context->scratch_registers[reg - SCRATCH_REGISTER_BASE];
    }
    return NULL;
}
