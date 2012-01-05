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

#define MAX(X, Y) (((X) > (Y))?(X):(Y))
#define SCRATCH_REGISTER_BASE 256
#define MAX_SCRATCH_REGISTERS 256

/* Given a pointer to a scratch register, this returns the index */
#define SCRATCH_REGISTER_INDEX(REG) ((((unsigned long)(REG) - (unsigned long)&context->scratch_registers[0]) / sizeof(context->scratch_registers[0])) + SCRATCH_REGISTER_BASE)
#define IS_SCRATCH_REGISTER(REG_INDEX) ((REG_INDEX) >= SCRATCH_REGISTER_BASE)

typedef struct _scratch_register
{
    size_t size;
} scratch_register;

typedef struct _translation_context
{
    /* The instruction being translated */
    INSTRUCTION * x86instruction;
    /* Buffer used to store intermediate result of the translation process. */
    reil_instruction instruction_buffer[REIL_MAX_INSTRUCTIONS];
    reil_instruction * instruction_sort_buffer[REIL_MAX_INSTRUCTIONS];
    size_t num_of_instructions;
    size_t last_offset;
    reil_register next_free_register;
    unsigned long address;
    scratch_register scratch_registers[MAX_SCRATCH_REGISTERS];
} translation_context;


/* This array hold the X86 instructions that map easily to REIL instructions */
enum Instruction simple_instructions[] =
{
    INSTRUCTION_TYPE_ADD,
    INSTRUCTION_TYPE_SUB,
    INSTRUCTION_TYPE_MUL,
    INSTRUCTION_TYPE_DIV,
    INSTRUCTION_TYPE_SHX,
    INSTRUCTION_TYPE_AND,
    INSTRUCTION_TYPE_OR,
    INSTRUCTION_TYPE_XOR,
    INSTRUCTION_TYPE_PUSH
};

static size_t get_operand_size(INSTRUCTION * x86instruction, OPERAND * x86operand);
static void init_translation_context(translation_context * context, INSTRUCTION * x86instruction, unsigned long address);
static void translate_operand(translation_context * context, OPERAND * x86operand, reil_instruction * instruction, reil_operand_index operand_index);
static int is_direct_translatable(enum Instruction x86instruction);
static scratch_register * alloc_scratch_reg(translation_context * context);
static size_t get_scratch_reg_size(translation_context * context, reil_register reg);
static void calculate_memory_offset(translation_context * context, POPERAND x86operand, int * offset, size_t * offset_size, reil_operand_type * offset_type);

static void gen_unknown(translation_context * context);
static void gen_storereg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size);
static void gen_storereg_int(translation_context * context, reil_integer integer, size_t integer_size, reil_register reg, size_t reg_size);
static void gen_store_reg_reg(translation_context * context, reil_register address, size_t address_size, reil_register value, size_t value_size);
static void gen_store_int_reg(translation_context * context, reil_integer address, size_t address_size, reil_register value, size_t value_size);
static reil_register gen_load_reg(translation_context * context, reil_register reg, size_t reg_size);
static reil_register gen_load_int(translation_context * context, reil_integer integer, size_t integer_size);
static reil_register gen_add_reg_int(translation_context * context, reil_register reg, size_t reg_size, int integer, size_t integer_size);
static reil_register gen_multiply_reg_int(translation_context * context, reil_register multiplicand, size_t multiplicand_size, int multiplier, size_t multiplier_size);
static reil_register gen_add_reg_reg(translation_context * context, reil_register addend1, size_t addend1_size, reil_register addend2, size_t addend2_size);

reil_instructions * reil_translate(unsigned long address, INSTRUCTION * x86instruction)
{
    translation_context context;
    init_translation_context(&context, x86instruction, address);

    reil_instructions * instructions = NULL;

    if (is_direct_translatable(x86instruction->type))
    {
        reil_instruction * instruction = &context.instruction_buffer[context.num_of_instructions++];
        switch (x86instruction->type)
        {
            case INSTRUCTION_TYPE_ADD:
                {
                    memcpy(instruction, &reil_instruction_table[REIL_ADD], sizeof(reil_instruction_table[0]));
                }
                break;
            case INSTRUCTION_TYPE_SUB:
                {
                    memcpy(instruction, &reil_instruction_table[REIL_SUB], sizeof(reil_instruction_table[0]));
                }
                break;
            case INSTRUCTION_TYPE_MUL:
                {
                    memcpy(instruction, &reil_instruction_table[REIL_MUL], sizeof(reil_instruction_table[0]));
                }
                break;
            case INSTRUCTION_TYPE_DIV:
                {
                    memcpy(instruction, &reil_instruction_table[REIL_DIV], sizeof(reil_instruction_table[0]));
                }
                break;
            case INSTRUCTION_TYPE_SHX:
                {
                    if (!strcmp(instruction->mnemonic, "shl"))
                    {
                        memcpy(instruction, &reil_instruction_table[REIL_LSH], sizeof(reil_instruction_table[0]));
                    }
                    else if ( !strcmp(instruction->mnemonic, "shr"))
                    {
                        memcpy(instruction, &reil_instruction_table[REIL_RSH], sizeof(reil_instruction_table[0]));
                    }
                    else
                    {
                        gen_unknown(&context);
                    }
                }
                break;
            case INSTRUCTION_TYPE_AND:
                {
                    memcpy(instruction, &reil_instruction_table[REIL_AND], sizeof(reil_instruction_table[0]));
                }
                break;
            case INSTRUCTION_TYPE_OR:
                {
                    memcpy(instruction, &reil_instruction_table[REIL_OR], sizeof(reil_instruction_table[0]));
                }
                break;
            case INSTRUCTION_TYPE_XOR:
                {
                    memcpy(instruction, &reil_instruction_table[REIL_XOR], sizeof(reil_instruction_table[0]));
                }
                break;
            case INSTRUCTION_TYPE_PUSH:
                {
                    /* Allocate space on the stack */
                    memcpy(instruction, &reil_instruction_table[REIL_SUB], sizeof(reil_instruction_table[0]));
                    instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
                    instruction->operands[0].reg = REG_ESP;
                    instruction->operands[0].size = 0x4;
                    instruction->operands[2].type = REIL_OPERAND_TYPE_INTEGER;
                    instruction->operands[2].integer = get_operand_size(x86instruction, &x86instruction->op1);
                    instruction->operands[2].size = get_operand_size(x86instruction, &x86instruction->op1);

                    /* Allocate new instruction */
                    instruction = &context.instruction_buffer[context.num_of_instructions++];

                    /* Store operand on the stack */
                    memcpy(instruction, &reil_instruction_table[REIL_STM], sizeof(reil_instruction_table[0]));
                    instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
                    instruction->operands[0].reg = REG_ESP;
                    instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
                    instruction->operands[2].reg = context.next_free_register - 1;
                    instruction->operands[2].size = get_operand_size(x86instruction, &x86instruction->op1);
                }
                break;
            default:
                {
                    gen_unknown(&context);
                }
                break;
        }

        instruction->address = REIL_ADDRESS(address);

        if ( instruction->flags & REIL_INSTRUCTION_FLAG_INPUT1 )
            translate_operand(&context, &x86instruction->op1, instruction, REIL_OPERAND_INPUT1);
        if ( instruction->flags & REIL_INSTRUCTION_FLAG_INPUT2 )
            translate_operand(&context, &x86instruction->op2, instruction, REIL_OPERAND_INPUT2);

        instruction->offset = context.last_offset++;

        if ( instruction->flags & REIL_INSTRUCTION_FLAG_OUTPUT )
            translate_operand(&context, &x86instruction->op1, instruction, REIL_OPERAND_OUTPUT);
    }
    else
    {
        switch (x86instruction->type)
        {
            case INSTRUCTION_TYPE_MOV:
                {
                    if ( x86instruction->op1.type == OPERAND_TYPE_REGISTER && x86instruction->op2.type == OPERAND_TYPE_REGISTER)
                    {
                        gen_storereg_reg(&context, get_operand_register(&x86instruction->op2),
                                get_operand_size(x86instruction, &x86instruction->op2),
                                    get_operand_register(&x86instruction->op1),
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
                                    get_operand_register(&x86instruction->op2),
                                    get_operand_size(x86instruction, &x86instruction->op2));
                        }
                        else /* REIL_OPERAND_TYPE_INTEGER */
                        {
                            gen_store_int_reg(&context, (reil_integer)offset, offset_size,
                                    get_operand_register(&x86instruction->op2),
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
                            reil_register result_reg = gen_load_reg(&context, (reil_register)offset, offset_size);
                            gen_storereg_reg(&context, result_reg, get_scratch_reg_size(&context, result_reg), 
                                    get_operand_register(&x86instruction->op1),
                                    get_operand_size(x86instruction, &x86instruction->op1));
                        }
                        else /* REIL_OPERAND_TYPE_INTEGER */
                        {
                            reil_register result_reg = gen_load_int(&context, (reil_integer)offset, offset_size);
                            gen_storereg_reg(&context, result_reg, get_scratch_reg_size(&context, result_reg), 
                                    get_operand_register(&x86instruction->op1),
                                    get_operand_size(x86instruction, &x86instruction->op1));
                        }

                    }
#if 0
                    else if ( x86instruction->op1.type == OPERAND_TYPE_REGISTER && x86instruction->op2.type == OPERAND_TYPE_IMMEDIATE)
                    {
                        translate_operand(&context, &x86instruction->op2, instruction, REIL_OPERAND_INPUT1);
                        translate_operand(&context, &x86instruction->op1, instruction, REIL_OPERAND_OUTPUT);
                    }
#endif
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
    }
        
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

static void init_translation_context(translation_context * context, INSTRUCTION * x86instruction, unsigned long address)
{
    memset(context, 0, sizeof(*context));
    context->x86instruction = x86instruction;
    context->next_free_register = SCRATCH_REGISTER_BASE;
    context->address = address;
}

static void translate_operand(translation_context * context, OPERAND * x86operand, reil_instruction * instruction, reil_operand_index operand_index)
{
    reil_operand * operand = &instruction->operands[operand_index];
    if ( x86operand->type == OPERAND_TYPE_REGISTER )
    {
        if ( operand_index == REIL_OPERAND_INPUT1 || operand_index == REIL_OPERAND_INPUT2 )
        {
            operand->type = REIL_OPERAND_TYPE_REGISTER;
            operand->reg = get_operand_register(x86operand);
            operand->size = get_operand_size(context->x86instruction, x86operand);
        }
        else /* REIL_OPERAND_FLAG_OUTPUT */
        {
            operand->type = REIL_OPERAND_TYPE_REGISTER;

            /* The size of the output register is different for arithmetic
             * instructions because of possible overflows. */
            if (instruction->group == REIL_ARITHMETIC_INSTRUCTION)
            {
                scratch_register * output = alloc_scratch_reg(context);
                output->size =  2*MAX(instruction->operands[0].size, instruction->operands[1].size);

                operand->reg = SCRATCH_REGISTER_INDEX(output);
                operand->size = output->size;
                
                gen_storereg_reg(context, SCRATCH_REGISTER_INDEX(output), output->size, get_operand_register(x86operand), get_operand_size(context->x86instruction, x86operand));
            }
            else
            {
                operand->reg = x86operand->reg;
                operand->size = (context->x86instruction->mode == MODE_32)?4:2;
            }
        }
    }
    else if ( x86operand->type == OPERAND_TYPE_IMMEDIATE )
    {
        operand->type = REIL_OPERAND_TYPE_INTEGER;
        get_operand_immediate(x86operand, (unsigned int *)&operand->integer);
        operand->size = get_operand_size(context->x86instruction, x86operand);
    }
    else /* OPERAND_TYPE_MEMORY */
    {
        
        /* Depending on the operand encoding, this holds the actual address or the register number that contains the address. */
        int offset;
        /* We explicitly save the size, because the reil registers and scratch registers  are different internal but used as if the same.*/
        size_t offset_size;
        reil_operand_type offset_type;

        calculate_memory_offset(context, x86operand, &offset, &offset_size, &offset_type);

        if ( offset_type == REIL_OPERAND_TYPE_REGISTER )
        {
            if ( operand_index == REIL_OPERAND_INPUT1 || operand_index == REIL_OPERAND_INPUT2 )
            {
                reil_register destination = gen_load_reg(context, offset, offset_size);
                operand->type = REIL_OPERAND_TYPE_REGISTER;
                operand->reg = destination;
                operand->size = get_scratch_reg_size(context, destination);
            }
            else
            {
                scratch_register * destination = alloc_scratch_reg(context);
                if (instruction->group == REIL_ARITHMETIC_INSTRUCTION)
                {
                    destination->size = 2*MAX(instruction->operands[0].size, instruction->operands[1].size);
                }
                else
                {
                    destination->size = offset_size;
                }
                
                operand->type = REIL_OPERAND_TYPE_REGISTER;
                operand->reg = (reil_register)SCRATCH_REGISTER_INDEX(destination);
                operand->size = destination->size;

                gen_store_reg_reg(context, (reil_register)offset, offset_size, SCRATCH_REGISTER_INDEX(destination), destination->size);
            }
        }
        else
        {
            if ( operand_index == REIL_OPERAND_INPUT1 || operand_index == REIL_OPERAND_INPUT2 )
            {
                reil_register result = gen_load_int(context, offset, offset_size);
                operand->type = REIL_OPERAND_TYPE_REGISTER;
                operand->reg = result;
                operand->size = get_scratch_reg_size(context,result);
            }
            else
            {
                scratch_register * destination = alloc_scratch_reg(context);
                if (instruction->group == REIL_ARITHMETIC_INSTRUCTION)
                {
                    destination->size = 2*MAX(instruction->operands[0].size, instruction->operands[1].size);
                }
                else
                {
                    destination->size = offset_size;
                }

                gen_store_int_reg(context, offset, offset_size, SCRATCH_REGISTER_INDEX(destination), destination->size);
                operand->type = REIL_OPERAND_TYPE_REGISTER;
                operand->reg = (reil_register)SCRATCH_REGISTER_INDEX(destination);
                operand->size = destination->size;
            }
        }
    }
}

static scratch_register * alloc_scratch_reg(translation_context * context)
{
    scratch_register * reg = &context->scratch_registers[context->next_free_register - SCRATCH_REGISTER_BASE];
    context->next_free_register++;

    return reg;
}

static size_t get_scratch_reg_size(translation_context * context, reil_register reg)
{
    return context->scratch_registers[reg - SCRATCH_REGISTER_BASE].size;
}

static void gen_unknown(translation_context * context)
{
    reil_instruction * unknown_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(unknown_instruction, &reil_instruction_table[REIL_UNKN], sizeof(reil_instruction));

    unknown_instruction->address = REIL_ADDRESS(context->address);
    unknown_instruction->offset = context->last_offset++;
}

static void gen_storereg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size)
{
    reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(store_instruction, &reil_instruction_table[REIL_STR], sizeof(reil_instruction));

    store_instruction->address = REIL_ADDRESS(context->address);
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

    store_instruction->address = REIL_ADDRESS(context->address);
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

    store_instruction->address = REIL_ADDRESS(context->address);
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

    store_instruction->address = REIL_ADDRESS(context->address);
    store_instruction->offset = context->last_offset++; 

    store_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    store_instruction->operands[0].reg = value;
    store_instruction->operands[0].size = value_size;
    
    store_instruction->operands[2].type = REIL_OPERAND_TYPE_INTEGER;
    store_instruction->operands[2].integer = address;
    store_instruction->operands[2].size = address_size;
}

static reil_register gen_load_reg(translation_context * context, reil_register reg, size_t reg_size)
{
    reil_instruction * load_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(load_instruction, &reil_instruction_table[REIL_LDM], sizeof(reil_instruction));

    load_instruction->address = REIL_ADDRESS(context->address);
    load_instruction->offset = context->last_offset++;

    load_instruction->operands[0].type = REIL_OPERAND_TYPE_REGISTER;
    load_instruction->operands[0].reg = reg;
    load_instruction->operands[0].size = reg_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = reg_size;

    load_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    load_instruction->operands[2].reg = SCRATCH_REGISTER_INDEX(output);
    load_instruction->operands[2].size = output->size;

    return SCRATCH_REGISTER_INDEX(output);
}

static reil_register gen_load_int(translation_context * context, reil_integer integer, size_t integer_size)
{
    reil_instruction * load_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(load_instruction, &reil_instruction_table[REIL_LDM], sizeof(reil_instruction));

    load_instruction->address = REIL_ADDRESS(context->address);
    load_instruction->offset = context->last_offset++;

    load_instruction->operands[0].type = REIL_OPERAND_TYPE_INTEGER;
    load_instruction->operands[0].integer = integer;
    load_instruction->operands[0].size = integer_size;

    scratch_register * output = alloc_scratch_reg(context);
    output->size = integer_size;

    load_instruction->operands[2].type = REIL_OPERAND_TYPE_REGISTER;
    load_instruction->operands[2].reg = SCRATCH_REGISTER_INDEX(output);
    load_instruction->operands[2].size = output->size;
    
    return SCRATCH_REGISTER_INDEX(output);
}

static reil_register gen_add_reg_int(translation_context * context, reil_register reg, size_t reg_size, int integer, size_t integer_size)
{
    reil_instruction * add_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(add_instruction, &reil_instruction_table[REIL_ADD], sizeof(reil_instruction));

    add_instruction->address = REIL_ADDRESS(context->address);
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
    add_instruction->operands[2].reg = SCRATCH_REGISTER_INDEX(output);
    add_instruction->operands[2].size = output->size; 
    
    return SCRATCH_REGISTER_INDEX(output);
}

static reil_register gen_multiply_reg_int(translation_context * context, reil_register multiplicand, size_t multiplicand_size, int multiplier, size_t multiplier_size)
{
    reil_instruction * multiply_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(multiply_instruction, &reil_instruction_table[REIL_MUL], sizeof(reil_instruction));

    multiply_instruction->address = REIL_ADDRESS(context->address);
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
    multiply_instruction->operands[2].reg = SCRATCH_REGISTER_INDEX(output);
    multiply_instruction->operands[2].size = output->size;
    
    return SCRATCH_REGISTER_INDEX(output);
}

static reil_register gen_add_reg_reg(translation_context * context, reil_register addend1, size_t addend1_size, reil_register addend2, size_t addend2_size)
{
    reil_instruction * add_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(add_instruction, &reil_instruction_table[REIL_ADD], sizeof(reil_instruction));

    add_instruction->address = REIL_ADDRESS(context->address);
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
    add_instruction->operands[2].reg = SCRATCH_REGISTER_INDEX(output);
    add_instruction->operands[2].size = output->size;
    
    return SCRATCH_REGISTER_INDEX(output);
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

            *offset = gen_multiply_reg_int(context, multiplicand, multiplicands_size, multiplier, multiplicands_size);
            *offset_size = get_scratch_reg_size(context,*offset);
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

            *offset = gen_add_reg_reg(context, addend1, addend1_size, addend2, addend2_size);
            *offset_size = get_scratch_reg_size(context,*offset);
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

            *offset = gen_add_reg_int(context, addend1, addend1_size, addend2, addend2_size);
            *offset_size = get_scratch_reg_size(context,*offset);
        }
        else
        {
            *offset = displacement;
            *offset_size = get_operand_size(context->x86instruction, x86operand);
            *offset_type = REIL_OPERAND_TYPE_INTEGER;
        }
    }
}

int is_direct_translatable(enum Instruction x86instruction)
{
    int i;
    for ( i = 0; i < sizeof(simple_instructions)/sizeof(simple_instructions[0]); i++)
    {
        if ( simple_instructions[i] == x86instruction )
            return 1;
    }
    return 0;
}
