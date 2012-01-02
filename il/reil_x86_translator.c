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
#define NEXT_FREE_REGISTER_BASE 256

typedef struct _translation_context
{
    /* Buffer used to store intermediate result during the translation process. */
    reil_instruction instruction_buffer[REIL_MAX_INSTRUCTIONS];
    reil_instruction * instruction_sort_buffer[REIL_MAX_INSTRUCTIONS];
    size_t num_of_instructions;
    size_t last_offset;
    reil_register next_free_register;
    unsigned long address;
} translation_context;

/* This array holds the X86 instructions that map easily to REIL instructions */
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
static void init_translation_context(translation_context * context, unsigned long address);
static void translate_operand(INSTRUCTION * x86instruction, translation_context * context, reil_instruction * instruction, reil_operand_index operand_index);
static int is_simple(enum Instruction x86instruction);

static void emit_unknown(translation_context * context);
static void emit_store_reg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size);

reil_instructions * reil_translate(unsigned long address, INSTRUCTION * x86instruction)
{
    translation_context context;
    init_translation_context(&context, address);

    reil_instructions * instructions = NULL;
    reil_instruction * instruction = &context.instruction_buffer[context.num_of_instructions++];

    if (is_simple(x86instruction->type))
    {
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
                        emit_unknown(&context);
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
                    instruction->operands[0].type = REIL_OPERAND_REGISTER;
                    instruction->operands[0].reg = REG_ESP;
                    instruction->operands[0].size = 0x4;
                    instruction->operands[2].type = REIL_OPERAND_INTEGER;
                    instruction->operands[2].integer = get_operand_size(x86instruction, &x86instruction->op1);
                    instruction->operands[2].size = get_operand_size(x86instruction, &x86instruction->op1);

                    /* Allocate new instruction */
                    instruction = &context.instruction_buffer[context.num_of_instructions++];

                    /* Store operand on the stack */
                    memcpy(instruction, &reil_instruction_table[REIL_STM], sizeof(reil_instruction_table[0]));
                    instruction->operands[0].type = REIL_OPERAND_REGISTER;
                    instruction->operands[0].reg = REG_ESP;
                    instruction->operands[2].type = REIL_OPERAND_REGISTER;
                    instruction->operands[2].reg = context.next_free_register - 1;
                    instruction->operands[2].size = get_operand_size(x86instruction, &x86instruction->op1);
                }
                break;
            default:
                {
                    emit_unknown(&context);
                }
                break;
        }

        instruction->address = REIL_ADDRESS(address);

        if ( instruction->operand_flags & REIL_OPERAND_INPUT1 )
            translate_operand(x86instruction, &context, instruction, REIL_OPERAND_INPUT1);
        if ( instruction->operand_flags & REIL_OPERAND_INPUT2 )
            translate_operand(x86instruction, &context, instruction, REIL_OPERAND_INPUT2);

        instruction->offset = context.last_offset++;

        if ( instruction->operand_flags & REIL_OPERAND_OUTPUT )
            translate_operand(x86instruction, &context, instruction, REIL_OPERAND_OUTPUT);
    }
    else
    {
        switch (x86instruction->type)
        {
            case INSTRUCTION_TYPE_MOV:
                {
                    memcpy(instruction, &reil_instruction_table[REIL_NOP], sizeof(reil_instruction_table[0]));
                    translate_operand(x86instruction, &context, instruction, REIL_OPERAND_INPUT1);
                    translate_operand(x86instruction, &context, instruction, REIL_OPERAND_INPUT2);
                    translate_operand(x86instruction, &context, instruction, REIL_OPERAND_OUTPUT);
    
                    reil_instruction * last_instruction= &context.instruction_buffer[context.num_of_instructions-1];
                    if (last_instruction->index == REIL_STR )
                        last_instruction->operands[0].reg = instruction->operands[1].reg;
                    if (last_instruction->index == REIL_STM )
                        last_instruction->operands[2].reg = last_instruction->operands[0].reg - 1;

                    /* Remove the NOP instruction */
                    instruction->offset = REIL_MAX_INSTRUCTIONS - 1;
                    //context.num_of_instructions--;
                }
                break;
            default:
                {
                    emit_unknown(&context);
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

void init_translation_context(translation_context * context, unsigned long address)
{
    memset(context, 0, sizeof(*context));
    context->next_free_register = NEXT_FREE_REGISTER_BASE;
    context->address = address;
}

void translate_operand(INSTRUCTION * x86instruction, translation_context * context, reil_instruction * instruction, reil_operand_index operand_index)
{
    OPERAND * x86operand;
    reil_operand * operand;

    if ( operand_index == REIL_OPERAND_INPUT1 )
    {
        x86operand = &x86instruction->op1;
        operand = &instruction->operands[0];
    }
    else if ( operand_index == REIL_OPERAND_INPUT2 )
    {
        x86operand = &x86instruction->op2;
        operand = &instruction->operands[1];
    }
    else if ( operand_index == REIL_OPERAND_OUTPUT )
    {
        x86operand = &x86instruction->op1;
        operand = &instruction->operands[2];
    }
    else
    {
        /* TODO: Handle invalid operand index. */
        fprintf(stderr, "Invalid operand index!\n");
    }

    if ( x86operand->type == OPERAND_TYPE_REGISTER )
    {
        if ( operand_index == REIL_OPERAND_INPUT1 || operand_index == REIL_OPERAND_INPUT2 )
        {
            operand->type = REIL_OPERAND_REGISTER;
            operand->reg = x86operand->reg;
            operand->size = get_operand_size(x86instruction, x86operand);
        }
        else /* REIL_OPERAND_OUTPUT */
        {
            operand->type = REIL_OPERAND_REGISTER;
            operand->reg = context->next_free_register++;
            operand->size = 2*MAX(instruction->operands[0].size, instruction->operands[1].size);

            if ( operand->size > instruction->operands[0].size )
            {
                size_t reg_size = (x86instruction->mode == MODE_32)?4:2;
                emit_store_reg_reg(context, context->next_free_register - 1, reg_size, x86instruction->op1.reg, reg_size);
                
                /*
                reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
                memcpy(store_instruction, &reil_instruction_table[REIL_STR], sizeof(reil_instruction));

                store_instruction->address = REIL_ADDRESS(context->address);
                store_instruction->offset = context->last_offset++; 

                store_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                store_instruction->operands[0].reg = context->next_free_register - 1;
                store_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;

                store_instruction->operands[1].type = REIL_OPERAND_EMPTY;

                store_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                store_instruction->operands[2].reg = x86instruction->op1.reg;
                store_instruction->operands[2].size = (x86instruction->mode == MODE_32)?4:2;
                */
            }
        }
    }
    else if ( x86operand->type == OPERAND_TYPE_IMMEDIATE )
    {
        operand->type = REIL_OPERAND_INTEGER;
        operand->integer = x86operand->immediate;
        operand->size = get_operand_size(x86instruction, x86operand);
    }
    else /* OPERAND_TYPE_MEMORY */
    {
        /* Base register */
        if (x86operand->basereg != REG_NOP && x86operand->indexreg == REG_NOP) 
        {
            if ( operand_index == REIL_OPERAND_INPUT1 || operand_index == REIL_OPERAND_INPUT2 )
            {
                /* Displacement */
                if ( x86operand->dispbytes )
                {
                    reil_instruction * add_instruction = &context->instruction_buffer[context->num_of_instructions++];
                    memcpy(add_instruction, &reil_instruction_table[REIL_ADD], sizeof(reil_instruction));

                    add_instruction->address = REIL_ADDRESS(context->address);
                    add_instruction->offset = context->last_offset++;

                    add_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[0].reg = x86operand->basereg;
                    add_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;

                    add_instruction->operands[1].type = REIL_OPERAND_INTEGER;
                    add_instruction->operands[1].reg = x86operand->displacement;
                    add_instruction->operands[1].size = (x86instruction->mode == MODE_32)?4:2;

                    add_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[2].reg = context->next_free_register++;
                    add_instruction->operands[2].size = 2 * MAX(add_instruction->operands[0].size, add_instruction->operands[1].size);
                }

                reil_instruction * load_instruction = &context->instruction_buffer[context->num_of_instructions++];
                memcpy(load_instruction, &reil_instruction_table[REIL_LDM], sizeof(reil_instruction));

                load_instruction->address = REIL_ADDRESS(context->address);
                load_instruction->offset = context->last_offset++;

                load_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                if ( !x86operand->dispbytes )
                {
                    load_instruction->operands[0].reg = x86operand->basereg;
                    load_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;
                }
                else
                {
                    load_instruction->operands[0].reg = context->next_free_register - 1;
                    load_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;
                }

                load_instruction->operands[1].type = REIL_OPERAND_EMPTY;

                load_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                load_instruction->operands[2].reg = context->next_free_register++;
                load_instruction->operands[2].size = load_instruction->operands[0].size;

                /* The execution of the load instruction requires a different operand for
                 * the add instruction */
                memcpy(operand, &load_instruction->operands[2], sizeof(reil_operand));
            }
            else /* REIL_OPERAND_OUTPUT */
            {
                /* The address to store the result should already be calculated
                 * and stored in the register minus 1 that is used as the first
                 * operand in the add instruction.
                 * */
                reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
                memcpy(store_instruction, &reil_instruction_table[REIL_STM], sizeof(reil_instruction));

                store_instruction->address = REIL_ADDRESS(context->address);
                store_instruction->offset = context->last_offset++;
                
                store_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                store_instruction->operands[0].reg = context->next_free_register;
                store_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;

                store_instruction->operands[1].type = REIL_OPERAND_EMPTY;

                store_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                if ( x86operand->dispbytes )
                {
                    store_instruction->operands[2].reg = instruction->operands[0].reg - 1;
                }
                else
                {
                    store_instruction->operands[2].reg = x86operand->basereg;
                }
                store_instruction->operands[2].size = (x86instruction->mode == MODE_32)?4:2;
                
                operand->type = REIL_OPERAND_REGISTER;
                operand->reg = context->next_free_register++;
                operand->size = 2*MAX(instruction->operands[0].size, instruction->operands[1].size);
            }
        }
        /* Index register */
        if (x86operand->indexreg != REG_NOP) 
        {
            if ( operand_index == REIL_OPERAND_INPUT1 || operand_index == REIL_OPERAND_INPUT2 )
            {
                if (x86operand->scale)
                {
                    reil_instruction * multiply_instruction = &context->instruction_buffer[context->num_of_instructions++];
                    memcpy(multiply_instruction, &reil_instruction_table[REIL_MUL], sizeof(reil_instruction));

                    multiply_instruction->address = REIL_ADDRESS(context->address);
                    multiply_instruction->offset = context->last_offset++;

                    multiply_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                    multiply_instruction->operands[0].reg = x86operand->indexreg;
                    multiply_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;

                    multiply_instruction->operands[1].type = REIL_OPERAND_INTEGER;
                    multiply_instruction->operands[1].integer = x86operand->scale;
                    multiply_instruction->operands[1].size = 4;

                    multiply_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                    multiply_instruction->operands[2].reg = context->next_free_register++;
                    multiply_instruction->operands[2].size = 2 * MAX(multiply_instruction->operands[0].size,
                            multiply_instruction->operands[1].size);

                }

                if (x86operand->basereg != REG_NOP)
                {
                    reil_instruction * add_instruction = &context->instruction_buffer[context->num_of_instructions++];
                    memcpy(add_instruction, &reil_instruction_table[REIL_ADD], sizeof(reil_instruction));

                    add_instruction->address = REIL_ADDRESS(context->address);
                    add_instruction->offset = context->last_offset++;

                    add_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[0].reg = x86operand->basereg;
                    add_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;

                    add_instruction->operands[1].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[1].reg = context->next_free_register - 1;
                    /* TODO: This should be the actual register size, current equal to the size of the first operand. */
                    add_instruction->operands[1].size = add_instruction->operands[0].size;

                    add_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[2].reg = context->next_free_register++;
                    add_instruction->operands[2].size = 2 * MAX(add_instruction->operands[0].size,
                            add_instruction->operands[1].size);

                }

                /* Displacement */
                if ( x86operand->dispbytes )
                {
                    reil_instruction * add_instruction = &context->instruction_buffer[context->num_of_instructions++];
                    memcpy(add_instruction, &reil_instruction_table[REIL_ADD], sizeof(reil_instruction));

                    add_instruction->address = REIL_ADDRESS(context->address);
                    add_instruction->offset = context->last_offset++;

                    add_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[0].reg = context->next_free_register - 1;
                    /* TODO: use actual register size */
                    add_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;

                    add_instruction->operands[1].type = REIL_OPERAND_INTEGER;
                    add_instruction->operands[1].reg = x86operand->displacement;
                    add_instruction->operands[1].size = (x86instruction->mode == MODE_32)?4:2;

                    add_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[2].reg = context->next_free_register++;
                    add_instruction->operands[2].size = 2 * MAX(add_instruction->operands[0].size,
                            add_instruction->operands[1].size);
                }

                reil_instruction * load_instruction = &context->instruction_buffer[context->num_of_instructions++];
                memcpy(load_instruction, &reil_instruction_table[REIL_LDM], sizeof(reil_instruction));

                load_instruction->address = REIL_ADDRESS(context->address);
                load_instruction->offset = context->last_offset++;

                load_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                load_instruction->operands[0].reg = context->next_free_register - 1;
                load_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;

                load_instruction->operands[1].type = REIL_OPERAND_EMPTY;

                load_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                load_instruction->operands[2].reg = context->next_free_register++;
                load_instruction->operands[2].size = load_instruction->operands[0].size;

                operand->type = REIL_OPERAND_REGISTER;
                operand->reg = context->next_free_register - 1;
                /* TODO: Get real size of last free register. */
                operand->size = 4;
            }
            else /* REIL_OPERAND_OUTPUT */
            {
                /* The address to store the result should already be calculated
                 * and stored in the register minus 1 that is used as the first
                 * operand in the add instruction.
                 * */
                reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
                memcpy(store_instruction, &reil_instruction_table[REIL_STM], sizeof(reil_instruction));

                store_instruction->address = REIL_ADDRESS(context->address);
                store_instruction->offset = context->last_offset++;
                
                store_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                store_instruction->operands[0].reg = context->next_free_register;
                store_instruction->operands[0].size = (x86instruction->mode == MODE_32)?4:2;

                store_instruction->operands[1].type = REIL_OPERAND_EMPTY;

                store_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                store_instruction->operands[2].reg = instruction->operands[0].reg - 1;
                store_instruction->operands[2].size = (x86instruction->mode == MODE_32)?4:2;
                
                operand->type = REIL_OPERAND_REGISTER;
                operand->reg = context->next_free_register++;
                operand->size = 2*MAX(instruction->operands[0].size, instruction->operands[1].size);
            }
        }
    }
}

static void emit_unknown(translation_context * context)
{
    reil_instruction * unknown_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(unknown_instruction, &reil_instruction_table[REIL_UNKN], sizeof(reil_instruction));

    unknown_instruction->address = context->address;
}

static void emit_store_reg_reg(translation_context * context, reil_register reg1, size_t reg1_size, reil_register reg2, size_t reg2_size)
{
    reil_instruction * store_instruction = &context->instruction_buffer[context->num_of_instructions++];
    memcpy(store_instruction, &reil_instruction_table[REIL_STR], sizeof(reil_instruction));

    store_instruction->address = REIL_ADDRESS(context->address);
    store_instruction->offset = context->last_offset++; 

    store_instruction->operands[0].type = REIL_OPERAND_REGISTER;
    store_instruction->operands[0].reg = reg1;
    store_instruction->operands[0].size = reg1_size;

    store_instruction->operands[2].type = REIL_OPERAND_REGISTER;
    store_instruction->operands[2].reg = reg2;
    store_instruction->operands[2].size = reg2_size;
}

int is_simple(enum Instruction x86instruction)
{
    int i;
    for ( i = 0; i < sizeof(simple_instructions)/sizeof(simple_instructions[0]); i++)
    {
        if ( simple_instructions[i] == x86instruction )
            return 1;
    }
    return 0;
}
