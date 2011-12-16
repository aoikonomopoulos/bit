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

/* Buffer used to store intermediate result during the translation process. */
reil_instruction instruction_buffer[REIL_MAX_INSTRUCTIONS];
reil_instruction * instruction_sort_buffer[REIL_MAX_INSTRUCTIONS];
int translate_input_operand(INSTRUCTION * instruction, OPERAND * source_operand, reil_operand * operand);
int translate_output_operand(OPERAND * source_operand, reil_register * next_free_register, size_t size, reil_operand * operand);
size_t get_operand_size(INSTRUCTION * instruction, OPERAND * operand);

reil_instructions * reil_translate(unsigned long address, INSTRUCTION * instruction)
{
    /* size holds the number of reil instructions, which is at least one. */
    size_t size = 0;
    size_t max_offset = 0;
    reil_register next_free_register = 256;
    reil_instructions * translated_instructions = NULL;
    if ( instruction->type == INSTRUCTION_TYPE_ADD )
    {
        reil_instruction * translated_instruction = &instruction_buffer[size++];

        /* First operand of ADD can be a register or a memory location.
         * A memory location requires an extra load instruction.  */
        if ( instruction->op1.type == OPERAND_TYPE_REGISTER )
        {
            translated_instruction->operands[0].type = REIL_OPERAND_REGISTER;
            translated_instruction->operands[0].reg = instruction->op1.basereg;
            translated_instruction->operands[0].size = get_operand_size(instruction, &instruction->op1);
        }
        else if ( instruction->op1.type == OPERAND_TYPE_IMMEDIATE )
        {
            translated_instruction->operands[0].type = REIL_OPERAND_INTEGER;
            translated_instruction->operands[0].integer = instruction->op1.immediate;
            translated_instruction->operands[0].size = get_operand_size(instruction, &instruction->op1);
        }
        else /* OPERAND_TYPE_MEMORY */
        {
            /* Base register */
            if (instruction->op1.basereg != REG_NOP && instruction->op1.indexreg == REG_NOP) 
            {
                reil_instruction * load_instruction = &instruction_buffer[size++];

                load_instruction->group = REIL_DATATRANSFER_INSTRUCTION;
                load_instruction->index= REIL_LDM;
                load_instruction->mnemonic = reil_mnemonics[load_instruction->index];
                load_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_OUTPUT;
                load_instruction->address = REIL_ADDRESS(address);
                load_instruction->offset = max_offset++;
                load_instruction->metadata = NULL;

                load_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                load_instruction->operands[0].reg = instruction->op1.basereg;
                load_instruction->operands[0].size = (instruction->mode == MODE_32)?4:2;

                load_instruction->operands[1].type = REIL_OPERAND_EMPTY;

                load_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                /* TODO: Calculate next free reil register */
                load_instruction->operands[2].reg = next_free_register++;
                load_instruction->operands[2].size = load_instruction->operands[0].size;

                memcpy(&translated_instruction->operands[0], &load_instruction->operands[2],
                        sizeof(reil_operand));
            }
            /* Index register */
            if (instruction->op1.indexreg != REG_NOP) 
            {
                if (instruction->op1.scale)
                {
                    reil_instruction * multiply_instruction = &instruction_buffer[size++];
                    multiply_instruction->group = REIL_ARITHMETIC_INSTRUCTION;
                    multiply_instruction->index = REIL_MUL;
                    multiply_instruction->mnemonic = reil_mnemonics[multiply_instruction->index];
                    multiply_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_INPUT2|REIL_OPERAND_OUTPUT;
                    multiply_instruction->address = REIL_ADDRESS(address);
                    multiply_instruction->offset = max_offset++;
                    multiply_instruction->metadata = NULL;

                    multiply_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                    multiply_instruction->operands[0].reg = instruction->op1.indexreg;
                    multiply_instruction->operands[0].size = (instruction->mode == MODE_32)?4:2;

                    multiply_instruction->operands[1].type = REIL_OPERAND_INTEGER;
                    multiply_instruction->operands[1].integer = instruction->op1.scale;
                    multiply_instruction->operands[1].size = 4;

                    multiply_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                    multiply_instruction->operands[2].reg = next_free_register++;
                    multiply_instruction->operands[2].size = 2 * MAX(multiply_instruction->operands[0].size,
                            multiply_instruction->operands[1].size);

                }

                if (instruction->op1.basereg != REG_NOP)
                {
                    reil_instruction * add_instruction = &instruction_buffer[size++];
                    add_instruction->group = REIL_ARITHMETIC_INSTRUCTION;
                    add_instruction->index = REIL_ADD;
                    add_instruction->mnemonic = reil_mnemonics[add_instruction->index];
                    add_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_INPUT2|REIL_OPERAND_OUTPUT;
                    add_instruction->address = REIL_ADDRESS(address);
                    add_instruction->offset = max_offset++;
                    add_instruction->metadata = NULL;

                    add_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[0].reg = instruction->op1.basereg;
                    add_instruction->operands[0].size = (instruction->mode == MODE_32)?4:2;

                    add_instruction->operands[1].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[1].reg = next_free_register - 1;
                    /* TODO: This should be the actual register size, current equal to the size of the first operand. */
                    add_instruction->operands[1].size = add_instruction->operands[0].size;

                    add_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                    add_instruction->operands[2].reg = next_free_register++;
                    add_instruction->operands[2].size = 2 * MAX(add_instruction->operands[0].size,
                            add_instruction->operands[1].size);

                }
                
                reil_instruction * load_instruction = &instruction_buffer[size++];

                load_instruction->group = REIL_DATATRANSFER_INSTRUCTION;
                load_instruction->index= REIL_LDM;
                load_instruction->mnemonic = reil_mnemonics[load_instruction->index];
                load_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_OUTPUT;
                load_instruction->address = REIL_ADDRESS(address);
                load_instruction->offset = max_offset++;
                load_instruction->metadata = NULL;

                load_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                load_instruction->operands[0].reg = next_free_register - 1;
                /* TODO: Use real size of last free register. */
                load_instruction->operands[0].size = (instruction->mode == MODE_32)?4:2;

                load_instruction->operands[1].type = REIL_OPERAND_EMPTY;

                load_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                /* TODO: Calculate next free reil register */
                load_instruction->operands[2].reg = next_free_register++;
                load_instruction->operands[2].size = load_instruction->operands[0].size;
            }

            translated_instruction->operands[0].type = REIL_OPERAND_REGISTER;
            translated_instruction->operands[0].reg = next_free_register - 1;
            /* TODO: Get real size of last free register. */
            translated_instruction->operands[0].size = 4;
        }
        
        /* The second operand of ADD can be a register, a memory location or an intermediate. */
        if ( instruction->op2.type == OPERAND_TYPE_REGISTER )
        {
            translated_instruction->operands[1].type = REIL_OPERAND_REGISTER;
            translated_instruction->operands[1].reg = instruction->op2.basereg;
            translated_instruction->operands[1].size = get_operand_size(instruction, &instruction->op2);
        }
        else if ( instruction->op2.type == OPERAND_TYPE_IMMEDIATE )
        {
            translated_instruction->operands[1].type = REIL_OPERAND_INTEGER;
            translated_instruction->operands[1].integer = instruction->op2.immediate;
            translated_instruction->operands[1].size = get_operand_size(instruction, &instruction->op2);
        }
        else /* OPERAND_TYPE_MEMORY */
        {
            translated_instruction->operands[1].type = REIL_OPERAND_EMPTY;
        }
        
        translated_instruction->group = REIL_ARITHMETIC_INSTRUCTION;
        translated_instruction->index = REIL_ADD;
        translated_instruction->mnemonic = reil_mnemonics[translated_instruction->index];
        translated_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_INPUT2|REIL_OPERAND_OUTPUT;
        translated_instruction->address = REIL_ADDRESS(address);
        translated_instruction->offset = max_offset++;
        translated_instruction->metadata = NULL;

        /* The third operand is equal to the first. */
        if ( instruction->op1.type == OPERAND_TYPE_REGISTER )
        {
            translated_instruction->operands[2].type = REIL_OPERAND_REGISTER;
            translated_instruction->operands[2].reg = next_free_register++;
            translated_instruction->operands[2].size = 2*get_operand_size(instruction, &instruction->op1);
                
            reil_instruction * store_instruction = &instruction_buffer[size++];
            store_instruction->group = REIL_DATATRANSFER_INSTRUCTION;
            store_instruction->index= REIL_STR;
            store_instruction->mnemonic = reil_mnemonics[store_instruction->index];
            store_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_OUTPUT;
            store_instruction->address = REIL_ADDRESS(address);
            store_instruction->offset = ++max_offset;
            store_instruction->metadata = NULL;

            store_instruction->operands[0].type = REIL_OPERAND_REGISTER;
            store_instruction->operands[0].reg = next_free_register - 1;
            /* TODO: Get real size of last free register. */
            store_instruction->operands[0].size = translated_instruction->operands[0].size;

            store_instruction->operands[1].type = REIL_OPERAND_EMPTY;

            store_instruction->operands[2].type = REIL_OPERAND_REGISTER;
            store_instruction->operands[2].reg = instruction->op1.basereg;
            store_instruction->operands[2].size = (instruction->mode == MODE_32)?4:2;
        }
        else if ( instruction->op1.type == OPERAND_TYPE_MEMORY )
        {
            translated_instruction->operands[2].type = REIL_OPERAND_REGISTER;
            translated_instruction->operands[2].reg = next_free_register++;
            translated_instruction->operands[2].size = 2*get_operand_size(instruction, &instruction->op1);
            if (instruction->op1.basereg != REG_NOP && instruction->op1.indexreg == REG_NOP) 
            {
                reil_instruction * store_instruction = &instruction_buffer[size++];
                store_instruction->group = REIL_DATATRANSFER_INSTRUCTION;
                store_instruction->index= REIL_STM;
                store_instruction->mnemonic = reil_mnemonics[store_instruction->index];
                store_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_OUTPUT;
                store_instruction->address = REIL_ADDRESS(address);
                store_instruction->offset = ++max_offset;
                store_instruction->metadata = NULL;
                
                store_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                store_instruction->operands[0].reg = next_free_register - 1;
                /* TODO: Get real size of last free register. */
                store_instruction->operands[0].size = (translated_instruction->operands[2].size > 4)?4:translated_instruction->operands[2].size;
                
                store_instruction->operands[1].type = REIL_OPERAND_EMPTY;

                store_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                store_instruction->operands[2].reg = instruction->op1.basereg;
                store_instruction->operands[2].size = (instruction->mode == MODE_32)?4:2;
            }
        }
        
        translated_instructions = malloc(sizeof(reil_instructions) + size * sizeof(reil_instruction));
        if (!translated_instructions)
        {
            fprintf(stderr, "Failed to allocate memory for translated instructions!");
            exit(EXIT_FAILURE);
        }
        translated_instructions->size = size;

        size_t i, j;
        for ( i = 0; i < size; i++)
        {
            instruction_sort_buffer[i] = &instruction_buffer[i];
        }
        
        for ( i = 0; i < size; i++)
        {
            for ( j = i+1; j < size; j++ )
            {
                if ( instruction_sort_buffer[i]->offset > instruction_sort_buffer[j]->offset)
                {
                    reil_instruction * tmp = instruction_sort_buffer[i];
                    instruction_sort_buffer[i] = instruction_sort_buffer[j];
                    instruction_sort_buffer[j] = tmp;
                }
            }
        }
        
        for ( i = 0; i < size; i++)
        {
            memcpy(&translated_instructions->instruction[i], instruction_sort_buffer[i], sizeof(reil_instruction));
        }

    }
    else
    {
        translated_instructions = malloc(sizeof(reil_instructions) + sizeof(reil_instruction));
        if (!translated_instructions)
        {
            fprintf(stderr, "Failed to allocate memory for translated instructions!");
            exit(EXIT_FAILURE);
        }
        reil_instruction * translated_instruction = &translated_instructions->instruction[0];
        translated_instruction->group = REIL_OTHER_INSTRUCTION;
        translated_instruction->index = REIL_UNKN;
        translated_instruction->mnemonic = reil_mnemonics[translated_instruction->index];
        translated_instruction->address = address;
        translated_instruction->offset = 0;
        translated_instruction->metadata = NULL;
    }

    return translated_instructions;
}

int translate_input_operand(INSTRUCTION * instruction, OPERAND * source_operand, reil_operand * operand)
{
    if ( source_operand->type == OPERAND_TYPE_REGISTER )
    {
        operand->type = REIL_OPERAND_REGISTER;
        operand->reg = source_operand->reg;
    }
    else if ( source_operand->type == OPERAND_TYPE_IMMEDIATE )
    {
        operand->type = REIL_OPERAND_INTEGER;
        operand->integer = source_operand->immediate;
    }
    else
    {
        /* Requires additional reil instructions */
        return 1;
    }
    
    /* Successfully translated operand */
    return 0;
}

size_t get_operand_size(INSTRUCTION * instruction, OPERAND * operand)
{
    size_t size = 0;
    switch (MASK_OT(operand->flags)) {
        case OT_b:
            size = 1;
            break;
        case OT_v:
            {
                enum Mode mode = MODE_CHECK_OPERAND(instruction->mode, instruction->flags);
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

int translate_output_operand(OPERAND * source_operand, reil_register * next_free_register, size_t size, reil_operand * operand)
{
    operand->type = REIL_OPERAND_REGISTER;
    operand->reg = (*next_free_register)++;
    operand->size = size;

    /* Need additional instructions to store result in memory */
    return source_operand->type == OPERAND_TYPE_MEMORY;
}
