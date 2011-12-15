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

/* Buffer used to store intermediate result during the translation process. */
reil_instruction instruction_buffer[REIL_MAX_INSTRUCTIONS];
int translate_operand(INSTRUCTION * instruction, OPERAND * source_operand, reil_operand * operand);

reil_instructions * reil_translate(unsigned long address, INSTRUCTION * instruction)
{
    /* size holds the number of reil instructions, which is at least one. */
    size_t size = 1;
    unsigned int lowest_index = REIL_MAX_INSTRUCTIONS - 1 - 4;
    reil_instructions * translated_instructions = NULL;
    if ( instruction->type == INSTRUCTION_TYPE_ADD )
    {
        reil_instruction * translated_instruction = &instruction_buffer[lowest_index];

        translated_instruction->group = REIL_ARITHMETIC_INSTRUCTION;
        translated_instruction->index = REIL_ADD;
        translated_instruction->mnemonic = reil_mnemonics[translated_instruction->index];
        translated_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_INPUT2|REIL_OPERAND_OUTPUT;
        translated_instruction->address = REIL_ADDRESS(address);
        translated_instruction->offset = 0;
        translated_instruction->metadata = NULL;

        /* First operand of ADD can be a register or a memory location.
         * A memory location requires an extra load instruction.  */
        if ( translate_operand(instruction, &instruction->op1, &translated_instruction->operands[0]) )
        {
            if (instruction->op1.basereg != REG_NOP && instruction->op1.indexreg == REG_NOP) 
            {
                size++;
                lowest_index--;

                reil_instruction * extra_load_instruction = &instruction_buffer[lowest_index];
                extra_load_instruction->group = REIL_DATATRANSFER_INSTRUCTION;
                extra_load_instruction->index= REIL_LDM;
                extra_load_instruction->mnemonic = reil_mnemonics[extra_load_instruction->index];
                extra_load_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_OUTPUT;
                extra_load_instruction->address = REIL_ADDRESS(address);
                extra_load_instruction->offset = 0;
                extra_load_instruction->metadata = NULL;

                extra_load_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                extra_load_instruction->operands[0].reg = instruction->op1.basereg;
                extra_load_instruction->operands[0].size = (instruction->mode == MODE_32)?4:2;
        
                extra_load_instruction->operands[1].type = REIL_OPERAND_EMPTY;
                
                extra_load_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                /* TODO: Calculate next free reil register */
                extra_load_instruction->operands[2].reg = 0x100;
                extra_load_instruction->operands[2].size = extra_load_instruction->operands[0].size;

                memcpy(&translated_instruction->operands[0], &extra_load_instruction->operands[2],
                        sizeof(reil_operand));
                translated_instruction->offset += 1;
            }
            /*
            // Index register
            if (op->indexreg != REG_NOP) {
                if (op->basereg != REG_NOP)
                    snprintf(string + strlen(string), length - strlen(string),
                            "%s%s", (format == FORMAT_ATT) ? ",%" : "+", 
                            (mode == MODE_32) ?
                            reg_table[REG_GEN_DWORD][op->indexreg] :
                            reg_table[REG_GEN_WORD][op->indexreg]); 
                else
                    snprintf(string + strlen(string), length - strlen(string),
                            "%s%s", (format == FORMAT_ATT) ? "%" : "",
                            (mode == MODE_32) ?
                            reg_table[REG_GEN_DWORD][op->indexreg] :
                            reg_table[REG_GEN_WORD][op->indexreg]); 
                switch (op->scale) {
                    case 2:
                        snprintf(string + strlen(string), length - strlen(string),
                                "%s", (format == FORMAT_ATT) ?
                                ",2" : "*2"); 
                        break;
                    case 4:
                        snprintf(string + strlen(string), length - strlen(string),
                                "%s", (format == FORMAT_ATT) ?
                                ",4" : "*4"); 
                        break;
                    case 8:
                        snprintf(string + strlen(string), length - strlen(string),
                                "%s", (format == FORMAT_ATT) ?
                                ",8" : "*8"); 
                        break;
                }
            }
            */
        }
        /* The second operand of ADD can be a register, a memory location or an intermediate. */
        if ( translate_operand(instruction, &instruction->op2, &translated_instruction->operands[1]) )
        {
        }
        
        /* The third operand is equal to the first. */
        if ( translate_operand(instruction, &instruction->op1, &translated_instruction->operands[2]) )
        {
            if (instruction->op1.basereg != REG_NOP && instruction->op1.indexreg == REG_NOP) 
            {
                memcpy(&translated_instruction->operands[2], &translated_instruction->operands[0],
                        sizeof(reil_operand));
                
                size++;
                reil_instruction * extra_store_instruction = &instruction_buffer[lowest_index+2];
                extra_store_instruction->group = REIL_DATATRANSFER_INSTRUCTION;
                extra_store_instruction->index= REIL_STM;
                extra_store_instruction->mnemonic = reil_mnemonics[extra_store_instruction->index];
                extra_store_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_OUTPUT;
                extra_store_instruction->address = REIL_ADDRESS(address);
                extra_store_instruction->offset = translated_instruction->offset + 1;
                extra_store_instruction->metadata = NULL;

                extra_store_instruction->operands[0].type = REIL_OPERAND_REGISTER;
                extra_store_instruction->operands[0].reg = instruction->op1.basereg;
                extra_store_instruction->operands[0].size = (instruction->mode == MODE_32)?4:2;
        
                extra_store_instruction->operands[1].type = REIL_OPERAND_EMPTY;
                
                extra_store_instruction->operands[2].type = REIL_OPERAND_REGISTER;
                memcpy(&extra_store_instruction->operands[2], &translated_instruction->operands[2],
                        sizeof(reil_operand));
            }
        }
        
        translated_instructions = malloc(sizeof(reil_instructions) + size * sizeof(reil_instruction));
        if (!translated_instructions)
        {
            fprintf(stderr, "Failed to allocate memory for translated instructions!");
            exit(EXIT_FAILURE);
        }
        translated_instructions->size = size;

        memcpy(translated_instructions->instruction, &instruction_buffer[lowest_index], size*sizeof(reil_instruction));

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

int translate_operand(INSTRUCTION * instruction, OPERAND * source_operand, reil_operand * operand)
{
    if ( source_operand->type == OPERAND_TYPE_REGISTER )
    {
        operand->type = REIL_OPERAND_REGISTER;
        operand->reg = source_operand->reg;
    }
    else if ( source_operand->type == OPERAND_TYPE_IMMEDIATE )
    {
        operand->type = REIL_OPERAND_INTEGER;
        operand->reg = source_operand->immediate;
    }
    else
    {
        /* Requires additional reil instructions */
        return 1;
    }
    
    switch (MASK_OT(source_operand->flags)) {
        case OT_b:
            operand->size = 1;
            break;
        case OT_v:
            {
                enum Mode mode = MODE_CHECK_OPERAND(instruction->mode, instruction->flags);
                operand->size = (mode == MODE_32)?4:2;
            }
            break;
        case OT_w:
            operand->size = 2;
            break;
        case OT_d:
            operand->size = 4;
            break;
    }
    /* Successfully translated operand */
    return 0;
}
