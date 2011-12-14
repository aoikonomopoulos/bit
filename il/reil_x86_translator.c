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

int translate_operand(INSTRUCTION * instruction, OPERAND * source_operand, reil_operand * operand);

reil_instructions * reil_translate(unsigned long address, INSTRUCTION * instruction)
{
    reil_instructions * translated_instructions = NULL;
    if ( instruction->type == INSTRUCTION_TYPE_ADD )
    {
        translated_instructions = malloc(sizeof(reil_instructions) + sizeof(reil_instruction));
        if (!translated_instructions)
        {
            fprintf(stderr, "Failed to allocate memory for translated instructions!");
            exit(EXIT_FAILURE);
        }
        translated_instructions->size = 1;

        reil_instruction * translated_instruction = &translated_instructions->instruction[0];

        translated_instruction->group = REIL_ARITHMETIC_INSTRUCTION;
        translated_instruction->index = REIL_ADD;
        translated_instruction->mnemonic = reil_mnemonics[translated_instruction->index];
        translated_instruction->operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_INPUT2|REIL_OPERAND_OUTPUT;
        translated_instruction->address = address << 8;
        translated_instruction->offset = 0;
        translated_instruction->metadata = NULL;

        if ( translate_operand(instruction, &instruction->op1, &translated_instruction->operands[0]) )
        {
            if (instruction->op1.basereg != REG_NOP && instruction->op1.indexreg == REG_NOP) 
            {
                reil_instruction extra_load_instruction;
                extra_load_instruction.group = REIL_DATATRANSFER_INSTRUCTION;
                extra_load_instruction.index= REIL_LDM;
                extra_load_instruction.mnemonic = reil_mnemonics[extra_load_instruction.index];
                extra_load_instruction.operand_flags = REIL_OPERAND_INPUT1|REIL_OPERAND_OUTPUT;
                extra_load_instruction.address = address << 8;
                extra_load_instruction.offset = 0;
                extra_load_instruction.metadata = NULL;

                extra_load_instruction.operands[0].type = REIL_OPERAND_REGISTER;
                extra_load_instruction.operands[0].reg = instruction->op1.basereg;
                extra_load_instruction.operands[0].size = (instruction->mode == MODE_32)?4:2;
        
                extra_load_instruction.operands[1].type = REIL_OPERAND_EMPTY;
                
                extra_load_instruction.operands[2].type = REIL_OPERAND_REGISTER;
                /* TODO: Calculate next free reil register */
                extra_load_instruction.operands[2].reg = 0x100;
                extra_load_instruction.operands[2].size = extra_load_instruction.operands[0].size;
                reil_instructions * previos_translated_instructions = translated_instructions;
                translated_instructions = malloc(sizeof(reil_instructions) + 2 * sizeof(reil_instruction));
                if (!translated_instructions)
                {
                    fprintf(stderr, "Failed to allocate memory for translated instructions!");
                    exit(EXIT_FAILURE);
                }
                translated_instructions->size = 2;

                memcpy(&translated_instructions->instruction[0], &extra_load_instruction, sizeof(reil_instruction));
                memcpy(&translated_instructions->instruction[1], &previos_translated_instructions->instruction[0], sizeof(reil_instruction));

                translated_instructions->instruction[1].offset += 1;

                free(previos_translated_instructions);
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
        if ( translate_operand(instruction, &instruction->op2, &translated_instruction->operands[1]) )
        {
        }
        if ( translate_operand(instruction, &instruction->op1, &translated_instruction->operands[2]) )
        {
        }
        
        if ( translated_instruction->operands[0].type == REIL_OPERAND_EMPTY 
          || translated_instruction->operands[1].type == REIL_OPERAND_EMPTY
          || translated_instruction->operands[2].type == REIL_OPERAND_EMPTY )
        {
            translated_instruction->group = REIL_OTHER_INSTRUCTION;
            translated_instruction->index = REIL_UNKN;
            translated_instruction->mnemonic = reil_mnemonics[translated_instruction->index];
            translated_instruction->operand_flags = REIL_OPERAND_NONE;
        }

    }
    else
    {
        translated_instructions = malloc(sizeof(reil_instructions) + sizeof(reil_instruction));
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
