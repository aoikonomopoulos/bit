#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libdasm.h"
#include "reil.h"
#include "reil_x86_translator.h"

void translate_operand(OPERAND * source_operand, reil_operand * operand);

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
        translated_instruction->address = address;
        translated_instruction->offset = 0;
        translated_instruction->metadata = NULL;

        translate_operand(&instruction->op1, &translated_instruction->operands[0]);
        translate_operand(&instruction->op2, &translated_instruction->operands[1]);
        translate_operand(&instruction->op1, &translated_instruction->operands[2]);

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

void translate_operand(OPERAND * source_operand, reil_operand * operand)
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
        operand->type = REIL_OPERAND_EMPTY;
    }
}
