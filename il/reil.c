#include <stdio.h>
#include <string.h>
#include "reil.h"

/* Index with reil instruction index */
const char * reil_mnemonics[] =
{
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "MOD",
    "BSH",
    "AND",
    "OR",
    "XOR",
    "LDM",
    "STM",
    "STR",
    "BISZ",
    "JCC",
    "UNDEF",
    "UNKN",
    "NOP"
};

void reil_get_string(reil_instruction * instruction, char * string, size_t size)
{
    size_t i, bytes_left = size;
    int bytes_written, total_bytes_written = 0;

    bytes_written = snprintf(string, bytes_left, "%s", instruction->mnemonic);

    if ( bytes_written >= bytes_left )
        return;

    bytes_left -= bytes_written;
    total_bytes_written += bytes_written;
    
    for (i = 0; i < REIL_NUMBER_OF_INSTRUCTION_OPERANDS; i++)
    {
        reil_operand * operand = &instruction->operands[i];
        if (operand->type == REIL_OPERAND_EMPTY) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left," ");
        }
        else if (operand->type == REIL_OPERAND_INTEGER) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left, " 0x%x", operand->reg);
        }
        else if (operand->type == REIL_OPERAND_REGISTER) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left, " T%u", operand->reg);
        }
        else if (operand->type == REIL_OPERAND_SUBADDRESS) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left, " loc_%xh", operand->reg);
        }

        if ( bytes_written >= bytes_left )
            return;

        bytes_left -= bytes_written;
        total_bytes_written += bytes_written;

        if ( i != REIL_NUMBER_OF_INSTRUCTION_OPERANDS - 1)
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left, ",");
            if ( bytes_written >= bytes_left )
                return;

            bytes_left -= bytes_written;
            total_bytes_written += bytes_written;
        }
    }
}
