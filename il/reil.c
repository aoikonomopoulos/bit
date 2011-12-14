#include <stdio.h>
#include <stdlib.h>
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

    /* See if instruction has operands */
    if ( !instruction->operand_flags )
        return;
    
    for (i = 0; i < REIL_NUMBER_OF_INSTRUCTION_OPERANDS; i++)
    {
        reil_operand * operand = &instruction->operands[i];
        if (operand->type == REIL_OPERAND_EMPTY) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left," ");
        }
        else if (operand->type == REIL_OPERAND_INTEGER) 
        {
            if ( operand->size == 1)
                bytes_written = snprintf(string+total_bytes_written, bytes_left, " 0x%02x/%u", operand->integer, operand->size);
            else if ( operand->size == 2)
                bytes_written = snprintf(string+total_bytes_written, bytes_left, " 0x%04x/%u", operand->integer, operand->size);
            else if ( operand->size == 4)
                bytes_written = snprintf(string+total_bytes_written, bytes_left, " 0x%08x/%u", operand->integer, operand->size);
            else if ( operand->size == 8)
                bytes_written = snprintf(string+total_bytes_written, bytes_left, " 0x%016x/%u", operand->integer, operand->size);
            else
            {
                fprintf(stderr, "Invalid operand size!\n");
                exit(EXIT_FAILURE);
            }
        }
        else if (operand->type == REIL_OPERAND_REGISTER) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left, " T%u/%u", operand->reg, operand->size);
        }
        else if (operand->type == REIL_OPERAND_SUBADDRESS) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left, " loc_%xh", operand->subaddress);
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
