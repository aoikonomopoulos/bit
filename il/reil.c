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
#include <stdlib.h>
#include <string.h>
#include "reil.h"

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
    
    for (i = 0; i < REIL_MAX_OPERANDS; i++)
    {
        reil_operand * operand = &instruction->operands[i];
        if (operand->type == REIL_OPERAND_TYPE_EMPTY) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left," ");
        }
        else if (operand->type == REIL_OPERAND_TYPE_INTEGER) 
        {
                bytes_written = snprintf(string+total_bytes_written, bytes_left, " 0x%x", operand->integer);
        }
        else if (operand->type == REIL_OPERAND_TYPE_REGISTER) 
        {
            const char * size_prefix = NULL;
            if ( operand->size == 1 )
            {
                size_prefix = "byte";
            }
            else if ( operand->size == 2 )
            {
                size_prefix = "word";
            }
            else if ( operand->size == 4 )
            {
                size_prefix = "dword";
            }
            else if ( operand->size == 8 )
            {
                size_prefix = "qword";
            }
            else
            {
                size_prefix = "???";
            }
            bytes_written = snprintf(string+total_bytes_written, bytes_left, " %s T%u", size_prefix, operand->reg);
        }
        else if (operand->type == REIL_OPERAND_TYPE_SUBADDRESS) 
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left, " loc_%xh", operand->subaddress);
        }

        if ( bytes_written >= bytes_left )
            return;

        bytes_left -= bytes_written;
        total_bytes_written += bytes_written;

        if ( i != REIL_MAX_OPERANDS - 1)
        {
            bytes_written = snprintf(string+total_bytes_written, bytes_left, ",");
            if ( bytes_written >= bytes_left )
                return;

            bytes_left -= bytes_written;
            total_bytes_written += bytes_written;
        }
    }
}
