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

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "x86/reil_x86.h"
#include "reil.h"

void usage(const char * progname);
void * read_file(size_t *len, char *name);
int main(int argc, char** argv)
{
    if (argc != 2)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    INSTRUCTION x86_instruction;
    size_t len, buflen, c = 0;
    BYTE * buf = read_file(&buflen, argv[1]);
    unsigned int base = 0, offset = 0;
    do 
    {
        len = get_instruction(&x86_instruction, buf+c, MODE_32);
        if ( len != 0 )
        {
            size_t i;
            char x86_instruction_string[256];
            get_instruction_string(&x86_instruction, FORMAT_INTEL, c, x86_instruction_string,
                    sizeof(x86_instruction_string));

            reil_instructions * instructions = reil_translate_from_x86(base, offset++, &x86_instruction);
            for ( i = 0; i < instructions->size; i++)
            {
                reil_instruction * instruction = &instructions->instruction[i];

                char instruction_string[256];
                reil_get_string(instruction, reil_register_x86_formatter, instruction_string, sizeof(instruction_string));
                if ( i == 0 )
                {
                    printf("0x%08x %-40s // %s\n", instruction->address + instruction->offset,
                            instruction_string, x86_instruction_string);
                }
                else
                {
                    printf("0x%08x %-40s\n", instruction->address + instruction->offset,
                            instruction_string);
                }
            }

            for ( i = 0; i < 79; i++)
                printf("=");
            printf("\n");

            free(instructions);
        }
        else
        {
            printf("%#8zx Invalid x86 instruction", c);
            len = 1;
        }
        c += len;
    } while ( c < buflen );

    return 0;
}

void usage(const char * progname)
{
    printf("Usage: %s [--arch] FILE\n"
           "    --arch      - Architecture of FILE, default is x86\n",
           progname);
}

void * read_file(size_t *len, char *name)
{
        unsigned char *buf;
	int fd;
        struct stat sstat;

        if ((fd = open(name, O_RDONLY)) < 0) {
                fprintf(stderr,"Error: unable to open file \"%s\"\n", name);
                exit(1);
        }

        /* Get file len */
        if (fstat(fd, &sstat) < 0) {
                fprintf(stderr,"Error: can't stat \"%s\"\n", name);
                exit (1);
        }
        *len = sstat.st_size;

	if (!(buf = mmap(NULL, *len, PROT_READ, MAP_PRIVATE, fd, 0))) {
                fprintf(stderr,"Error: unable to mmap file \"%s\"\n", name);
                exit(1);
        }

        return buf;
}
