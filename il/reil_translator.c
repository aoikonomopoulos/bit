#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "libdasm.h"
#include "reil.h"
#include "reil_x86_translator.h"

void usage(const char * progname);
unsigned char * read_file(size_t *len, char *name);
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
    do 
    {
        len = get_instruction(&x86_instruction, buf+c, MODE_32);
        if ( len != 0 )
        {
            size_t i;
            reil_instructions * instructions = reil_translate(c, &x86_instruction);
            reil_instruction * instruction = &instructions->instruction[i];
            
            char instruction_string[256];
            reil_get_string(instruction, instruction_string, sizeof(instruction_string));

            char x86_instruction_string[256];
            get_instruction_string(&x86_instruction, FORMAT_INTEL, c, x86_instruction_string,
                    sizeof(x86_instruction_string));
            printf("%#8x %s // %s\n", instruction->address + instruction->offset,
                instruction_string, x86_instruction_string);

            free(instructions);
        }
        else
        {
            printf("%#8x Invalid x86 instruction", c);
            len = 1;
        }
        c += len;
    } while ( c < buflen );

    return 0;
}

void usage(const char * progname)
{
    printf("Usage: %s FILE\n", progname);
}

unsigned char * read_file(size_t *len, char *name)
{
        unsigned char            *buf;
        FILE            *fp;
        int             c;
        struct stat     sstat;

        if ((fp = fopen(name, "r+b")) == NULL) {
                fprintf(stderr,"Error: unable to open file \"%s\"\n", name);
                exit(0);
        }

        /* Get file len */
        if ((c = stat(name, &sstat)) == -1) {
                fprintf(stderr,"Error: stat\n");
                exit (1);
        }
        *len = sstat.st_size;

        /* Allocate space for file */
        if (!(buf = (unsigned char *)malloc(*len))) {
                fprintf(stderr,"Error: malloc\n");
                exit (1);
        }

        /* Read file in allocated space */
        if ((c = fread(buf, 1, *len, fp)) != *len) {
                fprintf(stderr,"Error: fread\n");
                exit (1);
        }

        fclose(fp);

        return (buf);
}
