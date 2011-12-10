#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "libdasm.h"

void usage(const char * progname);
unsigned char * read_file(int *len, char *name);
int main(int argc, char** argv)
{
    if (argc != 2)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    INSTRUCTION inst;
    int len, buflen, c = 0;
    BYTE * buf = read_file(&buflen, argv[1]);
    char inst_str[256];
    do 
    {
        len = get_instruction(&inst, buf+c, MODE_32);
        if ( len != 0 )
        {
            get_instruction_string(&inst, FORMAT_INTEL, c, inst_str, sizeof(inst_str));
            if ( inst.type == INSTRUCTION_TYPE_ADD )
            {
                if ( inst.op1.type == OPERAND_TYPE_REGISTER )
                {
                    if ( inst.op2.type == OPERAND_TYPE_REGISTER )
                    {
                        printf("%#8x ADD T%i,T%i,T%i // %s\n",
                                c * 256, inst.op1.reg, inst.op2.reg,
                                inst.op1.reg, inst_str);
                    }
                    else if ( inst.op2.type == OPERAND_TYPE_IMMEDIATE )
                    {
                        printf("%#8x ADD T%i,%#x,T%i // %s\n",
                                c * 256, inst.op1.reg, inst.op2.immediate,
                                inst.op1.reg, inst_str);
                    }
                    else
                    {
                        printf("%#8x UNKN\n", c * 256);
                    }
                }
                else
                {
                    printf("%#8x UNKN // %s\n", c * 256, inst_str);
                }
            }
            else
            {
                printf("%#8x UNKN // %s\n", c * 256, inst_str);
            }
        }
        else
        {
            printf("%#8x UNKN\n", c * 256);
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

unsigned char * read_file(int *len, char *name)
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
