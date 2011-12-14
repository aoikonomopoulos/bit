#ifndef REIL_X86_TRANSLATOR
#define REIL_X86_TRANSLATOR

typedef struct _reil_instructions
{
    unsigned int size;
    /* 
     * Using struct hack to defer array size calculation to runtime.
     * NOTE: This struct must be allocated on the heap!!!  */ 
    reil_instruction instruction[];
} reil_instructions;

reil_instructions * reil_translate(unsigned long address, INSTRUCTION * instruction);

#endif
