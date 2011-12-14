#ifndef REIL_H
#define REIL_H

#define REIL_NUMBER_OF_INSTRUCTION_OPERANDS 3

typedef enum _reil_instruction_group
{
    REIL_ARITHMETIC_INSTRUCTION,
    REIL_BITWISE_INSTRUCTION,
    REIL_DATATRANSFER_INSTRUCTION,
    REIL_CONDITIONAL_INSTRUCTION,
    REIL_OTHER_INSTRUCTION
} reil_instruction_group;

typedef enum _reil_instruction_index
{
    /* Arithmetic instructions */
    REIL_ADD,
    REIL_SUB,
    REIL_MUL,
    REIL_DIV,
    REIL_MOD,
    REIL_BSH,
    /* Bitwise instructions */
    REIL_AND,
    REIL_OR,
    REIL_XOR,
    /* Data transfer instructions */
    REIL_LDM,
    REIL_STM,
    REIL_STR,
    /* Conditional instructions */
    REIL_BISZ,
    REIL_JCC,
    /* Other instructions */
    REIL_UNDEF,
    REIL_UNKN,
    REIL_NOP
} reil_instruction_index;

typedef int reil_integer;
typedef int reil_register;
typedef int reil_subaddress;

typedef enum _reil_operand_type
{
    REIL_OPERAND_EMPTY,
    REIL_OPERAND_INTEGER,
    REIL_OPERAND_REGISTER,
    REIL_OPERAND_SUBADDRESS,
} reil_operand_type;

#define REIL_OPERAND_NONE   0x0
#define REIL_OPERAND_INPUT1 0x1
#define REIL_OPERAND_INPUT2 0x2
#define REIL_OPERAND_OUTPUT 0x4

typedef struct _reil_operand
{
    reil_operand_type type;
    union
    {
        reil_integer integer;
        reil_register reg;
        reil_subaddress subaddress;

    };
    /* Size in bytes (e.g. 1, 2, and 4 bytes ); */
    unsigned char size;
} reil_operand;

typedef struct _reil_keyvalue
{
    const char * key;
    void * value;
} reil_keyvalue;

typedef struct _reil_instruction_metadata
{
    unsigned int size;
    /* 
     * Using struct hack to defer array size calculation to runtime.
     * NOTE: This struct must be allocated on the heap!!!  */ 
    reil_keyvalue properties[];
} reil_instruction_metadata;

typedef struct _reil_instruction
{
    reil_instruction_group group;
    reil_instruction_index index;
    const char * mnemonic;
    /* Address of corresponding arch depended instruction */
    unsigned int address;
    /* Offset from address, since an arch depended instruction can expand
     * to multiple reil instructions.
     * */
    unsigned char offset;
    unsigned char operand_flags;
    reil_operand operands[REIL_NUMBER_OF_INSTRUCTION_OPERANDS];
    reil_instruction_metadata * metadata;

} reil_instruction;


extern const char * reil_mnemonics[];

void reil_get_string(reil_instruction * instruction, char * string, size_t size);

#endif
