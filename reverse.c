#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

typedef struct {
    size_t file_size;
    uint8_t * values;
} file_t;



typedef struct {
    size_t pc;
    uint8_t opcode;
} cpu_instruction;



enum ins_type {
    NOP,
    RET,
    RET_IMM16,
    INT3,
    INTO,
    IRET,
    HLT,
    CMC,
    CLC,
    STC,
    CLD,
    STD,
    CLI,
    STI,
    INVALID
};


enum operand_type{
    IMM16,
    IMM8
};

typedef struct {
    enum ins_type type;
    const char *mnemonic;
} instruction;



instruction opcode_table[256] = {
    [0x90] = {NOP,  "NOP"},
    [0xC3] = {RET,  "RET"},
    [0xC2] = {RET_IMM16, "RET imm16"},
    [0xCC] = {INT3, "INT3"},
    [0xCE] = {INTO, "INTO"},
    [0xCF] = {IRET, "IRET"},
    [0xF4] = {HLT,  "HLT"},
    [0xF5] = {CMC,  "CMC"},

    [0xF8] = {CLC, "CLC"},
    [0xF9] = {STC, "STC"},
    [0xFC] = {CLD, "CLD"},
    [0xFD] = {STD, "STD"},
    [0xFA] = {CLI, "CLI"},
    [0xFB] = {STI, "STI"},
};

void get_opcode(cpu_instruction *cpu, file_t *file) {
    uint8_t op = file->values[cpu->pc];
    instruction ins = opcode_table[op];

    if (ins.mnemonic == NULL) {
        printf("%04zx: %02x   UNKNOWN\n", cpu->pc, op);
        return;
    }

    printf("%04zx: %02x   %s\n", cpu->pc, op, ins.mnemonic);
}





file_t * assign_values(FILE * fileptr){

    file_t * file_info = malloc(sizeof(file_t));
    if (file_info == NULL){
        perror("File structure is not allocated");
        exit(EXIT_FAILURE);
    }

    fseek(fileptr,0L,SEEK_END);
    size_t size = ftell(fileptr);
    rewind(fileptr);

    file_info->file_size = size;

    uint8_t * buffer = (uint8_t * ) malloc(size);
    if(buffer == NULL){
        perror("Buffer is Not Allocated enough memory");
        exit(EXIT_FAILURE);
    }

    file_info->values = buffer;
    int count = fread(buffer,1,size,fileptr);
    if(count != size)
    {
        printf("fread did not read all values");
        exit(EXIT_FAILURE);
    }

    return file_info;
}

void get_opcode(cpu_instruction cpu){
}



int main(int argc, char ** argv){
    if (argc < 2){
        printf("Program Excecution \n reverse [program] ");
        exit(EXIT_FAILURE);
    }

    // check for file
    FILE * fileptr = fopen(argv[1],"rb");
    if (fileptr == NULL){
        perror("An error occurred");
        exit(EXIT_FAILURE);
    }

    file_t * file = assign_values(fileptr);
    fclose(fileptr);

    cpu_instruction cpu;  
    
    cpu_instruction cpu = {0};

    while (cpu.pc < file->file_size) {
        get_opcode(&cpu, file);
        cpu.pc += 1;
    }


    exit(EXIT_SUCCESS);
}