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
    CBW,
    CWD,
    SAHF,
    LAHF,
    HLT,
    CMC,
    CLC,
    STC,
    CLI,
    STI,
    CLD,
    STD,
    INT3,
    INTO,
    IRET,
    RET,
    RET_IMM16,
    RETF,
    DAA,
    DAS,
    AAA,
    AAS,
    INVALID
};


enum operand_type{
    IMM16,
    IMM8
};

typedef struct {
    enum ins_type type;
    const char *mnemonic;
    int pc_increment;
} instruction;


instruction opcode_table[256] = {
    [0 ... 255] = {INVALID, NULL, 1}, 

    [0x27] = {DAA,"DAA",1},
    [0x2F] = {DAS,"DAS",1},
    [0x37] = {AAA,"AAA",1},
    [0x3F] = {AAS,"AAS",1},

    [0x90] = {NOP,  "NOP", 1},
    [0x98] = {CBW,"CBW",1},
    [0x99] = {CWD,"CWD",1},
    [0x9E] = {SAHF,"SAHF",1},
    [0x9F] = {LAHF,"LAHF",1},

    [0xC3] = {RET,  "RET", 1},
    [0xC2] = {RET_IMM16, "RET imm16", 3},
    [0xCB] = {RETF, "RETF imm16", 3},

    [0xCC] = {INT3, "INT3", 1},
    [0xCE] = {INTO, "INTO", 1},
    [0xCF] = {IRET, "IRET", 1},

    [0xF4] = {HLT,  "HLT", 1},
    [0xF5] = {CMC,  "CMC", 1},
    [0xF8] = {CLC,  "CLC", 1},
    [0xF9] = {STC,  "STC", 1},
    [0xFA] = {CLI,  "CLI", 1},
    [0xFB] = {STI,  "STI", 1},
    [0xFC] = {CLD,  "CLD", 1},
    [0xFD] = {STD,  "STD", 1},
};


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

void get_opcode(cpu_instruction *cpu, file_t *file) {
    uint8_t op = file->values[cpu->pc];
    instruction ins = opcode_table[op];

    
    if (ins.mnemonic == NULL) {
        printf("%04zx: %02x   UNKNOWN (bytes: 1)\n", cpu->pc, op);
        cpu->pc += 1;
        return;
    }

    printf("%04zx: %02x   %s (bytes: %d)\n", cpu->pc, op, ins.mnemonic, ins.pc_increment);
    cpu->pc += ins.pc_increment;
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

    cpu_instruction cpu = {0};

    while (cpu.pc < file->file_size) {
        get_opcode(&cpu, file);
    }


    exit(EXIT_SUCCESS);
}