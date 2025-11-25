#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

typedef struct {
    size_t file_size;
    uint8_t * values;
} file_t;


typedef struct {
    char * reg_value;
} reg ;

reg registers[] = {
    [0] = {"EAX"},
    [1] = {"ECX"},
    [2] = {"EDX"},
    [3] = {"EBX"},
    [4] = {"SIB"},
    [5] = {"NO REG"},
    [6] = {"ESI"},
    [7] = {"EDI"},
    [8 ... 255] = {"NULL"}
};


typedef struct {
    size_t pc;
    uint8_t opcode;
} cpu_instruction;

enum ins_type {
    // Data Transfer
    MOV, PUSH, POP, XCHG, XLAT, LEA, LDS, LES,
    
    // Arithmetic
    ADD, ADC, SUB, SBB, INC, DEC, NEG, CMP, MUL, IMUL, DIV, IDIV,
    DAA, DAS, AAA, AAS, AAM, AAD,
    
    // Logical
    AND, OR, XOR, NOT, TEST,
    
    // Shift/Rotate
    SHL, SHR, SAL, SAR, ROL, ROR, RCL, RCR,
    
    // String Operations
    MOVS, CMPS, SCAS, LODS, STOS, REP, REPE, REPNE,
    
    // Control Transfer
    JMP, JE, JNE, JZ, JNZ, JL, JLE, JG, JGE, JB, JBE, JA, JAE,
    JS, JNS, JO, JNO, JP, JNP, JPE, JPO, JCXZ,
    CALL, RET, RET_IMM16, RETF, RETF_IMM16,
    INT, INT3, INTO, IRET, LOOP, LOOPE, LOOPNE,
    
    // Processor Control
    NOP, HLT, WAIT, ESC, LOCK,
    CLC, STC, CMC, CLD, STD, CLI, STI,
    LAHF, SAHF, PUSHF, POPF,
    
    // Conversion
    CBW, CWD, CDQ,
    
    // Segment
    SEGMENT_OVERRIDE,
    
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

    // Data Transfer Instructions
    [0x50] = {PUSH, "PUSH AX/EAX", 1},
    [0x51] = {PUSH, "PUSH CX/ECX", 1},
    [0x52] = {PUSH, "PUSH DX/EDX", 1},
    [0x53] = {PUSH, "PUSH BX/EBX", 1},
    [0x54] = {PUSH, "PUSH SP/ESP", 1},
    [0x55] = {PUSH, "PUSH BP/EBP", 1},
    [0x56] = {PUSH, "PUSH SI/ESI", 1},
    [0x57] = {PUSH, "PUSH DI/EDI", 1},
    
    [0x58] = {POP, "POP AX/EAX", 1},
    [0x59] = {POP, "POP CX/ECX", 1},
    [0x5A] = {POP, "POP DX/EDX", 1},
    [0x5B] = {POP, "POP BX/EBX", 1},
    [0x5C] = {POP, "POP SP/ESP", 1},
    [0x5D] = {POP, "POP BP/EBP", 1},
    [0x5E] = {POP, "POP SI/ESI", 1},
    [0x5F] = {POP, "POP DI/EDI", 1},
    
    [0x86] = {XCHG, "XCHG r/m8, r8", 2},
    [0x87] = {XCHG, "XCHG r/m16/32, r16/32", 2},
    [0x91] = {XCHG, "XCHG CX, AX", 1},
    [0x92] = {XCHG, "XCHG DX, AX", 1},
    [0x93] = {XCHG, "XCHG BX, AX", 1},
    [0x94] = {XCHG, "XCHG SP, AX", 1},
    [0x95] = {XCHG, "XCHG BP, AX", 1},
    [0x96] = {XCHG, "XCHG SI, AX", 1},
    [0x97] = {XCHG, "XCHG DI, AX", 1},

    [0xD7] = {XLAT, "XLAT", 1},

    // Arithmetic Instructions
    [0x04] = {ADD, "ADD AL, imm8", 2},
    [0x05] = {ADD, "ADD AX/EAX, imm16/32", 3},
    [0x14] = {ADC, "ADC AL, imm8", 2},
    [0x15] = {ADC, "ADC AX/EAX, imm16/32", 3},
    [0x24] = {AND, "AND AL, imm8", 2},
    [0x25] = {AND, "AND AX/EAX, imm16/32", 3},
    [0x2C] = {SUB, "SUB AL, imm8", 2},
    [0x2D] = {SUB, "SUB AX/EAX, imm16/32", 3},
    [0x34] = {XOR, "XOR AL, imm8", 2},
    [0x35] = {XOR, "XOR AX/EAX, imm16/32", 3},
    [0x3C] = {CMP, "CMP AL, imm8", 2},
    [0x3D] = {CMP, "CMP AX/EAX, imm16/32", 3},
    
    [0x1C] = {SBB, "SBB AL, imm8", 2},
    [0x1D] = {SBB, "SBB AX/EAX, imm16/32", 3},
    [0x0C] = {OR, "OR AL, imm8", 2},
    [0x0D] = {OR, "OR AX/EAX, imm16/32", 3},
    
    [0x40] = {INC, "INC AX/EAX", 1},
    [0x41] = {INC, "INC CX/ECX", 1},
    [0x42] = {INC, "INC DX/EDX", 1},
    [0x43] = {INC, "INC BX/EBX", 1},
    [0x44] = {INC, "INC SP/ESP", 1},
    [0x45] = {INC, "INC BP/EBP", 1},
    [0x46] = {INC, "INC SI/ESI", 1},
    [0x47] = {INC, "INC DI/EDI", 1},
    
    [0x48] = {DEC, "DEC AX/EAX", 1},
    [0x49] = {DEC, "DEC CX/ECX", 1},
    [0x4A] = {DEC, "DEC DX/EDX", 1},
    [0x4B] = {DEC, "DEC BX/EBX", 1},
    [0x4C] = {DEC, "DEC SP/ESP", 1},
    [0x4D] = {DEC, "DEC BP/EBP", 1},
    [0x4E] = {DEC, "DEC SI/ESI", 1},
    [0x4F] = {DEC, "DEC DI/EDI", 1},

    [0x27] = {DAA, "DAA", 1},
    [0x2F] = {DAS, "DAS", 1},
    [0x37] = {AAA, "AAA", 1},
    [0x3F] = {AAS, "AAS", 1},
    [0xD4] = {AAM, "AAM", 2},
    [0xD5] = {AAD, "AAD", 2},

    // String Operations
    [0xA4] = {MOVS, "MOVSB", 1},
    [0xA5] = {MOVS, "MOVSW/MOVSD", 1},
    [0xA6] = {CMPS, "CMPSB", 1},
    [0xA7] = {CMPS, "CMPSW/CMPSD", 1},
    [0xAA] = {STOS, "STOSB", 1},
    [0xAB] = {STOS, "STOSW/STOSD", 1},
    [0xAC] = {LODS, "LODSB", 1},
    [0xAD] = {LODS, "LODSW/LODSD", 1},
    [0xAE] = {SCAS, "SCASB", 1},
    [0xAF] = {SCAS, "SCASW/SCASD", 1},

    // Control Transfer - Conditional Jumps
    [0x70] = {JO, "JO rel8", 2},
    [0x71] = {JNO, "JNO rel8", 2},
    [0x72] = {JB, "JB/JNAE/JC rel8", 2},
    [0x73] = {JAE, "JAE/JNB/JNC rel8", 2},
    [0x74] = {JE, "JE/JZ rel8", 2},
    [0x75] = {JNE, "JNE/JNZ rel8", 2},
    [0x76] = {JBE, "JBE/JNA rel8", 2},
    [0x77] = {JA, "JA/JNBE rel8", 2},
    [0x78] = {JS, "JS rel8", 2},
    [0x79] = {JNS, "JNS rel8", 2},
    [0x7A] = {JP, "JP/JPE rel8", 2},
    [0x7B] = {JNP, "JNP/JPO rel8", 2},
    [0x7C] = {JL, "JL/JNGE rel8", 2},
    [0x7D] = {JGE, "JGE/JNL rel8", 2},
    [0x7E] = {JLE, "JLE/JNG rel8", 2},
    [0x7F] = {JG, "JG/JNLE rel8", 2},

    // Control Transfer - Unconditional
    [0xE8] = {CALL, "CALL rel16/32", 3},
    [0xE9] = {JMP, "JMP rel16/32", 3},
    [0xEA] = {JMP, "JMP ptr16:16/32", 5},
    [0xEB] = {JMP, "JMP rel8", 2},
    
    [0xE0] = {LOOPNE, "LOOPNE/LOOPNZ rel8", 2},
    [0xE1] = {LOOPE, "LOOPE/LOOPZ rel8", 2},
    [0xE2] = {LOOP, "LOOP rel8", 2},
    [0xE3] = {JCXZ, "JCXZ/JECXZ rel8", 2},

    // Interrupts and Returns
    [0xC2] = {RET_IMM16, "RET imm16", 3},
    [0xC3] = {RET, "RET", 1},
    [0xCA] = {RETF_IMM16, "RETF imm16", 3},
    [0xCB] = {RETF, "RETF", 1},
    [0xCC] = {INT3, "INT3", 1},
    [0xCD] = {INT, "INT imm8", 2},
    [0xCE] = {INTO, "INTO", 1},
    [0xCF] = {IRET, "IRET", 1},

    // Processor Control
    [0x90] = {NOP, "NOP", 1},
    [0x98] = {CBW, "CBW/CWDE", 1},
    [0x99] = {CWD, "CWD/CDQ", 1},
    [0x9C] = {PUSHF, "PUSHF/PUSHFD", 1},
    [0x9D] = {POPF, "POPF/POPFD", 1},
    [0x9E] = {SAHF, "SAHF", 1},
    [0x9F] = {LAHF, "LAHF", 1},
    
    [0xF4] = {HLT, "HLT", 1},
    [0xF5] = {CMC, "CMC", 1},
    [0xF8] = {CLC, "CLC", 1},
    [0xF9] = {STC, "STC", 1},
    [0xFA] = {CLI, "CLI", 1},
    [0xFB] = {STI, "STI", 1},
    [0xFC] = {CLD, "CLD", 1},
    [0xFD] = {STD, "STD", 1},
    
    [0x9B] = {WAIT, "WAIT/FWAIT", 1},
    [0xF0] = {LOCK, "LOCK", 1},

    // I/O Instructions
    [0xE4] = {INVALID, "IN AL, imm8", 2},
    [0xE5] = {INVALID, "IN AX/EAX, imm8", 2},
    [0xE6] = {INVALID, "OUT imm8, AL", 2},
    [0xE7] = {INVALID, "OUT imm8, AX/EAX", 2},
    [0xEC] = {INVALID, "IN AL, DX", 1},
    [0xED] = {INVALID, "IN AX/EAX, DX", 1},
    [0xEE] = {INVALID, "OUT DX, AL", 1},
    [0xEF] = {INVALID, "OUT DX, AX/EAX", 1},

    // Segment Override Prefixes
    [0x26] = {SEGMENT_OVERRIDE, "ES:", 1},
    [0x2E] = {SEGMENT_OVERRIDE, "CS:", 1},
    [0x36] = {SEGMENT_OVERRIDE, "SS:", 1},
    [0x3E] = {SEGMENT_OVERRIDE, "DS:", 1},
    [0x64] = {SEGMENT_OVERRIDE, "FS:", 1},
    [0x65] = {SEGMENT_OVERRIDE, "GS:", 1},

    // Repeat Prefixes
    [0xF2] = {REPNE, "REPNE/REPNZ", 1},
    [0xF3] = {REP, "REP/REPE/REPZ", 1},

    // Move Immediate to Register
    [0xB0] = {MOV, "MOV AL, imm8", 2},
    [0xB1] = {MOV, "MOV CL, imm8", 2},
    [0xB2] = {MOV, "MOV DL, imm8", 2},
    [0xB3] = {MOV, "MOV BL, imm8", 2},
    [0xB4] = {MOV, "MOV AH, imm8", 2},
    [0xB5] = {MOV, "MOV CH, imm8", 2},
    [0xB6] = {MOV, "MOV DH, imm8", 2},
    [0xB7] = {MOV, "MOV BH, imm8", 2},
    [0xB8] = {MOV, "MOV AX/EAX, imm16/32", 3},
    [0xB9] = {MOV, "MOV CX/ECX, imm16/32", 3},
    [0xBA] = {MOV, "MOV DX/EDX, imm16/32", 3},
    [0xBB] = {MOV, "MOV BX/EBX, imm16/32", 3},
    [0xBC] = {MOV, "MOV SP/ESP, imm16/32", 3},
    [0xBD] = {MOV, "MOV BP/EBP, imm16/32", 3},
    [0xBE] = {MOV, "MOV SI/ESI, imm16/32", 3},
    [0xBF] = {MOV, "MOV DI/EDI, imm16/32", 3},

    // Direct Memory Operations
    [0xA0] = {MOV, "MOV AL, moffs8", 3},
    [0xA1] = {MOV, "MOV AX/EAX, moffs16/32", 3},
    [0xA2] = {MOV, "MOV moffs8, AL", 3},
    [0xA3] = {MOV, "MOV moffs16/32, AX/EAX", 3},

    // Test
    [0xA8] = {TEST, "TEST AL, imm8", 2},
    [0xA9] = {TEST, "TEST AX/EAX, imm16/32", 3},
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