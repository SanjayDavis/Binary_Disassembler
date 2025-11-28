#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Cross-platform: only include unistd.h on non-Windows systems
#ifndef _WIN32
#include <unistd.h>
#endif

enum architecture {
    ARCH_UNKNOWN,
    ARCH_X86_32,
    ARCH_X86_64,
    ARCH_ARM,
    ARCH_ARM64,
    ARCH_MIPS,
    ARCH_RISCV,
    ARCH_IA64
};

enum file_type {
    ELF,
    PE,
    UNKNOWN
};

// Section flags (cross-platform)
#define SEC_ALLOC   0x1
#define SEC_EXEC    0x2
#define SEC_WRITE   0x4
#define SEC_READ    0x8

// ELF section types
#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_RELA     4
#define SHT_HASH     5
#define SHT_DYNAMIC  6
#define SHT_NOTE     7
#define SHT_NOBITS   8
#define SHT_REL      9
#define SHT_DYNSYM   11

// ELF section flags
#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4

typedef struct {
    char name[16];
    uint32_t type;    
    uint32_t vaddr;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t flags;
    uint32_t align;
    uint8_t *data;   
} section_t;

typedef struct {
    char name[256];
    uint32_t rva;     
    uint32_t address;  
} function_t;

typedef struct {
    size_t file_size;
    uint8_t * values;
    enum file_type f_type;
    enum architecture arch;
    uint8_t bits;
    uint8_t is_big_endian;  

    int num_of_sections;
    uint32_t entry_address;
    section_t * sections; 
    
    int num_of_functions;
    function_t * functions; 

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
    [8] = {"ESP"},
    [9] = {"EBP"},
    [10 ... 255] = {"NULL"}
};





enum ins_type {
    MOV, PUSH, POP, XCHG, XLAT, LEA, LDS, LES,
    
    ADD, ADC, SUB, SBB, INC, DEC, NEG, CMP, MUL, IMUL, DIV, IDIV,
    DAA, DAS, AAA, AAS, AAM, AAD,
    
    AND, OR, XOR, NOT, TEST,
    
    SHL, SHR, SAL, SAR, ROL, ROR, RCL, RCR,
    
    MOVS, CMPS, SCAS, LODS, STOS, REP, REPE, REPNE,
    
    JMP, JE, JNE, JZ, JNZ, JL, JLE, JG, JGE, JB, JBE, JA, JAE,
    JS, JNS, JO, JNO, JP, JNP, JPE, JPO, JCXZ,
    CALL, RET, RET_IMM16, RETF, RETF_IMM16,
    INT, INT3, INTO, IRET, LOOP, LOOPE, LOOPNE,
    
    NOP, HLT, WAIT, ESC, LOCK,
    CLC, STC, CMC, CLD, STD, CLI, STI,
    LAHF, SAHF, PUSHF, POPF,
    
    CBW, CWD, CDQ,
    
    SEGMENT_OVERRIDE,
    
    INVALID
};


    

const char * operand_type[] = {"rel8","rel16/32","imm8","imm16","moffs8","imm16/32","moffs16/32"};

typedef struct {
    enum ins_type type;
    char *mnemonic;
    int pc_increment;
    uint8_t opcode_len;
    uint8_t has_modrm;
} instruction;

typedef struct {
    size_t pc;
    uint8_t opcode;
} cpu_instruction;


instruction opcode_table[256] = {
    [0 ... 255] = {INVALID, NULL, 1, 1, 0}, 

    // Data Transfer Instructions
    [0x50] = {PUSH, "PUSH AX/EAX", 1, 1, 0},
    [0x51] = {PUSH, "PUSH CX/ECX", 1, 1, 0},
    [0x52] = {PUSH, "PUSH DX/EDX", 1, 1, 0},
    [0x53] = {PUSH, "PUSH BX/EBX", 1, 1, 0},
    [0x54] = {PUSH, "PUSH SP/ESP", 1, 1, 0},
    [0x55] = {PUSH, "PUSH BP/EBP", 1, 1, 0},
    [0x56] = {PUSH, "PUSH SI/ESI", 1, 1, 0},
    [0x57] = {PUSH, "PUSH DI/EDI", 1, 1, 0},
    
    [0x58] = {POP, "POP AX/EAX", 1, 1, 0},
    [0x59] = {POP, "POP CX/ECX", 1, 1, 0},
    [0x5A] = {POP, "POP DX/EDX", 1, 1, 0},
    [0x5B] = {POP, "POP BX/EBX", 1, 1, 0},
    [0x5C] = {POP, "POP SP/ESP", 1, 1, 0},
    [0x5D] = {POP, "POP BP/EBP", 1, 1, 0},
    [0x5E] = {POP, "POP SI/ESI", 1, 1, 0},
    [0x5F] = {POP, "POP DI/EDI", 1, 1, 0},
    
    [0x86] = {XCHG, "XCHG r/m8, r8", 2, 1, 1},
    [0x87] = {XCHG, "XCHG r/m16/32, r16/32", 2, 1, 1},
    [0x91] = {XCHG, "XCHG CX, AX", 1, 1, 0},
    [0x92] = {XCHG, "XCHG DX, AX", 1, 1, 0},
    [0x93] = {XCHG, "XCHG BX, AX", 1, 1, 0},
    [0x94] = {XCHG, "XCHG SP, AX", 1, 1, 0},
    [0x95] = {XCHG, "XCHG BP, AX", 1, 1, 0},
    [0x96] = {XCHG, "XCHG SI, AX", 1, 1, 0},
    [0x97] = {XCHG, "XCHG DI, AX", 1, 1, 0},

    [0xD7] = {XLAT, "XLAT", 1, 1, 0},

    // arithmetic inst
    [0x04] = {ADD, "ADD AL, imm8", 2, 1, 0},
    [0x05] = {ADD, "ADD AX/EAX, imm16/32", 3, 1, 0},
    [0x14] = {ADC, "ADC AL, imm8", 2, 1, 0},
    [0x15] = {ADC, "ADC AX/EAX, imm16/32", 3, 1, 0},
    [0x24] = {AND, "AND AL, imm8", 2, 1, 0},
    [0x25] = {AND, "AND AX/EAX, imm16/32", 3, 1, 0},
    [0x2C] = {SUB, "SUB AL, imm8", 2, 1, 0},
    [0x2D] = {SUB, "SUB AX/EAX, imm16/32", 3, 1, 0},
    [0x34] = {XOR, "XOR AL, imm8", 2, 1, 0},
    [0x35] = {XOR, "XOR AX/EAX, imm16/32", 3, 1, 0},
    [0x3C] = {CMP, "CMP AL, imm8", 2, 1, 0},
    [0x3D] = {CMP, "CMP AX/EAX, imm16/32", 3, 1, 0},
    
    [0x1C] = {SBB, "SBB AL, imm8", 2, 1, 0},
    [0x1D] = {SBB, "SBB AX/EAX, imm16/32", 3, 1, 0},
    [0x0C] = {OR, "OR AL, imm8", 2, 1, 0},
    [0x0D] = {OR, "OR AX/EAX, imm16/32", 3, 1, 0},
    
    [0x40] = {INC, "INC AX/EAX", 1, 1, 0},
    [0x41] = {INC, "INC CX/ECX", 1, 1, 0},
    [0x42] = {INC, "INC DX/EDX", 1, 1, 0},
    [0x43] = {INC, "INC BX/EBX", 1, 1, 0},
    [0x44] = {INC, "INC SP/ESP", 1, 1, 0},
    [0x45] = {INC, "INC BP/EBP", 1, 1, 0},
    [0x46] = {INC, "INC SI/ESI", 1, 1, 0},
    [0x47] = {INC, "INC DI/EDI", 1, 1, 0},
    
    [0x48] = {DEC, "DEC AX/EAX", 1, 1, 0},
    [0x49] = {DEC, "DEC CX/ECX", 1, 1, 0},
    [0x4A] = {DEC, "DEC DX/EDX", 1, 1, 0},
    [0x4B] = {DEC, "DEC BX/EBX", 1, 1, 0},
    [0x4C] = {DEC, "DEC SP/ESP", 1, 1, 0},
    [0x4D] = {DEC, "DEC BP/EBP", 1, 1, 0},
    [0x4E] = {DEC, "DEC SI/ESI", 1, 1, 0},
    [0x4F] = {DEC, "DEC DI/EDI", 1, 1, 0},

    [0x27] = {DAA, "DAA", 1, 1, 0},
    [0x2F] = {DAS, "DAS", 1, 1, 0},
    [0x37] = {AAA, "AAA", 1, 1, 0},
    [0x3F] = {AAS, "AAS", 1, 1, 0},
    [0xD4] = {AAM, "AAM", 2, 1, 0},
    [0xD5] = {AAD, "AAD", 2, 1, 0},

    // string operations
    [0xA4] = {MOVS, "MOVSB", 1, 1, 0},
    [0xA5] = {MOVS, "MOVSW/MOVSD", 1, 1, 0},
    [0xA6] = {CMPS, "CMPSB", 1, 1, 0},
    [0xA7] = {CMPS, "CMPSW/CMPSD", 1, 1, 0},
    [0xAA] = {STOS, "STOSB", 1, 1, 0},
    [0xAB] = {STOS, "STOSW/STOSD", 1, 1, 0},
    [0xAC] = {LODS, "LODSB", 1, 1, 0},
    [0xAD] = {LODS, "LODSW/LODSD", 1, 1, 0},
    [0xAE] = {SCAS, "SCASB", 1, 1, 0},
    [0xAF] = {SCAS, "SCASW/SCASD", 1, 1, 0},

    // condition jumps
    [0x70] = {JO, "JO rel8", 2, 1, 0},
    [0x71] = {JNO, "JNO rel8", 2, 1, 0},
    [0x72] = {JB, "JB/JNAE/JC rel8", 2, 1, 0},
    [0x73] = {JAE, "JAE/JNB/JNC rel8", 2, 1, 0},
    [0x74] = {JE, "JE/JZ rel8", 2, 1, 0},
    [0x75] = {JNE, "JNE/JNZ rel8", 2, 1, 0},
    [0x76] = {JBE, "JBE/JNA rel8", 2, 1, 0},
    [0x77] = {JA, "JA/JNBE rel8", 2, 1, 0},
    [0x78] = {JS, "JS rel8", 2, 1, 0},
    [0x79] = {JNS, "JNS rel8", 2, 1, 0},
    [0x7A] = {JP, "JP/JPE rel8", 2, 1, 0},
    [0x7B] = {JNP, "JNP/JPO rel8", 2, 1, 0},
    [0x7C] = {JL, "JL/JNGE rel8", 2, 1, 0},
    [0x7D] = {JGE, "JGE/JNL rel8", 2, 1, 0},
    [0x7E] = {JLE, "JLE/JNG rel8", 2, 1, 0},
    [0x7F] = {JG, "JG/JNLE rel8", 2, 1, 0},

    // normal jumps
    [0xE8] = {CALL, "CALL rel16/32", 3, 1, 0},
    [0xE9] = {JMP, "JMP rel16/32", 3, 1, 0},
    [0xEA] = {JMP, "JMP ptr16:16/32", 5, 1, 0},
    [0xEB] = {JMP, "JMP rel8", 2, 1, 0},
    
    [0xE0] = {LOOPNE, "LOOPNE/LOOPNZ rel8", 2, 1, 0},
    [0xE1] = {LOOPE, "LOOPE/LOOPZ rel8", 2, 1, 0},
    [0xE2] = {LOOP, "LOOP rel8", 2, 1, 0},
    [0xE3] = {JCXZ, "JCXZ/JECXZ rel8", 2, 1, 0},

    // interrupts , returns
    [0xC2] = {RET_IMM16, "RET imm16", 3, 1, 0},
    [0xC3] = {RET, "RET", 1, 1, 0},
    [0xCA] = {RETF_IMM16, "RETF imm16", 3, 1, 0},
    [0xCB] = {RETF, "RETF", 1, 1, 0},
    [0xCC] = {INT3, "INT3", 1, 1, 0},
    [0xCD] = {INT, "INT imm8", 2, 1, 0},
    [0xCE] = {INTO, "INTO", 1, 1, 0},
    [0xCF] = {IRET, "IRET", 1, 1, 0},

    // processor control
    [0x90] = {NOP, "NOP", 1, 1, 0},
    [0x98] = {CBW, "CBW/CWDE", 1, 1, 0},
    [0x99] = {CWD, "CWD/CDQ", 1, 1, 0},
    [0x9C] = {PUSHF, "PUSHF/PUSHFD", 1, 1, 0},
    [0x9D] = {POPF, "POPF/POPFD", 1, 1, 0},
    [0x9E] = {SAHF, "SAHF", 1, 1, 0},
    [0x9F] = {LAHF, "LAHF", 1, 1, 0},
    
    [0xF4] = {HLT, "HLT", 1, 1, 0},
    [0xF5] = {CMC, "CMC", 1, 1, 0},
    [0xF8] = {CLC, "CLC", 1, 1, 0},
    [0xF9] = {STC, "STC", 1, 1, 0},
    [0xFA] = {CLI, "CLI", 1, 1, 0},
    [0xFB] = {STI, "STI", 1, 1, 0},
    [0xFC] = {CLD, "CLD", 1, 1, 0},
    [0xFD] = {STD, "STD", 1, 1, 0},
    
    [0x9B] = {WAIT, "WAIT/FWAIT", 1, 1, 0},
    [0xF0] = {LOCK, "LOCK", 1, 1, 0},

    // io instructions
    [0xE4] = {INVALID, "IN AL, imm8", 2, 1, 0},
    [0xE5] = {INVALID, "IN AX/EAX, imm8", 2, 1, 0},
    [0xE6] = {INVALID, "OUT imm8, AL", 2, 1, 0},
    [0xE7] = {INVALID, "OUT imm8, AX/EAX", 2, 1, 0},
    [0xEC] = {INVALID, "IN AL, DX", 1, 1, 0},
    [0xED] = {INVALID, "IN AX/EAX, DX", 1, 1, 0},
    [0xEE] = {INVALID, "OUT DX, AL", 1, 1, 0},
    [0xEF] = {INVALID, "OUT DX, AX/EAX", 1, 1, 0},

    // segment override
    [0x26] = {SEGMENT_OVERRIDE, "ES:", 1, 1, 0},
    [0x2E] = {SEGMENT_OVERRIDE, "CS:", 1, 1, 0},
    [0x36] = {SEGMENT_OVERRIDE, "SS:", 1, 1, 0},
    [0x3E] = {SEGMENT_OVERRIDE, "DS:", 1, 1, 0},
    [0x64] = {SEGMENT_OVERRIDE, "FS:", 1, 1, 0},
    [0x65] = {SEGMENT_OVERRIDE, "GS:", 1, 1, 0},

    // repeat prefixes
    [0xF2] = {REPNE, "REPNE/REPNZ", 1, 1, 0},
    [0xF3] = {REP, "REP/REPE/REPZ", 1, 1, 0},

    // move immediate to register
    [0xB0] = {MOV, "MOV AL, imm8", 2, 1, 0},
    [0xB1] = {MOV, "MOV CL, imm8", 2, 1, 0},
    [0xB2] = {MOV, "MOV DL, imm8", 2, 1, 0},
    [0xB3] = {MOV, "MOV BL, imm8", 2, 1, 0},
    [0xB4] = {MOV, "MOV AH, imm8", 2, 1, 0},
    [0xB5] = {MOV, "MOV CH, imm8", 2, 1, 0},
    [0xB6] = {MOV, "MOV DH, imm8", 2, 1, 0},
    [0xB7] = {MOV, "MOV BH, imm8", 2, 1, 0},
    [0xB8] = {MOV, "MOV AX/EAX, imm16/32", 3, 1, 0},
    [0xB9] = {MOV, "MOV CX/ECX, imm16/32", 3, 1, 0},
    [0xBA] = {MOV, "MOV DX/EDX, imm16/32", 3, 1, 0},
    [0xBB] = {MOV, "MOV BX/EBX, imm16/32", 3, 1, 0},
    [0xBC] = {MOV, "MOV SP/ESP, imm16/32", 3, 1, 0},
    [0xBD] = {MOV, "MOV BP/EBP, imm16/32", 3, 1, 0},
    [0xBE] = {MOV, "MOV SI/ESI, imm16/32", 3, 1, 0},
    [0xBF] = {MOV, "MOV DI/EDI, imm16/32", 3, 1, 0},

    // direct mem operations
    [0xA0] = {MOV, "MOV AL, moffs8", 3, 1, 0},
    [0xA1] = {MOV, "MOV AX/EAX, moffs16/32", 3, 1, 0},
    [0xA2] = {MOV, "MOV moffs8, AL", 3, 1, 0},
    [0xA3] = {MOV, "MOV moffs16/32, AX/EAX", 3, 1, 0},

    // testing
    [0xA8] = {TEST, "TEST AL, imm8", 2, 1, 0},
    [0xA9] = {TEST, "TEST AX/EAX, imm16/32", 3, 1, 0},
};

char *mod_rm[2][8][4] = {
    { // 32-bit (16-bit addressing modes)
        {"[BX+SI]","[BX+SI+DISP8]","[BX+SI+DISP16]","AL/AX"},
        {"[BX+DI]","[BX+DI+DISP8]","[BX+DI+DISP16]","CL/CX"},
        {"[BP+SI]","[BP+SI+DISP8]","[BP+SI+DISP16]","DL/DX"},
        {"[BP+DI]","[BP+DI+DISP8]","[BP+DI+DISP16]","BL/BX"},
        {"[SI]","[SI+DISP8]","[SI+DISP16]","AH/SP"},
        {"[DI]","[DI+DISP8]","[DI+DISP16]","CH/BP"},
        {"[DISP16]","[BP+DISP8]","[BP+DISP16]","DH/SI"},
        {"[BX]","[BX+DISP8]","[BX+DISP16]","BH/DI"},
    },
    {   // 64-bit (32-bit addressing modes)
        {"[EAX]","[EAX+DISP8]","[EAX+DISP32]","AL/AX/EAX"},
        {"[ECX]","[ECX+DISP8]","[ECX+DISP32]","CL/CX/ECX"},
        {"[EDX]","[EDX+DISP8]","[EDX+DISP32]","DL/DX/EDX"},
        {"[EBX]","[EBX+DISP8]","[EBX+DISP32]","BL/BX/EBX"},
        {"[SIB]","[SIB+DISP8]","[SIB+DISP32]","AH/SP/ESP"},
        {"[DISP32]","[EBP+DISP8]","[EBP+DISP32]","CH/BP/EBP"},
        {"[ESI]","[ESI+DISP8]","[ESI+DISP32]","DH/SI/ESI"},
        {"[EDI]","[EDI+DISP8]","[EDI+DISP32]","BH/DI/EDI"}
    }
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
    size_t count = fread(buffer,1,size,fileptr);
    if(count != size)
    {
        printf("fread did not read all values");
        exit(EXIT_FAILURE);
    }

    return file_info;
}

typedef struct {
    char * initial;
    char * dest;
} mod_rm_registers ;

mod_rm_registers *  fill_mod_rm(uint8_t modrm,instruction * ins,file_t * file){
    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t r = ( modrm >> 3) & 0b00000111;
    uint8_t rm  = modrm & 0b00000111;

    if (file->bits == 32){
        mod_rm_registers * pre_modrm = malloc(sizeof(mod_rm_registers));
        pre_modrm->initial = mod_rm[0][r][mod];
        pre_modrm->dest = mod_rm[0][rm][mod];
        return pre_modrm;
    }
    else if (file->bits == 64)
    {
        mod_rm_registers * pre_modrm = malloc(sizeof(mod_rm_registers));
        pre_modrm->initial = mod_rm[1][r][mod];
        pre_modrm->dest = mod_rm[1][rm][mod];
        return pre_modrm;
    }

}

size_t get_immediate_offset(cpu_instruction *cpu, file_t *file, instruction *ins) {
    size_t offset = cpu->pc + ins->opcode_len;

    if (!ins->has_modrm)
        return offset;

    uint8_t modrm = file->values[offset];
    offset++;

    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t rm  = modrm & 0x7;

    
    if (file->bits == 32 && mod != 3 && rm == 4) {
        offset++;  
    }


    if (mod == 1)
        offset += 1;      
    else if (mod == 2)
        offset += 4;       
    else if (mod == 0 && rm == 5)
        offset += 4;       

    return offset;
}


void fill_instruction(instruction *ins, cpu_instruction *cpu, file_t *file) {
    if (ins->mnemonic == NULL) return;
    
    char filled_mnemonic[256];
    strcpy(filled_mnemonic, ins->mnemonic);
    
    for (int i = 0; i < 7 ; i++) {
        char *pos = strstr(filled_mnemonic, operand_type[i]);
        if (pos != NULL) {

            char value_str[64];
            size_t offset = get_immediate_offset(cpu, file, ins); 
            
            if (strcmp(operand_type[i], "rel8") == 0) {

                int8_t rel = (int8_t)file->values[offset];
                sprintf(value_str, "0x%04zx", cpu->pc + ins->pc_increment + rel);
            }
            else if (strcmp(operand_type[i], "rel16/32") == 0) {

                if (file->bits == 32) {
                    int32_t rel = *(int32_t*)&file->values[offset];
                    sprintf(value_str, "0x%08zx", cpu->pc + ins->pc_increment + rel);
                } else {
                    int16_t rel = *(int16_t*)&file->values[offset];
                    sprintf(value_str, "0x%04zx", cpu->pc + ins->pc_increment + rel);
                }
            }
            else if (strcmp(operand_type[i], "imm8") == 0) {

                uint8_t imm = file->values[offset];
                sprintf(value_str, "0x%02x", imm);
            }
            else if (strcmp(operand_type[i], "imm16") == 0) {

                uint16_t imm = *(uint16_t*)&file->values[offset];
                sprintf(value_str, "0x%04x", imm);
            }
            else if (strcmp(operand_type[i], "moffs8") == 0) {

                uint8_t moffs = file->values[offset];
                sprintf(value_str, "[0x%02x]", moffs);
            }
            else if (strcmp(operand_type[i], "imm16/32") == 0) {

                if (file->bits == 32) {
                    uint32_t imm = *(uint32_t*)&file->values[offset];
                    sprintf(value_str, "0x%08x", imm);
                } else {
                    uint16_t imm = *(uint16_t*)&file->values[offset];
                    sprintf(value_str, "0x%04x", imm);
                }
            }
            else if (strcmp(operand_type[i], "moffs16/32") == 0) {

                if (file->bits == 32) {
                    uint32_t moffs = *(uint32_t*)&file->values[offset];
                    sprintf(value_str, "[0x%08x]", moffs);
                } else {
                    uint16_t moffs = *(uint16_t*)&file->values[offset];
                    sprintf(value_str, "[0x%04x]", moffs);
                }
            }
            

            size_t prefix_len = pos - filled_mnemonic;
            char temp[256];
            strncpy(temp, filled_mnemonic, prefix_len);
            temp[prefix_len] = '\0';
            strcat(temp, value_str);
            strcat(temp, pos + strlen(operand_type[i]));
            

            ins->mnemonic = malloc(strlen(temp) + 1);
            if (ins->mnemonic != NULL) {
                strcpy(ins->mnemonic, temp);
            }
            return;
        }
    }
}

void get_opcode(cpu_instruction *cpu, file_t *file) {
    uint8_t op = file->values[cpu->pc];
    instruction ins = opcode_table[op];
    fill_instruction(&ins, cpu, file);

    
    if (ins.mnemonic == NULL) {
        printf("%04zx: %02x   UNKNOWN (bytes: 1)\n", cpu->pc, op);
        cpu->pc += 1;
        return;
    }
    // has modrm
    if (ins.has_modrm && cpu->pc + 1 < file->file_size) {
        uint8_t modrm = file->values[cpu->pc + ins.opcode_len];
        mod_rm_registers *modrm_info = fill_mod_rm(modrm, &ins, file);
        if (modrm_info) { // if null
            printf("%04zx: %02x %02x %s (bytes: %d) [%s, %s]\n", 
                   cpu->pc, op, modrm, ins.mnemonic, ins.pc_increment,
                   modrm_info->dest, modrm_info->initial);
            free(modrm_info);
        } else {
            printf("%04zx: %02x   %s (bytes: %d)\n", cpu->pc, op, ins.mnemonic, ins.pc_increment);
        }
    } else // no modrm
    {
        printf("%04zx: %02x   %s (bytes: %d)\n", cpu->pc, op, ins.mnemonic, ins.pc_increment);
    }
    
    cpu->pc += ins.pc_increment;
}

uint16_t read16(uint8_t *data, int swap);
uint32_t read32(uint8_t *data, int swap);
uint64_t read64(uint8_t *data, int swap);

void detect_elf_arch(file_t *file) {
    uint8_t elf_class = file->values[4];
    uint8_t elf_data = file->values[5];  // EI_DATA: 1 = little, 2 = big (endian)
    
    file->is_big_endian = (elf_data == 2) ? 1 : 0;
    
    int swap = 0;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        swap = !file->is_big_endian;
    #else
        swap = file->is_big_endian;
    #endif
    
    uint16_t machine = read16(&file->values[0x12], swap);

    if (elf_class == 1) file->bits = 32;
    else if (elf_class == 2) file->bits = 64;
    else file->bits = 0;

    switch (machine) {
        case 0x03: file->arch = ARCH_X86_32; break;
        case 0x3E: file->arch = ARCH_X86_64; break;
        case 0x28: file->arch = ARCH_ARM; break;
        case 0xB7: file->arch = ARCH_ARM64; break;
        case 0x08: file->arch = ARCH_MIPS; break;
        case 0xF3: file->arch = ARCH_RISCV; break;
        default:   file->arch = ARCH_UNKNOWN; break;
    }
}

void parse_elf_sections(file_t *file) {
    uint8_t *data = file->values;
    
    int swap = 0;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        swap = !file->is_big_endian;
    #else
        swap = file->is_big_endian;
    #endif
    
    if (file->bits == 32) {
        // ELF32
        uint32_t shoff = read32(&data[0x20], swap);        // Section header offset
        uint16_t shentsize = read16(&data[0x2E], swap);    // Section header entry size
        uint16_t shnum = read16(&data[0x30], swap);        // Number of section headers
        uint16_t shstrndx = read16(&data[0x32], swap);     // Section name string table index
        
        if (shoff == 0 || shoff >= file->file_size) {
            file->num_of_sections = 0;
            return;
        }
        if (shoff + (uint64_t)shnum * shentsize > file->file_size) {
            file->num_of_sections = 0;
            return;
        }
        
        file->num_of_sections = shnum;
        file->sections = calloc(shnum, sizeof(section_t));
        if (!file->sections) return;
        
        if (shstrndx >= shnum) {
            free(file->sections);
            file->sections = NULL;
            file->num_of_sections = 0;
            return;
        }
        
        uint32_t strtab_offset = read32(&data[shoff + shstrndx * shentsize + 0x10], swap);
        
        if (strtab_offset >= file->file_size) {
            free(file->sections);
            file->sections = NULL;
            file->num_of_sections = 0;
            return;
        }
        
        for (int i = 0; i < shnum; i++) {
            uint32_t sh_base = shoff + i * shentsize;
            
            uint32_t name_idx = read32(&data[sh_base + 0x00], swap);
            uint32_t sh_type = read32(&data[sh_base + 0x04], swap);
            uint32_t sh_flags = read32(&data[sh_base + 0x08], swap);
            uint32_t sh_addr = read32(&data[sh_base + 0x0C], swap);
            uint32_t sh_offset = read32(&data[sh_base + 0x10], swap);
            uint32_t sh_size = read32(&data[sh_base + 0x14], swap);
            uint32_t sh_addralign = read32(&data[sh_base + 0x20], swap);
            
            // Copy section name with validation
            if (strtab_offset + name_idx < file->file_size) {
                char *name_ptr = (char*)&data[strtab_offset + name_idx];
                size_t max_len = file->file_size - (strtab_offset + name_idx);
                size_t copy_len = (max_len < 15) ? max_len : 15;
                strncpy(file->sections[i].name, name_ptr, copy_len);
                file->sections[i].name[15] = '\0';
            } else {
                strcpy(file->sections[i].name, "<invalid>");
            }
            
            file->sections[i].type = sh_type;
            file->sections[i].vaddr = sh_addr;
            file->sections[i].raw_offset = sh_offset;
            file->sections[i].raw_size = sh_size;
            file->sections[i].align = sh_addralign;
            
            // Convert ELF flags to our flags (corrected)
            file->sections[i].flags = 0;
            if (sh_flags & SHF_ALLOC) {
                file->sections[i].flags |= SEC_ALLOC;
                file->sections[i].flags |= SEC_READ;  // Allocated sections are readable
            }
            if (sh_flags & SHF_WRITE) file->sections[i].flags |= SEC_WRITE;
            if (sh_flags & SHF_EXECINSTR) file->sections[i].flags |= SEC_EXEC;
            
            // Load section data into memory
            file->sections[i].data = NULL;
            if (sh_type != SHT_NOBITS && sh_size > 0) {
                // Validate section bounds
                if (sh_offset < file->file_size && 
                    sh_offset + sh_size <= file->file_size) {
                    file->sections[i].data = malloc(sh_size);
                    if (file->sections[i].data) {
                        memcpy(file->sections[i].data, &data[sh_offset], sh_size);
                    }
                }
            } else if (sh_type == SHT_NOBITS && sh_size > 0) {
                // .bss section - allocate zeroed memory
                file->sections[i].data = calloc(1, sh_size);
            }
        }
        
        file->entry_address = read32(&data[0x18], swap);
        
    } else if (file->bits == 64) {
        // ELF64
        uint64_t shoff = read64(&data[0x28], swap);        // Section header offset
        uint16_t shentsize = read16(&data[0x3A], swap);    // Section header entry size
        uint16_t shnum = read16(&data[0x3C], swap);        // Number of section headers
        uint16_t shstrndx = read16(&data[0x3E], swap);     // Section name string table index
        
        // Validation: check if section headers are within file
        if (shoff == 0 || shoff >= file->file_size) {
            file->num_of_sections = 0;
            return;
        }
        if (shoff + (uint64_t)shnum * shentsize > file->file_size) {
            file->num_of_sections = 0;
            return;
        }
        
        file->num_of_sections = shnum;
        file->sections = calloc(shnum, sizeof(section_t));
        if (!file->sections) return;
        
        // Get string table section offset
        if (shstrndx >= shnum) {
            free(file->sections);
            file->sections = NULL;
            file->num_of_sections = 0;
            return;
        }
        
        uint64_t strtab_offset = read64(&data[shoff + shstrndx * shentsize + 0x18], swap);
        
        // Validate string table offset
        if (strtab_offset >= file->file_size) {
            free(file->sections);
            file->sections = NULL;
            file->num_of_sections = 0;
            return;
        }
        
        for (int i = 0; i < shnum; i++) {
            uint64_t sh_base = shoff + i * shentsize;
            
            uint32_t name_idx = read32(&data[sh_base + 0x00], swap);
            uint32_t sh_type = read32(&data[sh_base + 0x04], swap);
            uint64_t sh_flags = read64(&data[sh_base + 0x08], swap);
            uint64_t sh_addr = read64(&data[sh_base + 0x10], swap);
            uint64_t sh_offset = read64(&data[sh_base + 0x18], swap);
            uint64_t sh_size = read64(&data[sh_base + 0x20], swap);
            uint64_t sh_addralign = read64(&data[sh_base + 0x30], swap);
            
            // Copy section name with validation
            if (strtab_offset + name_idx < file->file_size) {
                char *name_ptr = (char*)&data[strtab_offset + name_idx];
                size_t max_len = file->file_size - (strtab_offset + name_idx);
                size_t copy_len = (max_len < 15) ? max_len : 15;
                strncpy(file->sections[i].name, name_ptr, copy_len);
                file->sections[i].name[15] = '\0';
            } else {
                strcpy(file->sections[i].name, "<invalid>");
            }
            
            file->sections[i].type = sh_type;
            file->sections[i].vaddr = (uint32_t)sh_addr;  // Truncate for display
            file->sections[i].raw_offset = (uint32_t)sh_offset;
            file->sections[i].raw_size = (uint32_t)sh_size;
            file->sections[i].align = (uint32_t)sh_addralign;
            
            // Convert ELF flags to our flags (corrected)
            file->sections[i].flags = 0;
            if (sh_flags & SHF_ALLOC) {
                file->sections[i].flags |= SEC_ALLOC;
                file->sections[i].flags |= SEC_READ;  // Allocated sections are readable
            }
            if (sh_flags & SHF_WRITE) file->sections[i].flags |= SEC_WRITE;
            if (sh_flags & SHF_EXECINSTR) file->sections[i].flags |= SEC_EXEC;
            
            // Load section data into memory
            file->sections[i].data = NULL;
            if (sh_type != SHT_NOBITS && sh_size > 0 && sh_size < 0xFFFFFFFF) {
                // Validate section bounds
                if (sh_offset < file->file_size && 
                    sh_offset + sh_size <= file->file_size) {
                    file->sections[i].data = malloc((size_t)sh_size);
                    if (file->sections[i].data) {
                        memcpy(file->sections[i].data, &data[sh_offset], (size_t)sh_size);
                    }
                }
            } else if (sh_type == SHT_NOBITS && sh_size > 0 && sh_size < 0xFFFFFFFF) {
                // .bss section - allocate zeroed memory
                file->sections[i].data = calloc(1, (size_t)sh_size);
            }
        }
        
        // Read 64-bit entry point correctly
        uint64_t entry64 = read64(&data[0x18], swap);
        file->entry_address = (uint32_t)entry64;  // Truncate for 32-bit display
    }
}

uint16_t read16(uint8_t *data, int swap) {
    uint16_t val = *(uint16_t*)data;
    if (swap) {
        return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
    }
    return val;
}

uint32_t read32(uint8_t *data, int swap) {
    uint32_t val = *(uint32_t*)data;
    if (swap) {
        return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
               ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF);
    }
    return val;
}

uint64_t read64(uint8_t *data, int swap) {
    uint64_t val = *(uint64_t*)data;
    if (swap) {
        return ((val & 0xFFULL) << 56) | ((val & 0xFF00ULL) << 40) |
               ((val & 0xFF0000ULL) << 24) | ((val & 0xFF000000ULL) << 8) |
               ((val >> 8) & 0xFF000000ULL) | ((val >> 24) & 0xFF0000ULL) |
               ((val >> 40) & 0xFF00ULL) | ((val >> 56) & 0xFFULL);
    }
    return val;
}

void detect_pe_arch(file_t *file) {
    uint32_t pe_offset = *(uint32_t*)&file->values[0x3C];
    uint16_t machine = *(uint16_t*)&file->values[pe_offset + 4];

    switch (machine) {
        case 0x014c:
            file->arch = ARCH_X86_32;
            file->bits = 32;
            break;
        case 0x8664:
            file->arch = ARCH_X86_64;
            file->bits = 64;
            break;
        case 0x01c0:
            file->arch = ARCH_ARM;
            file->bits = 32;
            break;
        case 0xAA64:
            file->arch = ARCH_ARM64;
            file->bits = 64;
            break;
        case 0x0200:
            file->arch = ARCH_IA64;
            file->bits = 64;
            break;
        default:
            file->arch = ARCH_UNKNOWN;
            file->bits = 0;
            break;
    }
}

void parse_pe_sections(file_t *file) {
    uint8_t *data = file->values;
    uint32_t pe_offset = *(uint32_t*)&data[0x3C];
    
    // Get number of sections
    uint16_t num_sections = *(uint16_t*)&data[pe_offset + 6];
    uint16_t opt_hdr_size = *(uint16_t*)&data[pe_offset + 20];
    
    file->num_of_sections = num_sections;
    file->sections = malloc(sizeof(section_t) * num_sections);
    if (!file->sections) return;
    
    // Section table starts after optional header
    uint32_t section_table = pe_offset + 24 + opt_hdr_size;
    
    // Get entry point (AddressOfEntryPoint from optional header)
    if (opt_hdr_size > 0) {
        file->entry_address = *(uint32_t*)&data[pe_offset + 24 + 16];
    }
    
    for (int i = 0; i < num_sections; i++) {
        uint32_t section_base = section_table + i * 40; // each section (each entry is 40 bytes)
        
        strncpy(file->sections[i].name, (char*)&data[section_base], 8);
        file->sections[i].name[8] = '\0';
        
        uint32_t virtual_size = *(uint32_t*)&data[section_base + 8];
        uint32_t virtual_addr = *(uint32_t*)&data[section_base + 12];
        uint32_t raw_size = *(uint32_t*)&data[section_base + 16];
        uint32_t raw_offset = *(uint32_t*)&data[section_base + 20];
        uint32_t characteristics = *(uint32_t*)&data[section_base + 36];
        
        file->sections[i].type = SHT_PROGBITS;  // PE doesn't have type field, default to PROGBITS
        file->sections[i].vaddr = virtual_addr;
        file->sections[i].raw_offset = raw_offset;
        file->sections[i].raw_size = raw_size;
        file->sections[i].align = 0; // PE alignment is in the optional header
        file->sections[i].data = NULL;  // pr sections are not loaded yet
        
        file->sections[i].flags = 0;
        if (characteristics & 0x02000000) file->sections[i].flags |= SEC_EXEC;   // IMAGE_SCN_MEM_EXECUTE
        if (characteristics & 0x40000000) file->sections[i].flags |= SEC_READ;   // IMAGE_SCN_MEM_READ
        if (characteristics & 0x80000000) file->sections[i].flags |= SEC_WRITE;  // IMAGE_SCN_MEM_WRITE
        if (characteristics & 0x20000000) file->sections[i].flags |= SEC_ALLOC;  // IMAGE_SCN_MEM_EXECUTE (treated as alloc)
    }
}

void parse_pe_functions(file_t *file) {
    uint8_t *data = file->values;
    uint32_t pe_offset = *(uint32_t*)&data[0x3C];
    uint16_t opt_hdr_size = *(uint16_t*)&data[pe_offset + 20];
    
    if (opt_hdr_size == 0) return;
    
    // Get the image base and export table RVA from optional header
    uint32_t opt_hdr_base = pe_offset + 24;
    uint32_t image_base = 0;
    uint32_t export_rva = 0;
    uint32_t export_size = 0;
    
    // Check magic number to determine PE32 or PE32+
    uint16_t magic = *(uint16_t*)&data[opt_hdr_base];
    
    if (magic == 0x10B) { // PE32
        image_base = *(uint32_t*)&data[opt_hdr_base + 28];
        export_rva = *(uint32_t*)&data[opt_hdr_base + 96];  // Export Table RVA
        export_size = *(uint32_t*)&data[opt_hdr_base + 100]; // Export Table Size
    } else if (magic == 0x20B) { // PE32+
        image_base = *(uint32_t*)&data[opt_hdr_base + 24]; // Lower 32 bits
        export_rva = *(uint32_t*)&data[opt_hdr_base + 112]; // Export Table RVA
        export_size = *(uint32_t*)&data[opt_hdr_base + 116]; // Export Table Size
    }
    
    if (export_rva == 0 || export_size == 0) {
        file->num_of_functions = 0;
        file->functions = NULL;
        return;
    }
    
    // Convert RVA to file offset
    uint32_t export_offset = 0;
    for (int i = 0; i < file->num_of_sections; i++) {
        section_t *s = &file->sections[i];
        if (export_rva >= s->vaddr && export_rva < s->vaddr + s->raw_size) {
            export_offset = s->raw_offset + (export_rva - s->vaddr);
            break;
        }
    }
    
    if (export_offset == 0 || export_offset >= file->file_size) {
        file->num_of_functions = 0;
        file->functions = NULL;
        return;
    }
    
    // Parse export directory
    uint32_t num_of_names = *(uint32_t*)&data[export_offset + 24];
    uint32_t addr_of_funcs_rva = *(uint32_t*)&data[export_offset + 28];
    uint32_t addr_of_names_rva = *(uint32_t*)&data[export_offset + 32];
    uint32_t addr_of_ords_rva = *(uint32_t*)&data[export_offset + 36];
    
    if (num_of_names == 0) {
        file->num_of_functions = 0;
        file->functions = NULL;
        return;
    }
    
    file->num_of_functions = num_of_names;
    file->functions = malloc(sizeof(function_t) * num_of_names);
    if (!file->functions) return;
    
    // Convert RVAs to file offsets
    uint32_t names_offset = 0, funcs_offset = 0;
    for (int i = 0; i < file->num_of_sections; i++) {
        section_t *s = &file->sections[i];
        if (addr_of_names_rva >= s->vaddr && addr_of_names_rva < s->vaddr + s->raw_size) {
            names_offset = s->raw_offset + (addr_of_names_rva - s->vaddr);
        }
        if (addr_of_funcs_rva >= s->vaddr && addr_of_funcs_rva < s->vaddr + s->raw_size) {
            funcs_offset = s->raw_offset + (addr_of_funcs_rva - s->vaddr);
        }
    }
    
    // Read function names and addresses
    for (uint32_t i = 0; i < num_of_names; i++) {
        // Get name RVA
        uint32_t name_rva = *(uint32_t*)&data[names_offset + i * 4];
        
        // Convert name RVA to file offset
        uint32_t name_offset = 0;
        for (int j = 0; j < file->num_of_sections; j++) {
            section_t *s = &file->sections[j];
            if (name_rva >= s->vaddr && name_rva < s->vaddr + s->raw_size) {
                name_offset = s->raw_offset + (name_rva - s->vaddr);
                break;
            }
        }
        
        // Copy function name
        if (name_offset > 0 && name_offset < file->file_size) {
            strncpy(file->functions[i].name, (char*)&data[name_offset], 255);
            file->functions[i].name[255] = '\0';
        } else {
            strcpy(file->functions[i].name, "<unknown>");
        }
        
        // Get function address
        uint32_t func_rva = *(uint32_t*)&data[funcs_offset + i * 4];
        file->functions[i].rva = func_rva;
        file->functions[i].address = image_base + func_rva;
    }
}

void parse_elf_functions(file_t *file) {
    // Find .symtab or .dynsym section and corresponding string table
    section_t *symtab = NULL;
    section_t *strtab = NULL;
    int symtab_idx = -1;
    
    // First try to find .symtab (static symbol table)
    for (int i = 0; i < file->num_of_sections; i++) {
        if (strcmp(file->sections[i].name, ".symtab") == 0) {
            symtab = &file->sections[i];
            symtab_idx = i;
            break;
        }
    }
    
    // If no .symtab, try .dynsym (dynamic symbol table)
    if (!symtab) {
        for (int i = 0; i < file->num_of_sections; i++) {
            if (strcmp(file->sections[i].name, ".dynsym") == 0) {
                symtab = &file->sections[i];
                symtab_idx = i;
                break;
            }
        }
    }
    
    if (!symtab || !symtab->data) {
        file->num_of_functions = 0;
        file->functions = NULL;
        return;
    }
    
    // Find corresponding string table
    // For ELF, the sh_link field points to the string table section
    // We need to parse this from the section header
    uint8_t *data = file->values;
    int swap = 0;
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        swap = !file->is_big_endian;
    #else
        swap = file->is_big_endian;
    #endif
    
    uint32_t strtab_idx = 0;
    if (file->bits == 64) {
        uint64_t shoff = read64(&data[0x28], swap);
        uint16_t shentsize = read16(&data[0x3A], swap);
        uint64_t sh_base = shoff + symtab_idx * shentsize;
        strtab_idx = read32(&data[sh_base + 0x28], swap);  // sh_link at offset 0x28 in 64-bit
    } else {
        uint32_t shoff = read32(&data[0x20], swap);
        uint16_t shentsize = read16(&data[0x2E], swap);
        uint32_t sh_base = shoff + symtab_idx * shentsize;
        strtab_idx = read32(&data[sh_base + 0x18], swap);  // sh_link at offset 0x18 in 32-bit
    }
    
    if (strtab_idx >= file->num_of_sections) {
        file->num_of_functions = 0;
        file->functions = NULL;
        return;
    }
    
    strtab = &file->sections[strtab_idx];
    if (!strtab->data) {
        file->num_of_functions = 0;
        file->functions = NULL;
        return;
    }
    
    // Calculate number of symbols
    size_t sym_size = (file->bits == 64) ? 24 : 16;  // ELF64_Sym = 24 bytes, ELF32_Sym = 16 bytes
    size_t num_symbols = symtab->raw_size / sym_size;
    
    // First pass: count function symbols
    int func_count = 0;
    for (size_t i = 0; i < num_symbols; i++) {
        uint8_t *sym_data = &symtab->data[i * sym_size];
        uint8_t st_info;
        
        if (file->bits == 64) {
            st_info = sym_data[4];  // st_info is at offset 4 in ELF64
        } else {
            st_info = sym_data[12]; // st_info is at offset 12 in ELF32
        }
        
        uint8_t st_type = st_info & 0xF;
        // STT_FUNC = 2
        if (st_type == 2) {
            func_count++;
        }
    }
    
    if (func_count == 0) {
        file->num_of_functions = 0;
        file->functions = NULL;
        return;
    }
    
    // Allocate function array
    file->num_of_functions = func_count;
    file->functions = malloc(sizeof(function_t) * func_count);
    if (!file->functions) {
        file->num_of_functions = 0;
        return;
    }
    
    // Second pass: extract function symbols
    int func_idx = 0;
    for (size_t i = 0; i < num_symbols && func_idx < func_count; i++) {
        uint8_t *sym_data = &symtab->data[i * sym_size];
        uint8_t st_info;
        uint32_t st_name;
        uint64_t st_value;
        
        if (file->bits == 64) {
            st_name = read32(&sym_data[0], swap);
            st_info = sym_data[4];
            st_value = read64(&sym_data[8], swap);
        } else {
            st_name = read32(&sym_data[0], swap);
            st_value = read32(&sym_data[4], swap);
            st_info = sym_data[12];
        }
        
        uint8_t st_type = st_info & 0xF;
        if (st_type == 2) {  // STT_FUNC
            // Get function name from string table
            if (st_name < strtab->raw_size) {
                char *name_ptr = (char*)&strtab->data[st_name];
                strncpy(file->functions[func_idx].name, name_ptr, 255);
                file->functions[func_idx].name[255] = '\0';
            } else {
                strcpy(file->functions[func_idx].name, "<invalid>");
            }
            
            file->functions[func_idx].rva = (uint32_t)st_value;
            file->functions[func_idx].address = (uint32_t)st_value;
            func_idx++;
        }
    }
}

void check_for_file_type(file_t * file){
    int elf[] = {0x7f,0x45,0x4c,0x46}; // 0x7f E L F (Linux)
    int pe[] = {0x4d,0x5a}; // M Z (Windows)

    int check = 0;
    for (int i = 0 ; i < 4;i++){
        if (file->values[i] == elf[i]) check +=1;
        else break;
    }
    if (check == 4){
        file->f_type = ELF;
        detect_elf_arch(file);
        parse_elf_sections(file);
        parse_elf_functions(file);
        return;
    }
    check = 0;  
    for (int i = 0 ; i<2 ; i++){
        if (file->values[i] == pe[i]) check +=1;
        else break;
    }
    if (check == 2){
        file->f_type = PE;
        detect_pe_arch(file);
        parse_pe_sections(file);
        parse_pe_functions(file);
        return;
    }
    file->f_type = UNKNOWN;
    file->arch = ARCH_UNKNOWN;
    file->bits = 0;
}


void display_file_info(file_t * file){
    printf("\n==== FILE INFORMATION ====\n");
    
    printf("File Size: %zu bytes\n", file->file_size);
    
    printf("File Type: ");
    switch (file->f_type) {
        case ELF: printf("ELF (Linux/Unix)\n"); break;
        case PE:  printf("PE (Windows)\n"); break;
        default:  printf("Unknown\n"); break;
    }
    
    printf("Architecture: ");
    switch (file->arch) {
        case ARCH_X86_32: printf("x86 (IA-32)\n"); break;
        case ARCH_X86_64: printf("x86-64\n"); break;
        case ARCH_ARM:    printf("ARM\n"); break;
        case ARCH_ARM64:  printf("ARM64 (AArch64)\n"); break;
        case ARCH_MIPS:   printf("MIPS\n"); break;
        case ARCH_RISCV:  printf("RISC-V\n"); break;
        case ARCH_IA64:   printf("IA-64\n"); break;
        default:          printf("Unknown\n"); break;
    }
    
    if (file->bits > 0) {
        printf("Bit Width: %d-bit\n", file->bits);
    }
    
    if (file->entry_address > 0) {
        printf("Entry Point: 0x%08x\n", file->entry_address);
    }
    
    printf("==========================\n\n");
}

void display_sections(file_t *file) {
    if (file->num_of_sections == 0) {
        printf("No sections found.\n\n");
        return;
    }
    
    printf("==== SECTIONS (%d) ====\n", file->num_of_sections);
    printf("%-16s %-10s %-10s %-10s %-10s %-8s\n", "Name", "Type", "VirtAddr", "Offset", "Size", "Flags");
    printf("------------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < file->num_of_sections; i++) {
        section_t *s = &file->sections[i];
        
        const char *type_str = "UNKNOWN";
        switch(s->type) {
            case SHT_NULL:     type_str = "NULL"; break;
            case SHT_PROGBITS: type_str = "PROGBITS"; break;
            case SHT_SYMTAB:   type_str = "SYMTAB"; break;
            case SHT_STRTAB:   type_str = "STRTAB"; break;
            case SHT_RELA:     type_str = "RELA"; break;
            case SHT_NOBITS:   type_str = "NOBITS"; break;
            case SHT_REL:      type_str = "REL"; break;
            case SHT_DYNSYM:   type_str = "DYNSYM"; break;
            case SHT_DYNAMIC:  type_str = "DYNAMIC"; break;
            case SHT_NOTE:     type_str = "NOTE"; break;
        }
        
        char flags[16] = "";
        if (s->flags & SEC_READ)  strcat(flags, "R");
        if (s->flags & SEC_WRITE) strcat(flags, "W");
        if (s->flags & SEC_EXEC)  strcat(flags, "X");
        if (s->flags & SEC_ALLOC) strcat(flags, "A");
        if (flags[0] == '\0') strcpy(flags, "-");
        
        printf("%-16s %-10s 0x%08x 0x%08x 0x%08x %-8s", 
               s->name, type_str, s->vaddr, s->raw_offset, s->raw_size, flags);
        
        if (s->data != NULL) {
            printf(" [VERIFICATION DONE]");
        }
        printf("\n");
    }
    
    printf("==========================\n\n");
}

void display_functions(file_t *file) {
    if (file->num_of_functions == 0) {
        printf("No exported functions found.\n\n");
        return;
    }
    
    printf("==== EXPORTED FUNCTIONS (%d) ====\n", file->num_of_functions);
    printf("%-50s %-12s %-12s\n", "Function Name", "RVA", "Address");
    printf("--------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < file->num_of_functions; i++) {
        function_t *f = &file->functions[i];
        printf("%-50s 0x%08x   0x%08x\n", f->name, f->rva, f->address);
    }
    
    printf("==========================\n\n");
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

    check_for_file_type(file);
    display_file_info(file);
    display_sections(file);
    display_functions(file);

    

    cpu_instruction cpu = {0};
    while (cpu.pc < file->file_size) {
        get_opcode(&cpu, file);
    }

    // Cleanup
    if (file->sections) {
        for (int i = 0; i < file->num_of_sections; i++) {
            if (file->sections[i].data) {
                free(file->sections[i].data);
            }
        }
        free(file->sections);
    }
    if (file->functions) {
        free(file->functions);
    }
    free(file->values);
    free(file);

    exit(EXIT_SUCCESS);
}