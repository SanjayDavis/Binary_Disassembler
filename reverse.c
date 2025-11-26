#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

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

typedef struct {
    size_t file_size;
    uint8_t * values;
    enum file_type f_type;
    enum architecture arch;
    uint8_t bits;
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

    printf("%04zx: %02x   %s (bytes: %d)\n", cpu->pc, op, ins.mnemonic, ins.pc_increment);
    cpu->pc += ins.pc_increment;
}


void detect_elf_arch(file_t *file) {
    uint8_t elf_class = file->values[4];
    uint16_t machine = *(uint16_t*)&file->values[0x12];

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

    

    cpu_instruction cpu = {0};
    while (cpu.pc < file->file_size) {
        get_opcode(&cpu, file);
    }


    exit(EXIT_SUCCESS);
}