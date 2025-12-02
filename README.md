# Binary Disassembler

x86-64 binary disassembler supporting ELF and PE file formats.

## Features

Supports x86-64 instruction set including SSE, MMX, and system instructions.
Parses ELF and PE binary formats.
Displays file headers, sections, and exported functions.
Disassembles code sections with address tracking.

## Supported File Types

ELF (Executable and Linkable Format)
PE (Portable Executable)

## Supported Instructions

Over 200 x86-64 instructions including:
- Arithmetic: ADD, SUB, MUL, DIV, IMUL, IDIV
- Logical: AND, OR, XOR, NOT, NEG, TEST
- Data Movement: MOV, MOVZX, MOVSX, LEA, XCHG, PUSH, POP
- Control Flow: JMP, JE, JNE, JL, JG, CALL, RET
- Bit Operations: BT, BTC, BTR, BTS, BSF, BSR, SHL, SHR, SAL, SAR, ROL, ROR
- String Operations: MOVS, CMPS, SCAS, LODS, STOS, REP, REPE, REPNE
- System Instructions: SYSCALL, SYSRET, CPUID, RDTSC, RDMSR, WRMSR
- SSE Instructions: MOVUPS, MOVAPS, ADDPS, SUBPS, MULPS, DIVPS, ANDPS, ORPS, XORPS
- MMX Instructions: MOVQ, MOVD, PACKSSWB, PCMPGTB, PADDB, PSUBB, PMULLW
- Conditional Moves: CMOVO, CMOVNE, CMOVL, CMOVG, CMOVS, CMOVP
- Flag Instructions: LAHF, SAHF, PUSHF, POPF, CLC, STC, CMC, CLD, STD

## Usage

Compile the disassembler:
```
gcc -o reverse.exe reverse.c
```

Run with a binary file:
```
reverse.exe <binary_file>
```

Example:
```
reverse.exe a.out
```

## Output Format

The disassembler outputs three main sections:

File Information:
- File size
- File type (ELF or PE)
- Architecture (x86-64)
- Bit width (32-bit or 64-bit)
- Entry point address

Sections Table:
- Section name
- Section type
- Virtual address
- File offset
- Size
- Flags (Read/Write/Execute)

Exported Functions:
- Function name
- Relative Virtual Address (RVA)
- Absolute address

Disassembly:
- Memory address
- Raw bytes (hex)
- Instruction mnemonic
- Operands

## Technical Details

File Parsing:
- Reads binary files into memory
- Detects file format via magic bytes (ELF: 0x7F454C46, PE: 0x4D5A)
- Parses section headers and function tables

Instruction Decoding:
- Single-byte and two-byte opcode tables
- ModR/M and SIB byte decoding
- Prefix handling (REX, operand size, address size, segment override)
- Immediate value extraction

Architecture Support:
- x86-64 (64-bit)
- x86 (32-bit)
- Detection via ELF class or PE machine type

## Compilation

Requires C compiler with C99 support.
No external dependencies.

Standard compilation:
```
gcc -o reverse.exe reverse.c
```

With warnings:
```
gcc -Wall -Wextra -o reverse.exe reverse.c
```

## Limitations

Does not support ARM, MIPS, or other architectures.
Does not disassemble AVX/AVX2/AVX-512 instructions.
Does not perform control flow analysis.
Does not resolve symbols or relocations.
Limited support for instruction prefixes.



