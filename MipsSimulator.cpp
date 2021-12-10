// MipsSimulator.cpp : Defines the entry point for the console application.
//


#pragma warning(disable:4996)
#pragma GCC diagnostic ignored "-Wwrite-strings"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>

#define BUFFERSIZE                80
#define NUMBER_REGISTERS          32
#define NUMBER_INSTRUCTIONS       16
#define MAX_INSTRUCTIONS       32768
#define MAX_LABEL_SIZE            11
#define NUMBER_HEXDIGITS           8

enum instr_type { rtype = 'R', itype = 'I', jtype = 'J' };

typedef struct reg
{
    int      index;
    char     name[MAX_LABEL_SIZE];
    uint32_t value;
} reg;


typedef struct instruction
{
    int      number;
    char     name[MAX_LABEL_SIZE];
    char     type;
    uint32_t opcode;
    uint32_t funct;
} instruction;

instruction instructions[NUMBER_INSTRUCTIONS] =
{
    { -1, "addiu",   'I', 0x09, 0x00 },
    { -1, "addu",    'R', 0x00, 0x21 },
    { -1, "and",     'R', 0x00, 0x24 },
    { -1, "beq",     'I', 0x04, 0x00 },
    { -1, "bne",     'I', 0x05, 0x00 },
    { -1, "div",     'R', 0x00, 0x1A },
    { -1, "j",       'J', 0x02, 0x00 },
    { -1, "lw",      'I', 0x23, 0x00 },
    { -1, "mfhi",    'R', 0x00, 0x10 },
    { -1, "mflo",    'R', 0x00, 0x12 },
    { -1, "mult",    'R', 0x00, 0x18 },
    { -1, "or",      'R', 0x00, 0x25 },
    { -1, "slt",     'R', 0x00, 0x2A },
    { -1, "subu",    'R', 0x00, 0x23 },
    { -1, "sw",      'I', 0x2B, 0x00 },
    { -1, "syscall", 'R', 0x00, 0x0C }
};


typedef struct parameters
{
    uint32_t opcode;
    uint32_t rs;
    uint32_t rt;
    uint32_t rd;
    uint32_t shamt;
    uint32_t funct;
    uint32_t uimm;
    uint32_t simm;
    uint32_t addr;
} parameters;


typedef struct instruction_line
{
    char  type;
    int   numOperands;
    int   lineNumber;
    char  name[MAX_LABEL_SIZE];
    char  operand1[20];
    char  operand2[20];
    char  operand3[20];
} instruction_line;


//#define _CRT_SECURE_NO_WARNINGS 1
#pragma warning(disable:4996)

//
// declarations
//
int hexToBinStr(char *src, char *dst);
void strToHex(char *src, char *dst);
void binStrToHexStr(char *src, char *dst);
unsigned int binary_to_decimal(char *buff);
void decimal_to_binary(int n, char *buff, int numDigits);

//
//
//
int  getInstruction(instruction *instructions, instruction *instr, uint32_t opcode, uint32_t funct, int instrNumber);
reg *getRegister(char *str, reg *registers);
void setRegister(int index, char *name, uint32_t value, reg *ptrReg);
int  getIndexRegister(char *name, reg* ptrReg);
int  setValueInRegister(char *name, uint32_t value, reg *ptrReg);
reg *initRegisters();

//
//
//
instruction_line *setInstrArray(int numOfInstructions);
uint32_t *setWordsArray(int numOfWords);

//
//
//
int processRType(reg *regs, parameters *params, instruction_line *pInstrLine, instruction *instr);
int processIType(reg *regs, parameters *params, instruction_line *pInstrLine, instruction *instr);
int processJType(reg* regs, parameters* params, instruction_line* pInstrLine, instruction *instr);

int pass1(FILE *fpIn, FILE *fpOut, reg *regs, uint32_t *pWords, instruction *instructions, instruction_line *pInstrLine,
    int numOfInstructions, int numOfWords);

int execRType(reg *regs, instruction_line *pInstrLine, char instr_type, int *pc);
int execIType(reg *regs, instruction_line *pInstrLine, uint32_t *pWords, char instr_type, int *pc, int numOfInstr, int numOfWords);
int execJType(reg *regs, instruction_line *pInstrLine, char instr_type, int *pc, int numOfInstr);

//
//
//
void printParameters(FILE *fp, parameters *params);
void printRegValues(FILE *fp, reg *regs);
void printWordValues(FILE *fp, uint32_t *pWords, int numOfWords);

void printInstructionLine(FILE *fp, instruction_line *pInstrLine, int lineNumber, int numOfInstr, int flg);
void printAllInstructions(FILE *fp, instruction_line *pInstrLine, int numOfInstr);
void printAllData(FILE *fp, uint32_t *pWords, int numOfInstr, int numOfWords);





int hexToBinStr(char *src, char *dst)
{
    int k = 0;
    int isHex = 1;

    while (src[k])
    {
        if (!isxdigit(src[k]))
        {
            isHex = 0;
            break;
        }
        switch (src[k])
        {
        case '0':
            strcat(dst, "0000");
            break;
        case '1':
            strcat(dst, "0001");
            break;
        case '2':
            strcat(dst, "0010");
            break;
        case '3':
            strcat(dst, "0011");
            break;
        case '4':
            strcat(dst, "0100");
            break;
        case '5':
            strcat(dst, "0101");
            break;
        case '6':
            strcat(dst, "0110");
            break;
        case '7':
            strcat(dst, "0111");
            break;
        case '8':
            strcat(dst, "1000");
            break;
        case '9':
            strcat(dst, "1001");
            break;
        case 'a':
        case 'A':
            strcat(dst, "1010");
            break;
        case 'b':
        case 'B':
            strcat(dst, "1011");
            break;
        case 'c':
        case 'C':
            strcat(dst, "1100");
            break;
        case 'd':
        case 'D':
            strcat(dst, "1101");
            break;
        case 'e':
        case 'E':
            strcat(dst, "1110");
            break;
        case 'f':
        case 'F':
            strcat(dst, "1111");
            break;
        }
        k++;
    }

    return isHex;
}



void strToHex(char *src, char *dst)
{
    if (strcmp(src, "0000") == 0)
    {
        strcpy(dst, "0");
    }
    else if (strcmp(src, "0001") == 0)
    {
        strcpy(dst, "1");
    }
    else if (strcmp(src, "0010") == 0)
    {
        strcpy(dst, "2");
    }
    else if (strcmp(src, "0011") == 0)
    {
        strcpy(dst, "3");
    }
    else if (strcmp(src, "0100") == 0)
    {
        strcpy(dst, "4");
    }
    else if (strcmp(src, "0101") == 0)
    {
        strcpy(dst, "5");
    }
    else if (strcmp(src, "0110") == 0)
    {
        strcpy(dst, "6");
    }
    else if (strcmp(src, "0111") == 0)
    {
        strcpy(dst, "7");
    }
    else if (strcmp(src, "1000") == 0)
    {
        strcpy(dst, "8");
    }
    else if (strcmp(src, "1001") == 0)
    {
        strcpy(dst, "9");
    }
    else if (strcmp(src, "1010") == 0)
    {
        strcpy(dst, "a");
    }
    else if (strcmp(src, "1011") == 0)
    {
        strcpy(dst, "b");
    }
    else if (strcmp(src, "1100") == 0)
    {
        strcpy(dst, "c");
    }
    else if (strcmp(src, "1101") == 0)
    {
        strcpy(dst, "d");
    }
    else if (strcmp(src, "1110") == 0)
    {
        strcpy(dst, "e");
    }
    else if (strcmp(src, "1111") == 0)
    {
        strcpy(dst, "f");
    }
}


void binStrToHexStr(char *src, char *dst)
{
    char *pchar1, *pchar2 = NULL;
    char binbuf[5], hexbuf[5];

    pchar1 = src;
    for (int k = 0; k < NUMBER_HEXDIGITS; k++)
    {
        pchar2 = pchar1;
        pchar2 += 4;
        strncpy(binbuf, pchar1, 4);
        binbuf[4] = '\0';

        strToHex(binbuf, hexbuf);

        pchar1 += 4;
        strcat(dst, hexbuf);
    }
}


unsigned int binary_to_decimal(char *buff)
{
    int x = 0;
    int y = strlen(buff) - 1;

    unsigned int dec = 0;

    while (y >= 0)
    {
        if (buff[y] == '1')
        {
            dec += (unsigned int)pow(2, x);
        }
        x++;
        y--;
    }
    return dec;
}


void decimal_to_binary(int n, char *buff, int numDigits)
{
    int c, d, cnt;
    char *ptr = buff;

    cnt = 0;

    for (c = numDigits - 1; c >= 0; c--)
    {
        d = n >> c;

        if (d & 1)
            *(ptr + cnt) = 1 + '0';
        else
            *(ptr + cnt) = 0 + '0';

        cnt++;
    }
    *(ptr + cnt) = '\0';
}



int getInstruction(instruction *instructions, instruction *instr, uint32_t opcode, uint32_t funct, int instrNumber)
{
    int found = 0;

    instr->number = 0;
    memset(instr->name, 0, MAX_LABEL_SIZE * sizeof(char));
    instr->type = '\0';
    instr->opcode = 0;
    instr->funct = 0;

    for (int k = 0; k < NUMBER_INSTRUCTIONS; k++)
    {
        if (instructions[k].type == rtype)
        {
            if (opcode == instructions[k].opcode && funct == instructions[k].funct)
            {
                if (strcmp(instructions[k].name, "syscall") == 0)
                {
                    instr->number = instrNumber;
                    strcpy(instr->name, instructions[k].name);
                    instr->type = instructions[k].type;
                    instr->opcode = opcode;
                    instr->funct = funct;
                }
                else
                {
                    instr->number = instrNumber;
                    strcpy(instr->name, instructions[k].name);
                    instr->type = instructions[k].type;
                    instr->opcode = opcode;
                    instr->funct = funct;
                }
                found = 1;
                break;
            }
        }
        if (instructions[k].type == itype && opcode == instructions[k].opcode)
        {
            instr->number = instrNumber;
            strcpy(instr->name, instructions[k].name);
            instr->type = instructions[k].type;
            instr->opcode = opcode;
            instr->funct = funct;
            found = 1;
            break;
        }
        if (instructions[k].type == jtype && opcode == instructions[k].opcode)
        {
            instr->number = instrNumber;
            strcpy(instr->name, instructions[k].name);
            instr->type = instructions[k].type;
            instr->opcode = opcode;
            found = 1;
            break;
        }
    }

    return found;
}



reg *getRegister(char *str, reg *registers)
{
    reg *pReg = registers;

    for (int k = 0; k < NUMBER_REGISTERS + 2; k++)
    {
        if (strcmp(str, registers[k].name) == 0)
        {
            pReg += k;
            break;
        }
    }
    return pReg;
}


void setRegister(int index, char *name, uint32_t value, reg* ptrReg)
{
    ptrReg[index].index = index;
    strcpy(ptrReg[index].name, name);
    ptrReg[index].value = value;
}


int getIndexRegister(char *name, reg* ptrReg)
{
    int ndx = -1;
    int k;

    for (k = 0; k < NUMBER_REGISTERS + 2; k++)
    {
        if (strcmp(name, ptrReg[k].name) == 0)
        {
            ndx = k;
            break;
        }
    }

    return ndx;
}


int setValueInRegister(char *name, uint32_t value, reg* ptrReg)
{
    int ndx = -1;
    int k;

    for (k = 0; k < NUMBER_REGISTERS + 2; k++)
    {
        if (strcmp(name, ptrReg[k].name) == 0)
        {
            ptrReg[k].value = value;
            ndx = k;
            break;
        }
    }

    return ndx;
}


reg* initRegisters()
{
    reg* ptr = (reg*)malloc((NUMBER_REGISTERS + 2) * sizeof(reg));

    if (ptr == NULL)
    {
        return NULL;
    }

    setRegister(0, "$zero", 0, ptr);
    setRegister(1, "$at", 0, ptr);
    setRegister(2, "$v0", 0, ptr);
    setRegister(3, "$v1", 0, ptr);
    setRegister(4, "$a0", 0, ptr);
    setRegister(5, "$a1", 0, ptr);
    setRegister(6, "$a2", 0, ptr);
    setRegister(7, "$a3", 0, ptr);
    setRegister(8, "$t0", 0, ptr);
    setRegister(9, "$t1", 0, ptr);
    setRegister(10, "$t2", 0, ptr);
    setRegister(11, "$t3", 0, ptr);
    setRegister(12, "$t4", 0, ptr);
    setRegister(13, "$t5", 0, ptr);
    setRegister(14, "$t6", 0, ptr);
    setRegister(15, "$t7", 0, ptr);
    setRegister(16, "$s0", 0, ptr);
    setRegister(17, "$s1", 0, ptr);
    setRegister(18, "$s2", 0, ptr);
    setRegister(19, "$s3", 0, ptr);
    setRegister(20, "$s4", 0, ptr);
    setRegister(21, "$s5", 0, ptr);
    setRegister(22, "$s6", 0, ptr);
    setRegister(23, "$s7", 0, ptr);
    setRegister(24, "$t8", 0, ptr);
    setRegister(25, "$t9", 0, ptr);
    setRegister(26, "$k0", 0, ptr);
    setRegister(27, "$k1", 0, ptr);
    setRegister(28, "$gp", 0, ptr);
    setRegister(29, "$sp", 0, ptr);
    setRegister(30, "$fp", 0, ptr);
    setRegister(31, "$ra", 0, ptr);
    setRegister(32, "$lo", 0, ptr);
    setRegister(33, "$hi", 0, ptr);

    return ptr;
}


instruction_line *setInstrArray(int numOfInstr)
{
    instruction_line *pInstrLine;

    pInstrLine = (instruction_line*)malloc(numOfInstr * sizeof(instruction_line));
 
    if (pInstrLine != NULL)
    {
        for (int k = 0; k < numOfInstr; k++)
        {
            memset(&pInstrLine[k], 0, sizeof(instruction_line));
        }
    }

    return pInstrLine;
}


uint32_t *setWordsArray(int numOfWords)
{
    uint32_t *pWords = (uint32_t*)malloc(numOfWords * sizeof(uint32_t));

    if (pWords != NULL)
    {
        for (int k = 0; k < numOfWords; k++)
        {
            pWords[k] = 0;
        }
    }

    return pWords;
}



int processRType(reg *regs, parameters *params, instruction_line *pInstrLine, instruction *instr)
{
    int retVal = -1;
    int ndx = instr->number;

    if (instr->type == 'R')
    {
        // R type with 3 arguments
        if (strcmp(instr->name, "addu") == 0 ||
            strcmp(instr->name, "and") == 0 ||
            strcmp(instr->name, "or") == 0 ||
            strcmp(instr->name, "slt") == 0 ||
            strcmp(instr->name, "subu") == 0)
        {
            pInstrLine[ndx].type = instr->type;
            pInstrLine[ndx].lineNumber = ndx;
            strcpy(pInstrLine[ndx].name, instr->name);
            pInstrLine[ndx].numOperands = 3;
            strcpy(pInstrLine[ndx].operand1, regs[params->rd].name);
            strcpy(pInstrLine[ndx].operand2, regs[params->rs].name);
            strcpy(pInstrLine[ndx].operand3, regs[params->rt].name);
            retVal = 0;
        }

        // R type with 2 arguments
        if (strcmp(instr->name, "div") == 0 ||
            strcmp(instr->name, "mult") == 0)
        {
            pInstrLine[ndx].type = instr->type;
            pInstrLine[ndx].lineNumber = ndx;
            strcpy(pInstrLine[ndx].name, instr->name);
            pInstrLine[ndx].numOperands = 2;
            strcpy(pInstrLine[ndx].operand1, regs[params->rs].name);
            strcpy(pInstrLine[ndx].operand2, regs[params->rt].name);
            retVal = 0;
        }

        // R type with 1 arguments
        if (strcmp(instr->name, "mflo") == 0 ||
            strcmp(instr->name, "mfhi") == 0)
        {
            pInstrLine[ndx].type = instr->type;
            pInstrLine[ndx].lineNumber = ndx;
            strcpy(pInstrLine[ndx].name, instr->name);
            pInstrLine[ndx].numOperands = 1;
            strcpy(pInstrLine[ndx].operand1, regs[params->rd].name);
            retVal = 0;
        }

        // R type with 0 arguments
        if (strcmp(instr->name, "syscall") == 0)
        {
            pInstrLine[ndx].type = instr->type;
            pInstrLine[ndx].lineNumber = ndx;
            strcpy(pInstrLine[ndx].name, instr->name);
            pInstrLine[ndx].numOperands = 0;
            retVal = 0;
        }
    }

    return retVal;
}


int processIType(reg *regs, parameters *params, instruction_line *pInstrLine, instruction *instr)
{
    int retVal = -1;
    int ndx = instr->number;

    if (instr->type == itype)
    {
        if (strcmp(instr->name, "addiu") == 0)
        {
            pInstrLine[ndx].type = instr->type;
            pInstrLine[ndx].lineNumber = ndx;
            strcpy(pInstrLine[ndx].name, instr->name);
            pInstrLine[ndx].numOperands = 3;
            strcpy(pInstrLine[ndx].operand1, regs[params->rt].name);
            strcpy(pInstrLine[ndx].operand2, regs[params->rs].name);
            sprintf(pInstrLine[ndx].operand3, "%ld", params->simm);
            retVal = 0;
        }

        if (strcmp(instr->name, "bne") == 0 ||
            strcmp(instr->name, "beq") == 0)
        {
            pInstrLine[ndx].type = instr->type;
            pInstrLine[ndx].lineNumber = ndx;
            strcpy(pInstrLine[ndx].name, instr->name);
            pInstrLine[ndx].numOperands = 3;
            strcpy(pInstrLine[ndx].operand1, regs[params->rs].name);
            strcpy(pInstrLine[ndx].operand2, regs[params->rt].name);
            sprintf(pInstrLine[ndx].operand3, "%ld", params->simm);
            retVal = 0;
        }

        if (strcmp(instr->name, "lw") == 0 ||
            strcmp(instr->name, "sw") == 0)
        {
            pInstrLine[ndx].type = instr->type;
            pInstrLine[ndx].lineNumber = ndx;
            strcpy(pInstrLine[ndx].name, instr->name);
            pInstrLine[ndx].numOperands = 3;
            strcpy(pInstrLine[ndx].operand1, regs[params->rt].name);
            sprintf(pInstrLine[ndx].operand3, "%ld", params->simm);
            strcpy(pInstrLine[ndx].operand2, regs[params->rs].name);
            retVal = 0;
        }
    }

    return retVal;
}


int processJType(reg* regs, parameters* params, instruction_line* pInstrLine, instruction *instr)
{
    int retVal = -1;
    int ndx = instr->number;
    
    if (instr->type == jtype)
    {
        if (params->opcode == instr->opcode)
        {
            pInstrLine[ndx].type = instr->type;
            pInstrLine[ndx].lineNumber = instr->number;
            strcpy(pInstrLine[ndx].name, instr->name);
            pInstrLine[ndx].numOperands = 1;
            sprintf(pInstrLine[ndx].operand1, "%u", params->addr);
            retVal = 0;
        }
    }

    return retVal;
}



int pass1(FILE* fpIn, FILE* fpOut, reg* regs, uint32_t* pWords, instruction *instructions, instruction_line* pInstrLine,
    int numOfInstructions, int numOfWords)
{
    char       *ptr1;
    char        buffer[BUFFERSIZE];
    char        tmpBuff[BUFFERSIZE];
    int         len;
    int         instrNumber = 0;
    int         instrFlg = 1;
    int         dataFlg = 0;
    int         wordsCnt = 0;
    int         retval = 0;

    uint32_t    result;
    parameters  params;
    instruction instr;

    while (fgets(buffer, BUFFERSIZE, fpIn) != NULL)
    {
        // strip \n from input
        if ((ptr1 = strchr(buffer, '\n')) != NULL)
        {
            *ptr1 = '\0';
        }

        len = strlen(buffer);
        if (len != NUMBER_HEXDIGITS)
        {
            fprintf(stderr, "Invalid input");
            retval = 1;
            break;
        }

        memset(tmpBuff, '\0', sizeof(tmpBuff[0]));
        result = hexToBinStr(buffer, tmpBuff);

        if (result != 1)
        {
            fprintf(stderr, "Input contains non-Hex characters\n");
            retval = 1;
            break;
        }

        result = binary_to_decimal(tmpBuff);

        if (instrFlg == 1)
        {
            memset(&params, 0, sizeof(params));
            params.opcode = result >> 26;
            params.rs = (result >> 21) & 0x1F;
            params.rt = (result >> 16) & 0x1F;
            params.rd = (result >> 11) & 0x1F;
            params.shamt = (result >> 6) & 0x1F;
            params.funct = result & 0x3F;
            params.uimm = result & 0xFFFF;
            params.simm = result & 0xFFFF;
            params.addr = result & 0x3FFFFFF;
            
            if (getInstruction(instructions, &instr, params.opcode, params.funct, instrNumber) == 0)
            {
                fprintf(stderr, "Illegal Instruction\n");
                continue;
            }

            switch (instr.type)
            {
            case rtype:
                processRType(regs, &params, pInstrLine, &instr);
                break;
            case itype:
                processIType(regs, &params, pInstrLine, &instr);
                break;
            case jtype:
                processJType(regs, &params, pInstrLine, &instr);
                break;
            }

            if (instrNumber == numOfInstructions - 1)
            {
                instrFlg = 0;
                dataFlg = 1;
                continue;
            }
            instrNumber++;
        }

        if (dataFlg == 1)
        {
            pWords[wordsCnt] = result;
            wordsCnt++;
        }
    }

    return retval;
}




int execRType(reg *regs, instruction_line *pInstrLine, char instr_type, int *pc)
{
    if (instr_type != 'R')
    {
        return -1;
    }

    int       ndx1, ndx2, ndx3, ndx4;
    int       retval = -1;
    uint32_t  value;

    // R type with 3 arguments
    if (strcmp(pInstrLine->name, "addu") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);
        ndx3 = getIndexRegister(pInstrLine->operand3, regs);
        if (ndx3 != -1)
        {
            value = regs[ndx3].value;
        }
        else
        {
            // operand is a constant
            value = strtoul(pInstrLine->operand3, NULL, 10);
        }

        regs[ndx1].value = regs[ndx2].value + value;
        *pc += 1;
        retval = 0;
    }

    if (strcmp(pInstrLine->name, "slt") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);
        ndx3 = getIndexRegister(pInstrLine->operand3, regs);
        regs[ndx1].value = (regs[ndx2].value < regs[ndx3].value)? 1 : 0;
        *pc += 1;
        retval = 0;
    }

    if (strcmp(pInstrLine->name, "and") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);  // rd
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);  // rs
        ndx3 = getIndexRegister(pInstrLine->operand3, regs);  // rt
        regs[ndx1].value = regs[ndx2].value & regs[ndx3].value;
        *pc += 1;
        retval = 0;
    }

    if (strcmp(pInstrLine->name, "or") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);  // rd
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);  // rs
        ndx3 = getIndexRegister(pInstrLine->operand3, regs);  // rt
        regs[ndx1].value = regs[ndx2].value | regs[ndx3].value;
        *pc += 1;
        retval = 0;
    }

    if (strcmp(pInstrLine->name, "subu") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);  // rd
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);  // rs
        ndx3 = getIndexRegister(pInstrLine->operand3, regs);  // rt
        regs[ndx1].value = regs[ndx2].value - regs[ndx3].value;
        *pc += 1;
        retval = 0;
    }

    // R type with 2 arguments
    if (strcmp(pInstrLine->name, "div") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);  // rs
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);  // rt

        if (regs[ndx2].value != 0)
        {
            ndx3 = getIndexRegister("$lo", regs);
            ndx4 = getIndexRegister("$hi", regs);

            regs[ndx3].value = regs[ndx1].value / regs[ndx2].value;
            regs[ndx4].value = regs[ndx1].value % regs[ndx2].value;
            *pc += 1;
            retval = 0;
        }
        else
        {
            fprintf(stderr, "divide by zero\n");
        }
    }

    if (strcmp(pInstrLine->name, "mult") == 0)
    {
        int64_t longvalue;

        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);
        ndx3 = getIndexRegister("$lo", regs);
        ndx4 = getIndexRegister("$hi", regs);
        longvalue = regs[ndx1].value * regs[ndx2].value;
        regs[ndx3].value = longvalue & 0xFFFFFFFF;
        regs[ndx4].value = longvalue >> 32;

        *pc += 1;
        retval = 0;
    }

    // R type with 1 arguments
    if (strcmp(pInstrLine->name, "mflo") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx3 = getIndexRegister("$lo", regs);
        regs[ndx1].value = regs[ndx3].value;
        *pc += 1;
        retval = 0;
    }

    if (strcmp(pInstrLine->name, "mfhi") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx4 = getIndexRegister("$hi", regs);
        regs[ndx1].value = regs[ndx4].value;
        *pc += 1;
        retval = 0;
    }

    // R type with 0 arguments
    if (strcmp(pInstrLine->name, "syscall") == 0)
    {
        reg *pReg1, *pReg2;
        int value = 0;

        pReg1 = getRegister("$v0", regs);

        // System Call Code = 1
        // Print an integer value followed by a newline character to standard output
        // $a0 = integer
        // $v0 = 1
        if (pReg1->value == 1)
        {
            pReg2 = getRegister("$a0", regs);
            fprintf(stdout, "%d\n", pReg2->value);
            *pc += 1;
            retval = 0;
        }

        // System Call Code = 5
        // Read an integer value from standard input and assign the value to $v0
        if (pReg1->value == 5)
        {
            fscanf(stdin, "%d", &value);
            setValueInRegister("$v0", value, regs);
            *pc += 1;
            retval = 0;
        }

        // System Call Code = 10
        // exit simulation
        if (pReg1->value == 10)
        {
            retval = 1;
        }
    }

    return retval;
}


int execIType(reg* regs, instruction_line* pInstrLine, uint32_t *pWords, char instr_type, int *pc, int numOfInstr, int numOfWords)
{
    int ndx1, ndx2, ndx3;
    int value = 0;
    int retval = -1;

    reg *gp;

    if (instr_type != itype)
    {
        return -1;
    }

    if (strcmp(pInstrLine->name, "addiu") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);
        value = atoi(pInstrLine->operand3);
        regs[ndx1].value = regs[ndx2].value + value;
        *pc += 1;
        retval = 0;
    }

    if (strcmp(pInstrLine->name, "bne") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);
        value = atoi(pInstrLine->operand3);

        if (regs[ndx1].value != regs[ndx2].value)
        {
            *pc = *pc + value;
            if (*pc < 0 || *pc > numOfInstr)
            {
                fprintf(stderr, "Illegal Instruction Address\n");
                retval = -1;
            }
            else
            {
                retval = 0;
            }
        }
        else
        {
            *pc += 1;
            retval = 0;
        }
    }

    if (strcmp(pInstrLine->name, "beq") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);
        value = atoi(pInstrLine->operand3);
        
        if (regs[ndx1].value == regs[ndx2].value)
        {
            *pc = *pc + value;
            if (*pc < 0 || *pc > numOfInstr)
            {
                fprintf(stderr, "Illegal Instruction Address\n");
                retval = -1;
            }
            else
            {
                retval = 0;
            }
        }
        else
        {
            *pc += 1;
            retval = 0;
        }
    }

    if (strcmp(pInstrLine->name, "sw") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);
        ndx3 = regs[ndx2].value + atoi(pInstrLine->operand3);
        gp = getRegister("$gp", regs);
        ndx3 = ndx3 - gp->value;
        if (ndx3 > numOfWords)
        {
            fprintf(stderr, "Illegal Data Address\n");
            retval = -1;
        }
        else
        {
            pWords[ndx3] = regs[ndx1].value;
            *pc += 1;
            retval = 0;
        }
    }

    if (strcmp(pInstrLine->name, "lw") == 0)
    {
        ndx1 = getIndexRegister(pInstrLine->operand1, regs);
        ndx2 = getIndexRegister(pInstrLine->operand2, regs);
        ndx3 = regs[ndx2].value + atoi(pInstrLine->operand3);
        gp = getRegister("$gp", regs);
        ndx3 = ndx3 - gp->value;
        if (ndx3 > numOfWords)
        {
            fprintf(stderr, "Illegal Data Address\n");
            retval = -1;
        }
        else
        {
            regs[ndx1].value = pWords[ndx3];
            *pc += 1;
            retval = 0;
        }
    }

    return retval;
}



int execJType(reg *regs, instruction_line *pInstrLine, char instr_type,  int *pc, int numOfInstr)
{
    int retval = -1;
    int value;

    if (pInstrLine->type = jtype)
    {
        value = atoi(pInstrLine->operand1);
        *pc = value;
        if (*pc < 0 || *pc > numOfInstr)
        {
            fprintf(stderr, "Illegal Instruction Address\n");
            retval = -1;
        }
        else
        {
            retval = 0;
        }
    }

    return retval;
}



void printParameters(FILE *fp, parameters *params)
{
    fprintf(fp, "opcode: 0x%02X  ", params->opcode);
    fprintf(fp, "rs: %u  ", params->rs);
    fprintf(fp, "rt: %u  ", params->rt);
    fprintf(fp, "rd: %u  ", params->rd);
    fprintf(fp, "shamt: %u  ", params->shamt);
    fprintf(fp, "funct: 0x%02X  ", params->funct);
    fprintf(fp, "uimm: %u  ", params->uimm);
    fprintf(fp, "simm: %u  ", params->simm);
    fprintf(fp, "addr: %u\n", params->addr);
}


void printRegValues(FILE *fp, reg *regs)
{
    int k;
    fprintf(fp, "regs:\n");
    for (k = 0; k < NUMBER_REGISTERS; k = k + 4)
    {
        fprintf(fp, "%8s = %5u %7s = %5u %7s = %5u %7s = %5u\n",
            regs[k].name, regs[k].value,
            regs[k + 1].name, regs[k + 1].value,
            regs[k + 2].name, regs[k + 2].value,
            regs[k + 3].name, regs[k + 3].value);
    }
    fprintf(fp, "%8s = %5u %7s = %5u\n", regs[k].name, regs[k].value,
        regs[k + 1].name, regs[k + 1].value);
    fprintf(fp, "\n");
}


void printWordValues(FILE *fp, uint32_t *pWords, int numOfWords)
{
    fprintf(fp, "data memory:\n");

    for (int k = 0; k < numOfWords; k++)
    {
        fprintf(fp, "%7s[%3d] = %5u\n", "data", k, pWords[k]);
    }
    fprintf(fp, "\n");
}


void printInstructionLine(FILE *fp, instruction_line *pInstrLine, int lineNumber, int numberOfInstr, int flg)
{
    if (flg == 1)
    {
        fprintf(fp, "%4d: ", lineNumber);
    }
    if (flg == 2)
    {
        fprintf(fp, "inst: ");
    }

    switch (pInstrLine->numOperands)
    {
    case 0:
        fprintf(fp, "%s\n", pInstrLine->name);
        break;
    case 1:
        fprintf(fp, "%s\t%s\n", pInstrLine->name, pInstrLine->operand1);
        break;
    case 2:
        fprintf(fp, "%s\t%s,%s\n", pInstrLine->name, pInstrLine->operand1, pInstrLine->operand2);
        break;
    case 3:
        if (pInstrLine->type == 'I' && strcmp(pInstrLine->operand2, "$gp") == 0)
        {
            fprintf(fp, "%s\t%s,%s(%s)\n", pInstrLine->name, pInstrLine->operand1, pInstrLine->operand3, pInstrLine->operand2);
        }
        else
        {
            fprintf(fp, "%s\t%s,%s,%s\n", pInstrLine->name, pInstrLine->operand1, pInstrLine->operand2, pInstrLine->operand3);
        }
        break;
    }
    if (flg == 2 && lineNumber != numberOfInstr - 1)
    {
        fprintf(fp, "\n");
    }
}


void printAllInstructions(FILE *fp, instruction_line *pInstrLines, int numOfInstr)
{
    fprintf(fp, "insts:\n");

    for (int k = 0; k < numOfInstr; k++)
    {
        printInstructionLine(fp, &pInstrLines[k], k, numOfInstr, 1);
    }
    fprintf(fp, "\n");
}


void printAllData(FILE *fp, uint32_t *pWords, int numOfInstr, int numOfWords)
{
    fprintf(fp, "data:\n");

    for (int k = 0; k < numOfWords; k++)
    {
        fprintf(fp, "%4d: %x\n", numOfInstr + k, pWords[k]);
    }
}



int main(int argc, char *argv[])
{
    FILE             *fpIn = NULL;
    FILE             *fpOut = NULL;
    char             *ptr1 = NULL;
    instruction_line *pInstrLines = NULL;
    uint32_t         *pWords = NULL;

    char         fileIn[BUFFERSIZE];
    char         fileOut[BUFFERSIZE];
    char         buffer[BUFFERSIZE];
    int          retval = 0;

    int numOfWords = 0;
    int numOfInstructions = 0;
    int PC = 0;

    if (argc != 2)
    {
        fprintf(stderr, "usage: mips.exe <name>.obj\n");
        exit(1);
    }

    memset(fileIn, BUFFERSIZE, sizeof(char));
    strcpy(fileIn, argv[1]);
    strcpy(fileOut, "log.txt");

    fpIn = fopen(fileIn, "r");
    if (fpIn == NULL)
    {
        fprintf(stderr, "Unable to find input file %s\n", fileIn);
        return 1;
    }

    fpOut = fopen(fileOut, "w");
    if (fpOut == NULL)
    {
        fprintf(stderr, "Unable to create output file %s\n", fileOut);
        return 1;
    }

    if (fgets(buffer, BUFFERSIZE, fpIn) == NULL)
    {
        fprintf(stderr, "Input file is empty\n");
        return 1;
    }

    // get numOfInstructions and numOfWords from input
    sscanf(buffer, "%d %d", &numOfInstructions, &numOfWords);

    if (numOfInstructions > MAX_INSTRUCTIONS || numOfWords > MAX_INSTRUCTIONS)
    {
        fprintf(stderr, "Max Instructions or Words exceeded\n");
        exit(1);
    }

    pWords = setWordsArray(numOfWords);
    if (pWords == NULL)
    {
        fprintf(stderr, "Memory not allocated\n");
        exit(1);
    }

    pInstrLines = setInstrArray(numOfInstructions);
    if (pInstrLines == NULL)
    {
        fprintf(stderr, "Memory not allocated\n");
        exit(1);
    }

    reg* regs = initRegisters();
    setValueInRegister("$gp", numOfInstructions, regs);

    // pass 1
    retval = pass1(fpIn, fpOut, regs, pWords, instructions, pInstrLines, numOfInstructions, numOfWords);
    if (retval == 1)
    {
        exit(1);
    }

    printAllInstructions(fpOut, pInstrLines, numOfInstructions);
    printAllData(fpOut, pWords, numOfInstructions, numOfWords);

    // pass 2
    while (retval == 0)
    {
        fprintf(fpOut, "\n");
        fprintf(fpOut, "PC: %d\n", PC);
        printInstructionLine(fpOut, &pInstrLines[PC], PC, numOfInstructions, 2);

        switch (pInstrLines[PC].type)
        {
        case rtype:
            retval = execRType(regs, &pInstrLines[PC], rtype, &PC);
            break;
        case itype:
            retval = execIType(regs, &pInstrLines[PC], pWords, itype, &PC, numOfInstructions, numOfWords);
            break;
        case jtype:
            retval = execJType(regs, &pInstrLines[PC], jtype, &PC, numOfInstructions);
            break;
        }
        if (retval == 0)
        {
            printRegValues(fpOut, regs);
            printWordValues(fpOut, pWords, numOfWords);
        }
    }

     fprintf(fpOut, "exiting simulator\n");

    // free dynamically allocated memory
    free(pWords);
    free(pInstrLines);
    free(regs);

    return 0;
}
