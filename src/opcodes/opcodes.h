/* 
 * Polyvaccine a Polymorphic exploit detection engine.
 *                                                              
 * Copyright (C) 2009  Luis Campo Giralte 
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <camp0@gmail.com> 2009 
 *
 */

#ifndef _OPCODES_H_
#define _OPCODES_H_

enum {
	IA32_OPCODE_TYPES = 0,
	IA64_OPCODE_TYPES
};

struct ST_Opcode {
   	char *opcode;          /* the operation code */
   	int len;          	/* length of code */
	char *instruction;
	int matchs;
	struct ST_Opcode *op_table; /* extended table for indirections */
};
typedef struct ST_Opcode ST_Opcode;

struct ST_Lookup {
	ST_Opcode *opt;
	char *name;
	int items;
	int arch; // IA32_OPCODE_TYPES,IA64_OPCODE_TYPES;
};
typedef struct ST_Lookup ST_Lookup;

#define IA32_JUMPS 43 
static ST_Opcode ST_Intel32_JumpOpcodes[IA32_JUMPS] = {
	{ "\xe1",1,		"Loope rel8"	,0 ,NULL},		/* LOOPE rel8, LOOPZ rel8  */
   	{ "\xe2",1,		"Loop rel8"	,0 ,NULL},         /* LOOP rel8 */
   	{ "\xe0",1,		"Loopne rel8"	,0 ,NULL},         /* LOOPNE rel8, LOOPNZ rel8 */
   	{ "\xe9",1,		"Jmp rel8"	,0 ,NULL},         /* jmp */
	{ "\xeb",1,		"Jmp rel8"	,0 ,NULL},		/* JMP rel8 */
   	{ "\xea",1,		"Jmp"		,0 ,NULL},         /* jmp */
   	{ "\x9a",1,		"Call"		,0 ,NULL},         /* call puede ser con 4 o 6 de tamaño */
	{ "\xe8",1,		"Call rel16"	,0 ,NULL},		/* CALL rel16 */
	{ "\x9a",1,		"Call ptr16:16"	,0 ,NULL},		/* CALL ptr16:16 */
	{ "\x77",1,		"Ja rel8"	,0 ,NULL},		/* JA rel8, JNBE rel8 */
	{ "\x73",1,		"Jae rel8"	,0 ,NULL},		/* JAE rel8, JNB rel8, JNC rel8 */
	{ "\x72",1,		"Jb rel8"	,0 ,NULL},		/* JB rel8 , JC rel8, JNAE rel8 */
	{ "\x76",1,		"Jbe rel8"	,0 ,NULL},		/* JBE rel8 , JNA rel8 */
	{ "\xe3",1,		"Jcxz rel8"	,0 ,NULL},		/* JCXZ rel8 ,JECXZ rel8 */
	{ "\x74",1,		"Je rel8"	,0 ,NULL},		/* JE rel8, JZ rel8,  */
	{ "\x7f",1,		"Jg rel8"	,0 ,NULL},		/* JG rel8, JNLE rel8 */
	{ "\x7d",1,		"Jge rel8"	,0 ,NULL},		/* JGE rel8, JNL rel8 */
	{ "\x7c",1,		"Jl rel8"	,0 ,NULL},		/* JL rel8, JNGE rel8  */
	{ "\x7e",1,		"Jle rel8"	,0 ,NULL},		/* JLE rel8, JNG rel8 */
	{ "\x75",1,		"Jne rel8"	,0 ,NULL},		/* JNE rel8, JNZ rel8 */
	{ "\x71",1,		"Jno rel8"	,0 ,NULL},		/* JNO rel8 */
	{ "\x7b",1,		"Jnp rel8"	,0 ,NULL},		/* JNP rel8, JPO rel8  */
	{ "\x79",1,		"Jns rel8"	,0 ,NULL},		/* JNS rel8 */
	{ "\x70",1,		"Jo rel8"	,0 ,NULL},		/* JO rel8 */
	{ "\x7a",1,		"Jp rel8"	,0 ,NULL},		/* JP rel8, JPE rel8 */ 
/* 26*/	{ "\x78",1,		"Js rel8"	,0 ,NULL},		/* JS rel8 */
  	{ "\x0f\x87",2,		"Ja rel16"	,0 ,NULL},		/* JA rel16/32, JNBE rel16/32 */ 
  	{ "\x0f\x83",2,		"Jae rel16"	,0 ,NULL},		/* JAE rel16/32, JNB rel16/32, JNC rel16/32 */ 
  	{ "\x0f\x82",2,		"Jb rel16"	,0 ,NULL},		/* JB rel16/32, JC rel16, JNAE rel16/32 */ 
  	{ "\x0f\x86",2,		"Jbe rel16"	,0 ,NULL},		/* JBE rel16/32, JNA rel16/32 */ 
  	{ "\x0f\x84",2,		"Je rel16"	,0 ,NULL},		/* JE rel16/32, JZ rel16/32  */ 
  	{ "\x0f\x8f",2,		"Jg rel16"	,0 ,NULL},		/* JG rel16/32, JNLE rel16/32 */ 
  	{ "\x0f\x8d",2,		"Jge rel16"	,0 ,NULL},		/* JGE rel16/32, JNL rel16/32 */ 
  	{ "\x0f\x8c",2,		"Jl rel16"	,0 ,NULL},		/* JL rel16/32, JNGE rel16/32 */ 
  	{ "\x0f\x8e",2,		"Jle rel16"	,0 ,NULL},		/* JLE rel16/32, JNG rel16/32 */ 
  	{ "\x0f\x8f",2,		"Jg rel16"	,0 ,NULL},		/* JG rel16/32 */ 
  	{ "\x0f\x85",2,		"Jne rel16"	,0 ,NULL},		/* JNE rel16/32, JNZ rel16/32 */ 
  	{ "\x0f\x81",2,		"Jno rel16"	,0 ,NULL},		/* JNO rel16/32 */ 
  	{ "\x0f\x8b",2,		"Jnp rel16"	,0 ,NULL},		/* JNP rel16/32, JPO rel16/32 */ 
  	{ "\x0f\x89",2,		"Jns rel16"	,0 ,NULL},		/* JNS rel16/32,  */ 
  	{ "\x0f\x80",2,		"Jo rel16"	,0 ,NULL},		/* JO rel16/32,  */ 
  	{ "\x0f\x8a",2,		"Jp rel16"	,0 ,NULL},		/* JP rel16/32, JPE rel16/32 */ 
/* 43*/	{ "\x0f\x88",2,		"Js rel16"	,0 ,NULL}		/* JS rel16/32 */ 
};
/* las instrucciones de salto en intel son:
http://pdos.csail.mit.edu/6.828/2007/readings/i386/Jcc.htm
*/

/* This table is for indirections */
#define IA32_INDIRECT_OPCODES 58 
static ST_Opcode ST_Intel32_IndirectOpcodes[IA32_INDIRECT_OPCODES] = {
        { "\x03",1,	"mov (%ebx),%eax",	0,NULL }, /* 8b 03                   mov    (%ebx),%eax */
        { "\x1b",1,	"mov (%ebx),%ebx",	0,NULL }, /* 8b 1b                   mov    (%ebx),%ebx */
        { "\x0b",1,	"mov (%ebx),%ecx",	0,NULL }, /* 8b 0b                   mov    (%ebx),%ecx */
        { "\x13",1,	"mov (%ebx),%edx",	0,NULL }, /* 8b 13                   mov    (%ebx),%edx */
        { "\x00",1,	"mov (%eax),%eax",	0,NULL }, /* 8b 00                   mov    (%eax),%eax */
        { "\x18",1,	"mov (%eax),%ebx",	0,NULL }, /* 8b 18                   mov    (%eax),%ebx */
        { "\x08",1, 	"mov (%eax),%ecx",     	0,NULL }, /* 8b 08                   mov    (%eax),%ecx */
        { "\x10",1, 	"",     0,NULL     }, /* 8b 10                   mov    (%eax),%edx */
        { "\x01",1,  	"",     0,NULL    }, /* 8b 01                   mov    (%ecx),%eax */
        { "\x19",1,  	"",     0,NULL    }, /* 8b 19                   mov    (%ecx),%ebx */
        { "\x09",1, 	"",     0,NULL     }, /* 8b 09                   mov    (%ecx),%ecx */
        { "\x11",1,   	"",     0,NULL   }, /* 8b 11                   mov    (%ecx),%edx */
        { "\x02",1,   	"",     0,NULL   }, /* 8b 02                   mov    (%edx),%eax */
        { "\x1a",1,	"",     0,NULL      }, /* 8b 1a                   mov    (%edx),%ebx */
        { "\x0a",1,	"",     0,NULL      }, /* 8b 0a                   mov    (%edx),%ecx */
        { "\x12",1,	"",     0,NULL      }, /* 8b 12                   mov    (%edx),%edx */
        { "\x45",1,	"",     0,NULL      }, /* 8b 45 00                mov    0x0(%ebp),%eax */
        { "\x5d",1,	"",     0,NULL      }, /* 8b 5d 00                mov    0x0(%ebp),%ebx */
        { "\x4d",1,	"",     0,NULL      }, /* 8b 4d 00                mov    0x0(%ebp),%ecx */
/*20*/  { "\x55",1,	"",     0,NULL      }, /* 8b 55 00                mov    0x0(%ebp),%edx */
        { "\x24",1,	"",     0,NULL      }, /* 8b 04 24                mov    (%esp),%eax */
        { "\x58",1,	"",     0,NULL      }, /* 31 58 0c                xor    %ebx,0xc(%eax) */
        { "\x5b",1,	"",     0,NULL      }, /* 31 5b 0c                xor    %ebx,0xc(%ebx) */
        { "\x51",1,	"",     0,NULL      }, /* 31 51 0c                xor    %edx,0xc(%ecx) */
        { "\x61",1,	"",     0,NULL      }, /* 31 61 02                xor    %esp,0x2(%ecx) */
        { "\x52",1,	"",     0,NULL      }, /* 31 52 0c                xor    %edx,0xc(%edx) */
        { "\x62",1,	"",     0,NULL      }, /* 31 62 02                xor    %esp,0x2(%edx) */
/*28*/  { "\x6a",1,	"",     0,NULL      }, /* 31 6a 02                xor    %ebp,0x2(%edx) */
        { "\x44\x0d",2,"",     0,NULL  }, /* 8b 44 0d 00             mov    0x0(%ebp,%ecx,1),%eax */
/*30*/  { "\x5c\x0d",2,"",     0,NULL  }, /* 8b 5c 0d 00             mov    0x0(%ebp,%ecx,1),%ebx */
        { "\x4c\x0d",2,"",     0,NULL  }, /* 8b 4c 0d 00             mov    0x0(%ebp,%ecx,1),%ecx */
        { "\x54\x0d",2,}, /* 8b 54 0d 00             mov    0x0(%ebp,%ecx,1),%edx */
        { "\x04\x0c",2,}, /* 8b 04 0c                mov    (%esp,%ecx,1),%eax */
        { "\x1c\x0c",2,}, /* 8b 1c 0c                mov    (%esp,%ecx,1),%ebx */
        { "\x0c\x0c",2,}, /* 8b 0c 0c                mov    (%esp,%ecx,1),%ecx */
        { "\x14\x0c",2,}, /* 8b 14 0c                mov    (%esp,%ecx,1),%edx */
        { "\x54\x0c",2,}, /* 8b 54 0c 02             mov    0x2(%esp,%ecx,1),%edx */
        { "\x04\x0a",2,}, /* 8b 04 0a                mov    (%edx,%ecx,1),%eax */
        { "\x1c\x0a",2,}, /* 8b 1c 0a                mov    (%edx,%ecx,1),%ebx */
/*40*/  { "\x0c\x0a",2,}, /* 8b 0c 0a                mov    (%edx,%ecx,1),%ecx */
        { "\x14\x0a",2,}, /* 8b 14 0a                mov    (%edx,%ecx,1),%edx */
        { "\x54\x0a",2,}, /* 8b 54 0a 02             mov    0x2(%edx,%ecx,1),%edx */
        { "\x04\x0e",2,}, /* 8b 04 0e                mov    (%esi,%ecx,1),%eax */
        { "\x1c\x0e",2,}, /* 8b 1c 0e                mov    (%esi,%ecx,1),%ebx */
        { "\x0c\x0e",2,}, /* 8b 0c 0e                mov    (%esi,%ecx,1),%ecx */
        { "\x14\x0e",2,}, /* 8b 14 0e                mov    (%esi,%ecx,1),%edx */
        { "\x54\x0e",2,}, /* 8b 54 0e 02             mov    0x2(%esi,%ecx,1),%edx */
        { "\x07",1,    }, /* 8b 07                   mov    (%edi),%eax */
        { "\x1f",1,    }, /* 8b 1f                   mov    (%edi),%ebx */
/*50*/  { "\x0f",1,    }, /* 8b 0f                   mov    (%edi),%ecx */
        { "\x47",1,    }, /* 8b 47 02                mov    0x2(%edi),%eax */
        { "\x5f",1,    }, /* 8b 5f 08                mov    0x8(%edi),%ebx */
        { "\x4f",1,    }, /* 8b 4f 10                mov    0x10(%edi),%ecx */
        { "\x57",1,    }, /* 8b 57 20                mov    0x20(%edi),%edx */
        { "\x06",1,    }, /* 8b 06                   mov    (%esi),%eax */
        { "\x1e",1,    }, /* 8b 1e                   mov    (%esi),%ebx */
        { "\x0e",1,    }, /* 8b 0e                   mov    (%esi),%ecx */
        { "\x16",1,    }  /* 8b 16                   mov    (%esi),%edx */
};

#define IA32_OPERATION_OPCODES 18
static ST_Opcode ST_Intel32_OperationOpcodes[IA32_OPERATION_OPCODES] = {
        { "\x8b",1,	"mov",	0,	&ST_Intel32_IndirectOpcodes }, /* mov */ /* 1000 1000 */
        { "\x89",1,	"mov",	0,	&ST_Intel32_IndirectOpcodes }, /* mov */
        { "\x01",1,	"add",	0,	&ST_Intel32_IndirectOpcodes }, /* add */
        { "\x03",1,	"add",	0,	&ST_Intel32_IndirectOpcodes }, /* add */
        { "\x29",1,	"sub",	0,	&ST_Intel32_IndirectOpcodes }, /* sub */
        { "\x2b",1,	"sub",	0,	&ST_Intel32_IndirectOpcodes }, /* sub */
        { "\x11",1,	"adc",	0,	&ST_Intel32_IndirectOpcodes }, /* adc */ /* 0001 0001 */
        { "\x13",1,	"adc",	0,	&ST_Intel32_IndirectOpcodes }, /* adc */ /* 0001 0011 */
        { "\x21",1,	"and",	0,	&ST_Intel32_IndirectOpcodes }, /* and */ /* 0010 0001 */
/*10*/  { "\x23",1,    	"and",	0,	&ST_Intel32_IndirectOpcodes }, /* and */
        { "\x87",1,	"xchg",	0,	&ST_Intel32_IndirectOpcodes }, /* xchg */
        { "\x19",1,	"sbb",	0,	&ST_Intel32_IndirectOpcodes }, /* sbb */
        { "\x1b",1,	"sbb",	0,	&ST_Intel32_IndirectOpcodes }, /* sbb */
        { "\x0f\x0a",2,	"imul",	0,	&ST_Intel32_IndirectOpcodes }, /* 0f af 01                imul   (%ecx),%eax */
        { "\x09",1,	"or",	0,	&ST_Intel32_IndirectOpcodes }, /* or */
        { "\x0b",1,	"or",	0,	&ST_Intel32_IndirectOpcodes }, /* or */
        { "\x31",1,	"or",	0,	&ST_Intel32_IndirectOpcodes }, /* xor */
        { "\x33",1,	"xor",	0,	&ST_Intel32_IndirectOpcodes } /* xor */
};

#define IA32_SPECIAL_OPCODES 1
static ST_Opcode ST_Intel32_specialOpcodes[IA32_SPECIAL_OPCODES] = {
	{ "\xcd\x80",2,	"int80",	0,	NULL}
};

#define IA64_SPECIAL_OPCODES 1
static ST_Opcode ST_Intel64_specialOpcodes[IA64_SPECIAL_OPCODES] = {
	{ "\x0f\x55",2,	"int80",	0,	NULL}
};

/* Final lookup table */
#define MAX_LOOKUP_ITEMS 3
static ST_Lookup ST_LookupOpcodeTable [MAX_LOOKUP_ITEMS] = {
	{&ST_Intel64_specialOpcodes,	"64 bits syscall", 	IA64_SPECIAL_OPCODES, 	IA64_OPCODE_TYPES },
	{&ST_Intel32_specialOpcodes, 	"32 bits syscall",	IA32_SPECIAL_OPCODES, 	IA32_OPCODE_TYPES },	
	{&ST_Intel32_JumpOpcodes,	"32 bits jumps",	IA32_JUMPS,		IA32_OPCODE_TYPES }
};


#endif 
