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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2009 
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
	char *name;
	ST_Opcode *op_table;
	int arch; // IA32_OPCODE_TYPES,IA64_OPCODE_TYPES;
};
typedef struct ST_Lookup ST_Lookup;

#define IA32_JUMPS 43 
static ST_Opcode ST_Intel32_JumpOpcodes[IA32_JUMPS] = {
	{ 
		.opcode 	=	"\xe1", 	/* LOOPE rel8, LOOPZ rel8  */
		.len		=	1,		
		.instruction	=	"Loope rel8, LOOPZ rel8",
		.matchs		=	0, 
		.op_table	=	NULL
	},	
   	{ 
		.opcode		=	"\xe2",
		.len		=	1,
		.instruction	=	"Loop rel8",
		.matchs		=	0,
		.op_table	=	NULL
	},         /* LOOP rel8 */
   	{
		.opcode		=	"\xe0" ,
		.len		=	1 ,
		.instruction	=	"Loopne rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\xe9" ,
		.len		=	1 ,
		.instruction	=	"Jmp rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\xeb" ,
		.len		=	1 ,
		.instruction	=	"Jmp rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\xea" ,
		.len		=	1 ,
		.instruction	=	"Jmp" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x9a" ,
		.len		=	1 ,
		.instruction	=	"Call" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\xe8" ,
		.len		=	1 ,
		.instruction	=	"Call rel16" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x9a" ,
		.len		=	1 ,
		.instruction	=	"Call ptr16:16" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x77" ,
		.len		=	1 ,
		.instruction	=	"Ja rel8, JNBE rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x73" ,
		.len		=	1 ,
		.instruction	=	"Jae rel8, JNB rel8, JNC rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x72" ,
		.len		=	1 ,
		.instruction	=	"Jb rel8, JC rel8, JNAE rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x76" ,
		.len		=	1 ,
		.instruction	=	"Jbe rel8, JNA rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\xe3" , /* JCXZ rel8 ,JECXZ rel8 */
		.len		=	1 ,
		.instruction	=	"Jcxz rel8 ,JECXZ rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x74" ,
		.len		=	1 ,
		.instruction	=	"Je rel8, JZ rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x7f" ,
		.len		=	1 ,
		.instruction	=	"Jg rel8 , JNLE rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x7d" ,
		.len		=	1 ,
		.instruction	=	"Jge rel8, , JNL rel" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x7c" ,
		.len		=	1 ,
		.instruction	=	"Jl rel8, , JNGE rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x7e" ,
		.len		=	1 ,
		.instruction	=	"Jle rel8, , JNG rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x75" ,
		.len		=	1 ,
		.instruction	=	"Jne rel8 , JNZ rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{
		.opcode		=	"\x71" ,
		.len		=	1 ,
		.instruction	=	"Jno rel8" ,
		.matchs		=	0,
		.op_table	=	NULL
	},
	{	
                .opcode         =       "\x7b" ,
                .len            =       1 ,
                .instruction    =       "Jnp rel8 , JPO rel8" ,
                .matchs         =       0,
                .op_table       =       NULL
	},
	{
                .opcode         =       "\x79" ,
                .len            =       1 ,
                .instruction    =       "Jns rel8 " ,
                .matchs         =       0,
                .op_table       =       NULL
	},
	{
                .opcode         =       "\x70" ,
                .len            =       1 ,
                .instruction    =       "Jo rel8" ,
                .matchs         =       0,
                .op_table       =       NULL
	},
	{
                .opcode         =       "\x7a" ,
                .len            =       1 ,
                .instruction    =       "Jp rel8 , JPE rel8" ,
                .matchs         =       0,
                .op_table       =       NULL
	},
	{
                .opcode         =       "\x78" ,
                .len            =       1 ,
                .instruction    =       "Js rel8 " ,
                .matchs         =       0,
                .op_table       =       NULL
	},
	{	
                .opcode         =       "\x0f\x87" ,
                .len            =       2 ,
                .instruction    =       "JA rel16/32, JNBE rel16/32 " ,
                .matchs         =       0,
                .op_table       =       NULL
	},
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
static ST_Opcode ST_Intel32_IndirectOpcodes[] = {
        { 
		.opcode		=	"\x03",
		.len		=	1,
		.instruction	=	"mov (%ebx),%eax", /* 8b 03                   mov    (%ebx),%eax */
		.matchs		=	0,
		.op_table	=	NULL 
	}, 
        { 
		.opcode		=	"\x1b",
		.len		=	1,
		.instruction	=	"mov (%ebx),%ebx",/* 8b 1b                   mov    (%ebx),%ebx */	
		.matchs		=	0,
		.op_table	=	NULL 
	}, 
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
        { "\x16",1,    },  /* 8b 16                   mov    (%esi),%edx */
	{}
};

static ST_Opcode ST_Intel32_OperationOpcodes[] = {
        { 
		.opcode		=	"\x8b",
		.len		=	1,
		.instruction	=	"mov",/* mov */ /* 1000 1000 */	
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, 
        { 
		.opcode		=	"\x89",
		.len		=	1,
		.instruction	=	"mov",
		.matchs		=	0,	
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, 
        { 
		.opcode		=	"\x01",
		.len		=	1,
		.instruction	=	"add",
		.matchs		=	0,	
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, 
        { 
		.opcode		=	"\x03",
		.len		=	1,
		.instruction	=	"add",
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0])
	}, 
        { 
		.opcode		=	"\x29",
		.len		=	1,	
		.instruction	=	"sub",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, /* sub */
        { 
		.opcode		=	"\x2b",
		.len		=	1,
		.instruction	=	"sub",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, /* sub */
        { 
		.opcode		=	"\x11",
		.len		=	1,	
		.instruction	=	"adc",
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, /* adc */ /* 0001 0001 */
        { 
		.opcode		=	"\x13",
		.len		=	1,
		.instruction	=	"adc",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, /* adc */ /* 0001 0011 */
        { 
		.opcode		=	"\x21",
		.len		=	1,
		.instruction	=	"and",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0])
	}, /* and */ /* 0010 0001 */
	{ 
		.opcode		=	"\x23",
		.len		=	1,
		.instruction	=    	"and",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0])
	}, /* and */
        { 
		.opcode		=	"\x87",
		.len		=	1,
		.instruction	=	"xchg",	
		.matchs		=	0,	
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0])
	}, /* xchg */
        { 
		.opcode		=	"\x19",
		.len		=	1,
		.instruction	=	"sbb",
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0])
	}, /* sbb */
        { 
		.opcode		=	"\x1b",
		.len		=	1,
		.instruction	=	"sbb",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, /* sbb */
        { "\x0f\x0a",2,	"imul",	0,	&ST_Intel32_IndirectOpcodes }, /* 0f af 01                imul   (%ecx),%eax */
        { "\x09",1,	"or",	0,	&ST_Intel32_IndirectOpcodes }, /* or */
        { "\x0b",1,	"or",	0,	&ST_Intel32_IndirectOpcodes }, /* or */
        { "\x31",1,	"or",	0,	&ST_Intel32_IndirectOpcodes }, /* xor */
        { 
		.opcode		=	"\x33",
		.len		=	1,	
		.instruction	=	"xor",	
		.matchs		=	0,	
		.op_table	=	&(ST_Intel32_IndirectOpcodes[0]) 
	}, /* xor */
	{}
};

static ST_Opcode ST_Intel32_specialOpcodes[] = {
	{ 
		.opcode		=	"\xcd\x80",
		.len		=	2,
		.instruction	=	"int80",	
		.matchs		=	0,
		.op_table	=	NULL
	},
	{}
};

static ST_Opcode ST_Intel64_specialOpcodes[] = {
	{ 
		.opcode		=	"\x0f\x55",
		.len		=	2,	
		.instruction	=	"int80",
		.matchs		=	0,
		.op_table	=	NULL
	},
	{}
};

/* Final lookup table */
static ST_Lookup ST_LookupOpcodeTable [] = {
	{
		.name		=	"64 bits syscall",
		.op_table	= 	ST_Intel64_specialOpcodes,
		.arch		=	IA64_OPCODE_TYPES
	},
	{
		.name		=	"32 bits syscall",
		.op_table	=	ST_Intel32_specialOpcodes,
		.arch		=	IA32_OPCODE_TYPES
	},
	{
		.name		=	"32 bits jumps",
		.op_table	=	ST_Intel32_JumpOpcodes,
		.arch		=	IA32_OPCODE_TYPES
	},
	{
		.name		=	"operational 32 bits opcodes",
		.op_table	=	ST_Intel32_OperationOpcodes,
		.arch		=	IA32_OPCODE_TYPES
	},
	{}	
};


#endif 
