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
 * Notes:
 * This file contains the opcodes that are candidates to be executed.
 * The opcodes are classified on several groups as special, indirections, and so on.
 * Notice that on the special opcode table there is no instructions such as getpc,
 * instructions that get the program counter(should be included).
 *
 * The indirection opcode table contains all the posible indirection modes(or try to).
 * Most of polymorphic exploits needs at least one instruction with a indirection in 
 * order to decrypt their payload.
 */

#ifndef _OPCODES_H_
#define _OPCODES_H_

#include <stdio.h>

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

static ST_Opcode ST_Intel32_JumpOpcodes[] = {
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
  	{ 
		.opcode		=	"\x0f\x83",
		.len		=	2,
		.instruction	=	"Jae rel16",
		.matchs		=	0 ,
		.op_table	=	NULL
	},		/* JAE rel16/32, JNB rel16/32, JNC rel16/32 */ 
  	{ 
		.opcode		=	"\x0f\x82",
		.len		=	2,
		.instruction	=	"Jb rel16",
		.matchs		=	0 ,
		.op_table	=	NULL
	},		/* JB rel16/32, JC rel16, JNAE rel16/32 */ 
  	{ 
		.opcode		=	"\x0f\x86",
		.len		=	2,
		.instruction	=	"Jbe rel16",
		.matchs		=	0 ,
		.op_table	=	NULL
	},		/* JBE rel16/32, JNA rel16/32 */ 
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
	{ 
		.opcode		=	"\x0f\x88",
		.len		=	2,
		.instruction	=	"Js rel16",
		.matchs		=	0 ,
		.op_table 	=	NULL
	},		/* JS rel16/32 */ 
	{}
};

/* This table is for indirections  the same opcodes for 32 bits and 64 */
static ST_Opcode ST_Intel_IndirectOpcodes[] = {
        { 
		.opcode		=	"\x03",
		.len		=	1,
		.instruction	=	"(%ebx),%eax", /* 8b 03                   mov    (%ebx),%eax */
		.matchs		=	0,
		.op_table	=	NULL 
	}, 
        { 
		.opcode		=	"\x1b",
		.len		=	1,
		.instruction	=	"(%ebx),%ebx",/* 8b 1b                   mov    (%ebx),%ebx */	
		.matchs		=	0,
		.op_table	=	NULL 
	}, 
        { 
		.opcode		=	"\x0b",
		.len		=	1,	
		.instruction	=	"(%ebx),%ecx",/* 8b 0b                   mov    (%ebx),%ecx */	
		.matchs		=	0,
		.op_table	=	NULL 
	}, 
        { 
		.opcode		=	"\x13",
		.len		=	1,
		.instruction	=	"(%ebx),%edx", /* 8b 13                   mov    (%ebx),%edx */
		.matchs		=	0,
		.op_table	=	NULL 
	}, 
        { 
		.opcode		=	"\x00",
		.len		=	1,
		.instruction	=	"(%eax),%eax",/* 8b 00                   mov    (%eax),%eax */	
		.matchs		=	0,
		.op_table	=	NULL 
	}, 
        { 
		.opcode		=	"\x18",
		.len		=	1,
		.instruction	=	"(%eax),%ebx", /* 8b 18                   mov    (%eax),%ebx */	
		.matchs		=	0,
		.op_table	=	NULL 
	}, 
        { 
		.opcode		=	"\x08",
		.len		=	1,
		.instruction	= 	"(%eax),%ecx", /* 8b 08                   mov    (%eax),%ecx */
		.matchs		=     	0,
		.op_table	=	NULL 
	},
        { 
		.opcode		=	"\x10",
		.len		=	1, 
		.instruction	=	"(%eax),%edx", /* 8b 10                   mov    (%eax),%edx */
		.matchs		=     	0,
		.op_table	=	NULL     
	},
        { 
		.opcode		=	"\x01",
		.len		=	1,
		.instruction	=	"(%ecx),%eax", /* 8b 01                   mov    (%ecx),%eax */
		.matchs		=	0,
		.op_table	=	NULL    
	},
        { 
		.opcode		=	"\x19",
		.len		=	1,
		.instruction	=  	"(%ecx),%ebx", /* 8b 19                   mov    (%ecx),%ebx */
		.matchs		=	0,
		.op_table	=	NULL    
	},
        { 
		.opcode		=	"\x09",
		.len		=	1,
		.instruction	= 	"(%ecx),%ecx", /* 8b 09                   mov    (%ecx),%ecx */
		.matchs		=	0,
		.op_table	=	NULL     
	},
        { 
		.opcode		=	"\x11",
		.len		=	1,
		.instruction	=	"(%ecx),%edx", /* 8b 11                   mov    (%ecx),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x02",
		.len		=	1,
		.instruction	=   	"(%edx),%eax", /* 8b 02                   mov    (%edx),%eax */
		.matchs		=	0,
		.op_table	=	NULL   
	},
        { 
		.opcode		=	"\x1a",
		.len		=	1,
		.instruction	=	"(%edx),%ebx", /* 8b 1a                   mov    (%edx),%ebx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x0a",
		.len		=	1,
		.instruction	=	"(%edx),%ecx", /* 8b 0a                   mov    (%edx),%ecx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x12",
		.len		=	1,	
		.instruction	=	"(%edx),%edx", /* 8b 12                   mov    (%edx),%edx */
		.matchs		=	0,
		.op_table	=	NULL      
	},
        { 
		.opcode		=	"\x45",
		.len		=	1,
		.instruction	=	"0x0(%ebp),%eax", /* 8b 45 00                mov    0x0(%ebp),%eax */
		.matchs		=	0,
		.op_table	=	NULL
	}, 
        { 
		.opcode		=	"\x5d",
		.len		=	1,
		.instruction	=	"0x0(%ebp),%ebx", /* 8b 5d 00                mov    0x0(%ebp),%ebx */
		.matchs		=	0,
		.op_table	=	NULL 
	},
        { 
		.opcode		=	"\x4d",
		.len		=	1,	
		.instruction	=	"0x0(%ebp),%ecx", /* 8b 4d 00                mov    0x0(%ebp),%ecx */ 
		.matchs		=	0,
		.op_table	=	NULL      
	},
	{ 
		.opcode		=	"\x55",
		.len		=	1,
		.instruction	=	"0x0(%ebp),%edx", /* 8b 55 00                mov    0x0(%ebp),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	}, 
        { 
		.opcode		=	"\x24",
		.len		=	1,
		.instruction	=	"(%esp),%eax", /* 8b 04 24                mov    (%esp),%eax */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x58",
		.len		=	1,
		.instruction	=	"%ebx,0xc(%eax)", /* 31 58 0c                xor    %ebx,0xc(%eax) */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x5b",
		.len		=	1,
		.instruction	=	"%ebx,0xc(%ebx)", /* 31 5b 0c                xor    %ebx,0xc(%ebx) */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x51",
		.len		=	1,
		.instruction	=	"%edx,0xc(%ecx)", /* 31 51 0c                xor    %edx,0xc(%ecx) */
		.matchs		=	0,
		.op_table	=	NULL      
	},
        { 
		.opcode		=	"\x61",
		.len		=	1,
		.instruction	=	"%esp,0x2(%ecx)", /* 31 61 02                xor    %esp,0x2(%ecx) */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x52",
		.len		=	1,	
		.instruction	=	"%edx,0xc(%edx)",    /* 31 52 0c                xor    %edx,0xc(%edx) */ 
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x62",
		.len		=	1,
		.instruction	=	"%esp,0x2(%edx)", /* 31 62 02                xor    %esp,0x2(%edx) */
		.matchs		=	0,
		.op_table	=	NULL
	},
	{ 
		.opcode		=	"\x6a",
		.len		=	1,
		.instruction	=	"%ebp,0x2(%edx)", /* 31 6a 02                xor    %ebp,0x2(%edx) */
		.matchs		=	0,
		.op_table	=	NULL      
	},
        { 
		.opcode		=	"\x44\x0d",
		.len		=	2,
		.instruction	=	"0x0(%ebp,%ecx,1),%eax",/* 8b 44 0d 00             mov    0x0(%ebp,%ecx,1),%eax */ 
		.matchs		=	0,
		.op_table	=	NULL  
	}, 
	{ 
		.opcode		=	"\x5c\x0d",
		.len		=	2,
		.instruction	=	"0x0(%ebp,%ecx,1),%ebx", /* 8b 5c 0d 00             mov    0x0(%ebp,%ecx,1),%ebx */
		.matchs		=	0,
		.op_table	=	NULL  
	}, 
        { 
		.opcode		=	"\x4c\x0d",
		.len		=	2,
		.instruction	=	"0x0(%ebp,%ecx,1),%ecx", /* 8b 4c 0d 00             mov    0x0(%ebp,%ecx,1),%ecx */
		.matchs		=	0,
		.op_table	=	NULL  
	},
        { 
		.opcode		=	"\x54\x0d",
		.len		=	2,
		.instruction	=	"0x0(%ebp,%ecx,1),%edx", /* 8b 54 0d 00             mov    0x0(%ebp,%ecx,1),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x04\x0c",
		.len		=	2,
		.instruction	=	"(%esp,%ecx,1),%eax",  /* 8b 04 0c                mov    (%esp,%ecx,1),%eax */
		.matchs		=	0,
		.op_table	=	NULL
	}, 
        { 
		.opcode		=	"\x1c\x0c",
		.len		=	2,
		.instruction	=	"(%esp,%ecx,1),%ebx", /* 8b 1c 0c                mov    (%esp,%ecx,1),%ebx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x0c\x0c",
		.len		=	2,
		.instruction	=	"(%esp,%ecx,1),%ecx", /* 8b 0c 0c                mov    (%esp,%ecx,1),%ecx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x14\x0c",
		.len		=	2,
		.instruction	=	"(%esp,%ecx,1),%edx",
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x54\x0c",
		.len		=	2,
		.instruction	=	"0x2(%esp,%ecx,1),%edx", /* 8b 54 0c 02             mov    0x2(%esp,%ecx,1),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x04\x0a",
		.len		=	2,
		.instruction	=	"(%edx,%ecx,1),%eax", /* 8b 04 0a                mov    (%edx,%ecx,1),%eax */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x1c\x0a",
		.len		=	2,
		.instruction	=	"(%edx,%ecx,1),%ebx", /* 8b 1c 0a                mov    (%edx,%ecx,1),%ebx */
		.matchs		=	0,
		.op_table	=	NULL
	},
	{ 
		.opcode		=	"\x0c\x0a",
		.len		=	2,
		.instruction	=	"(%edx,%ecx,1),%ecx", /* 8b 0c 0a                mov    (%edx,%ecx,1),%ecx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x14\x0a",
		.len		=	2,
		.instruction	=	"(%edx,%ecx,1),%edx", /* 8b 14 0a                mov    (%edx,%ecx,1),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x54\x0a",
		.len		=	2,
		.instruction	=	"0x2(%edx,%ecx,1),%edx", /* 8b 54 0a 02             mov    0x2(%edx,%ecx,1),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x04\x0e",
		.len		=	2,
		.instruction	=	"(%esi,%ecx,1),%eax", /* 8b 04 0e                mov    (%esi,%ecx,1),%eax */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x1c\x0e",
		.len		=	2,
		.instruction	=	"(%esi,%ecx,1),%ebx", /* 8b 1c 0e                mov    (%esi,%ecx,1),%ebx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x0c\x0e",
		.len		=	2,
		.instruction	=	"(%esi,%ecx,1),%ecx", /* 8b 0c 0e                mov    (%esi,%ecx,1),%ecx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x14\x0e",
		.len		=	2,
		.instruction	=	"(%esi,%ecx,1),%edx", /* 8b 14 0e                mov    (%esi,%ecx,1),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x54\x0e",
		.len		=	2,
		.instruction	=	"0x2(%esi,%ecx,1),%edx", /* 8b 54 0e 02             mov    0x2(%esi,%ecx,1),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x07",
		.len		=	1,
		.instruction	=	"(%edi),%eax", /* 8b 07                   mov    (%edi),%eax */
		.matchs		=	0,
		.op_table	=	NULL    
	},
        { 
		.opcode		=	"\x1f",
		.len		=	1,
		.instruction	=	"(%edi),%ebx", /* 8b 1f                   mov    (%edi),%ebx */
		.matchs		=	0,
		.op_table	=	NULL
	},
	{ 
		.opcode		=	"\x0f",
		.len		=	1,
		.instruction	=	"(%edi),%ecx", /* 8b 0f                   mov    (%edi),%ecx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x47",
		.len		=	1,
		.instruction	=	"0x2(%edi),%eax", /* 8b 47 02                mov    0x2(%edi),%eax */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x5f",
		.len		=	1,
		.instruction	=	"0x8(%edi),%ebx", /* 8b 5f 08                mov    0x8(%edi),%ebx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x4f",
		.len		=	1,
		.instruction	=	"0x10(%edi),%ecx", /* 8b 4f 10                mov    0x10(%edi),%ecx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x57",
		.len		=	1,
		.instruction	=	"0x20(%edi),%edx", /* 8b 57 20                mov    0x20(%edi),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x06",
		.len		=	1,
		.instruction	=	"(%esi),%eax", /* 8b 06                   mov    (%esi),%eax */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x1e",
		.len		=	1,
		.instruction	=	"(%esi),%ebx", /* 8b 1e                   mov    (%esi),%ebx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x0e",
		.len		=	1,
		.instruction	=	"(%esi),%ecx",  /* 8b 0e                   mov    (%esi),%ecx */
		.matchs		=	0,
		.op_table	=	NULL
	},
        { 
		.opcode		=	"\x16",
		.len		=	1,
		.instruction	=	"(%esi),%edx", /* 8b 16                   mov    (%esi),%edx */
		.matchs		=	0,
		.op_table	=	NULL
	}, 
	{}
};

static ST_Opcode ST_Intel32_OperationOpcodes[] = {
        { 
		.opcode		=	"\x8b",
		.len		=	1,
		.instruction	=	"mov",/* mov */ /* 1000 1000 */	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, 
        { 
		.opcode		=	"\x89",
		.len		=	1,
		.instruction	=	"mov",
		.matchs		=	0,	
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, 
        { 
		.opcode		=	"\x01",
		.len		=	1,
		.instruction	=	"add",
		.matchs		=	0,	
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, 
        { 
		.opcode		=	"\x03",
		.len		=	1,
		.instruction	=	"add",
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0])
	}, 
        { 
		.opcode		=	"\x29",
		.len		=	1,	
		.instruction	=	"sub",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* sub */
        { 
		.opcode		=	"\x2b",
		.len		=	1,
		.instruction	=	"sub",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* sub */
        { 
		.opcode		=	"\x11",
		.len		=	1,	
		.instruction	=	"adc",
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* adc */ /* 0001 0001 */
        { 
		.opcode		=	"\x13",
		.len		=	1,
		.instruction	=	"adc",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* adc */ /* 0001 0011 */
        { 
		.opcode		=	"\x21",
		.len		=	1,
		.instruction	=	"and",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0])
	}, /* and */ /* 0010 0001 */
	{ 
		.opcode		=	"\x23",
		.len		=	1,
		.instruction	=    	"and",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0])
	}, /* and */
        { 
		.opcode		=	"\x87",
		.len		=	1,
		.instruction	=	"xchg",	
		.matchs		=	0,	
		.op_table	=	&(ST_Intel_IndirectOpcodes[0])
	}, /* xchg */
        { 
		.opcode		=	"\x19",
		.len		=	1,
		.instruction	=	"sbb",
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0])
	}, /* sbb */
        { 
		.opcode		=	"\x1b",
		.len		=	1,
		.instruction	=	"sbb",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* sbb */
        { 
		.opcode		=	"\x0f\x0a",
		.len		=	2,
		.instruction	=	"imul",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* 0f af 01                imul   (%ecx),%eax */
        { 
		.opcode		=	"\x09",
		.len		=	1,
		.instruction	=	"or",
		.matchs		=	0,	
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* or */
        { 
		.opcode		=	"\x0b",
		.len		=	1,
		.instruction	=	"or",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* or */
        { 
		.opcode		=	"\x31",
		.len		=	1,
		.instruction	=	"xor",	
		.matchs		=	0,
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
	}, /* xor */
        { 
		.opcode		=	"\x33",
		.len		=	1,	
		.instruction	=	"xor",	
		.matchs		=	0,	
		.op_table	=	&(ST_Intel_IndirectOpcodes[0]) 
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

static ST_Opcode ST_Intel64_OperationOpcodes[] = {
        {
                .opcode         =       "\x67\x8b",
                .len            =       2,
                .instruction    =       "mov",/* mov */ /* 1000 1000 */
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x89",
                .len            =       2,
                .instruction    =       "mov",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x01",
                .len            =       2,
                .instruction    =       "add",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x03",
                .len            =       2,
                .instruction    =       "add",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x29",
                .len            =       2,
                .instruction    =       "sub",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x2b",
                .len            =       2,
                .instruction    =       "sub",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x11",
                .len            =       2,
                .instruction    =       "adc",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x13",
                .len            =       2,
                .instruction    =       "adc",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x21",
                .len            =       2,
                .instruction    =       "and",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        },
        {
                .opcode         =       "\x67\x23",
                .len            =       2,
                .instruction    =       "and",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* and */
        {
                .opcode         =       "\x67\x87",
                .len            =       2,
                .instruction    =       "xchg",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* xchg */
        {
                .opcode         =       "\x67\x19",
                .len            =       2,
                .instruction    =       "sbb",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* sbb */
        {
                .opcode         =       "\x67\x1b",
                .len            =       2,
                .instruction    =       "sbb",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* sbb */
        {
                .opcode         =       "\x67\x0f\x0a",
                .len            =       3,
                .instruction    =       "imul",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* 0f af 01                imul   (%ecx),%eax */
        {
                .opcode         =       "\x67\x09",
                .len            =       2,
                .instruction    =       "or",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* or */
        {
                .opcode         =       "\x67\x0b",
                .len            =       2,
                .instruction    =       "or",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* or */
        {
                .opcode         =       "\x67\x31",
                .len            =       2,
                .instruction    =       "xor",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* xor */
        {
                .opcode         =       "\x67\x33",
                .len            =       2,
                .instruction    =       "xor",
                .matchs         =       0,
                .op_table       =       &(ST_Intel_IndirectOpcodes[0])
        }, /* xor */
        {}
};

static ST_Opcode ST_Intel64_specialOpcodes[] = {
	{ 
		.opcode		=	"\x0f\x05",
		.len		=	2,	
		.instruction	=	"int80",
		.matchs		=	0,
		.op_table	=	NULL
	},
	{}
};

/* Final lookup table */
static ST_Lookup ST_LookupOpcodeTable [] = {
#ifdef __LINUX__
#if __WORDSIZE == 64
	{
		.name		=	"64 bits syscall",
		.op_table	= 	ST_Intel64_specialOpcodes,
		.arch		=	IA64_OPCODE_TYPES
	},
        {
                .name           =       "operational 64 bits opcodes",
                .op_table       =       ST_Intel64_OperationOpcodes,
                .arch           =       IA64_OPCODE_TYPES
        }
#else 
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
	}
#endif
#endif
	,{}	
};

#endif 
