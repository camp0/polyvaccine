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

#ifndef _JUMP_H_
#define _JUMP_H_

#define IA32_JUMPS 43 

struct ST_Jump {
   	char *opcode;          /* the operation code */
   	int len;          /* length of code */
   	int lenaddr;          /* can we use it for NOP pad? */
	char *instruction;
	unsigned long rcount;
	unsigned long fcount;
};

static struct ST_Jump ST_IntelJumps[IA32_JUMPS] = {
	{ "\xe1",1,1,		"Loope rel8"	,0,0 },		/* LOOPE rel8, LOOPZ rel8  */
   	{ "\xe2",1,1,		"Loop rel8"	,0,0 },         /* LOOP rel8 */
   	{ "\xe0",1,1,		"Loopne rel8"	,0,0 },         /* LOOPNE rel8, LOOPNZ rel8 */
   	{ "\xe9",1,1,		"Jmp rel8"	,0,0 },         /* jmp */
	{ "\xeb",1,1,		"Jmp rel8"	,0,0 },		/* JMP rel8 */
   	{ "\xea",1,1,		"Jmp"		,0,0 },         /* jmp */
   	{ "\x9a",1,4,		"Call"		,0,0 },         /* call puede ser con 4 o 6 de tamaño */
	{ "\xe8",1,4,		"Call rel16"	,0,0 },		/* CALL rel16 */
	{ "\x9a",1,4,		"Call ptr16:16"	,0,0 },		/* CALL ptr16:16 */
	{ "\x77",1,1,		"Ja rel8"	,0,0 },		/* JA rel8, JNBE rel8 */
	{ "\x73",1,1,		"Jae rel8"	,0,0 },		/* JAE rel8, JNB rel8, JNC rel8 */
	{ "\x72",1,1,		"Jb rel8"	,0,0 },		/* JB rel8 , JC rel8, JNAE rel8 */
	{ "\x76",1,1,		"Jbe rel8"	,0,0 },		/* JBE rel8 , JNA rel8 */
	{ "\xe3",1,1,		"Jcxz rel8"	,0,0 },		/* JCXZ rel8 ,JECXZ rel8 */
	{ "\x74",1,1,		"Je rel8"	,0,0 },		/* JE rel8, JZ rel8,  */
	{ "\x7f",1,1,		"Jg rel8"	,0,0 },		/* JG rel8, JNLE rel8 */
	{ "\x7d",1,1,		"Jge rel8"	,0,0 },		/* JGE rel8, JNL rel8 */
	{ "\x7c",1,1,		"Jl rel8"	,0,0 },		/* JL rel8, JNGE rel8  */
	{ "\x7e",1,1,		"Jle rel8"	,0,0 },		/* JLE rel8, JNG rel8 */
	{ "\x75",1,1,		"Jne rel8"	,0,0 },		/* JNE rel8, JNZ rel8 */
	{ "\x71",1,1,		"Jno rel8"	,0,0 },		/* JNO rel8 */
	{ "\x7b",1,1,		"Jnp rel8"	,0,0 },		/* JNP rel8, JPO rel8  */
	{ "\x79",1,1,		"Jns rel8"	,0,0 },		/* JNS rel8 */
	{ "\x70",1,1,		"Jo rel8"	,0,0 },		/* JO rel8 */
	{ "\x7a",1,1,		"Jp rel8"	,0,0 },		/* JP rel8, JPE rel8 */ 
/* 26*/	{ "\x78",1,1,		"Js rel8"	,0,0 },		/* JS rel8 */
  	{ "\x0f\x87",2,2,	"Ja rel16"	,0,0 },		/* JA rel16/32, JNBE rel16/32 */ 
  	{ "\x0f\x83",2,2,	"Jae rel16"	,0,0 },		/* JAE rel16/32, JNB rel16/32, JNC rel16/32 */ 
  	{ "\x0f\x82",2,2,	"Jb rel16"	,0,0 },		/* JB rel16/32, JC rel16, JNAE rel16/32 */ 
  	{ "\x0f\x86",2,2,	"Jbe rel16"	,0,0 },		/* JBE rel16/32, JNA rel16/32 */ 
  	{ "\x0f\x84",2,2,	"Je rel16"	,0,0 },		/* JE rel16/32, JZ rel16/32  */ 
  	{ "\x0f\x8f",2,2,	"Jg rel16"	,0,0 },		/* JG rel16/32, JNLE rel16/32 */ 
  	{ "\x0f\x8d",2,2,	"Jge rel16"	,0,0 },		/* JGE rel16/32, JNL rel16/32 */ 
  	{ "\x0f\x8c",2,2,	"Jl rel16"	,0,0 },		/* JL rel16/32, JNGE rel16/32 */ 
  	{ "\x0f\x8e",2,2,	"Jle rel16"	,0,0 },		/* JLE rel16/32, JNG rel16/32 */ 
  	{ "\x0f\x8f",2,2,	"Jg rel16"	,0,0 },		/* JG rel16/32 */ 
  	{ "\x0f\x85",2,2,	"Jne rel16"	,0,0 },		/* JNE rel16/32, JNZ rel16/32 */ 
  	{ "\x0f\x81",2,2,	"Jno rel16"	,0,0 },		/* JNO rel16/32 */ 
  	{ "\x0f\x8b",2,2,	"Jnp rel16"	,0,0 },		/* JNP rel16/32, JPO rel16/32 */ 
  	{ "\x0f\x89",2,2,	"Jns rel16"	,0,0 },		/* JNS rel16/32,  */ 
  	{ "\x0f\x80",2,2,	"Jo rel16"	,0,0 },		/* JO rel16/32,  */ 
  	{ "\x0f\x8a",2,2,	"Jp rel16"	,0,0 },		/* JP rel16/32, JPE rel16/32 */ 
/* 43*/	{ "\x0f\x88",2,2,	"Js rel16"	,0,0 }		/* JS rel16/32 */ 
};
/* las instrucciones de salto en intel son:
http://pdos.csail.mit.edu/6.828/2007/readings/i386/Jcc.htm

cb, cw, cd, cp—A 1-byte (cb), 2-byte (cw), 4-byte (cd), or 6-byte (cp) value following the opcode that is used to specify a code offset and possibly a new value for the code segment register.


 * CALL
 * JMP
 * JE
 * JZ
 * JCXZ
 * JP 
 * JPE
 * RET
 * JNE
 * JNZ
 * JECXZ
 * JNP
 * JPO
 * JA
 * JAE
 * JB
 * JBE
 * JNA
 * JNAE
 * JNB
 * JNBE
 * JC
 * JNC
 * JG
 * JGE
 * JL
 * JLE
 * JNG
 * JNGE
 * JNL
 * JNLE
 * JO
 * JNO
 * JS
 * JNS
 */

#endif 
