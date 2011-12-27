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

#define IA32_INDIRECT_OPCODES 58 
#define IA32_OPERATION_OPCODES 18 

struct ST_IndirectOpcode {
	char *opcode;
	int len;
	unsigned long count;
};

static struct ST_IndirectOpcode ST_OperationOpcodes[IA32_OPERATION_OPCODES] = {
	{ "\x8b",1,0	}, /* mov */ /* 1000 1000 */
	{ "\x89",1,0	}, /* mov */
	{ "\x01",1,0	}, /* add */
	{ "\x03",1,0	}, /* add */
	{ "\x29",1,0	}, /* sub */
	{ "\x2b",1,0	}, /* sub */
	{ "\x11",1,0	}, /* adc */ /* 0001 0001 */
	{ "\x13",1,0	}, /* adc */ /* 0001 0011 */
	{ "\x21",1,0	}, /* and */ /* 0010 0001 */
/*10*/	{ "\x23",1,0	}, /* and */
	{ "\x87",1,0	}, /* xchg */
	{ "\x19",1,0	}, /* sbb */
	{ "\x1b",1,0	}, /* sbb */
	{ "\x0f\x0a",2,0}, /* 0f af 01                imul   (%ecx),%eax */
	{ "\x09",1,0	}, /* or */
	{ "\x0b",1,0	}, /* or */
	{ "\x31",1,0	}, /* xor */
	{ "\x33",1,0	} /* xor */
};

static struct ST_IndirectOpcode ST_IndirectOpcodes[IA32_INDIRECT_OPCODES] = {
	{ "\x03",1,0	}, /* 8b 03                   mov    (%ebx),%eax */
	{ "\x1b",1,0	}, /* 8b 1b                   mov    (%ebx),%ebx */
	{ "\x0b",1,0	}, /* 8b 0b                   mov    (%ebx),%ecx */
	{ "\x13",1,0	}, /* 8b 13                   mov    (%ebx),%edx */
	{ "\x00",1,0	}, /* 8b 00                   mov    (%eax),%eax */
	{ "\x18",1,0	}, /* 8b 18                   mov    (%eax),%ebx */
	{ "\x08",1,0	}, /* 8b 08                   mov    (%eax),%ecx */
	{ "\x10",1,0	}, /* 8b 10                   mov    (%eax),%edx */
	{ "\x01",1,0	}, /* 8b 01                   mov    (%ecx),%eax */
	{ "\x19",1,0	}, /* 8b 19                   mov    (%ecx),%ebx */
	{ "\x09",1,0	}, /* 8b 09                   mov    (%ecx),%ecx */
	{ "\x11",1,0	}, /* 8b 11                   mov    (%ecx),%edx */
	{ "\x02",1,0	}, /* 8b 02                   mov    (%edx),%eax */
	{ "\x1a",1,0	}, /* 8b 1a                   mov    (%edx),%ebx */
	{ "\x0a",1,0	}, /* 8b 0a                   mov    (%edx),%ecx */
	{ "\x12",1,0	}, /* 8b 12                   mov    (%edx),%edx */
	{ "\x45",1,0	}, /* 8b 45 00                mov    0x0(%ebp),%eax */
	{ "\x5d",1,0	}, /* 8b 5d 00                mov    0x0(%ebp),%ebx */
	{ "\x4d",1,0	}, /* 8b 4d 00                mov    0x0(%ebp),%ecx */
/*20*/	{ "\x55",1,0	}, /* 8b 55 00                mov    0x0(%ebp),%edx */
	{ "\x24",1,0	}, /* 8b 04 24                mov    (%esp),%eax */
	{ "\x58",1,0	}, /* 31 58 0c                xor    %ebx,0xc(%eax) */
	{ "\x5b",1,0	}, /* 31 5b 0c                xor    %ebx,0xc(%ebx) */
	{ "\x51",1,0	}, /* 31 51 0c                xor    %edx,0xc(%ecx) */
	{ "\x61",1,0	}, /* 31 61 02                xor    %esp,0x2(%ecx) */
	{ "\x52",1,0	}, /* 31 52 0c                xor    %edx,0xc(%edx) */
	{ "\x62",1,0	}, /* 31 62 02                xor    %esp,0x2(%edx) */
/*28*/	{ "\x6a",1,0	}, /* 31 6a 02                xor    %ebp,0x2(%edx) */
	{ "\x44\x0d",2,0}, /* 8b 44 0d 00             mov    0x0(%ebp,%ecx,1),%eax */
/*30*/	{ "\x5c\x0d",2,0}, /* 8b 5c 0d 00             mov    0x0(%ebp,%ecx,1),%ebx */
	{ "\x4c\x0d",2,0}, /* 8b 4c 0d 00             mov    0x0(%ebp,%ecx,1),%ecx */
	{ "\x54\x0d",2,0}, /* 8b 54 0d 00             mov    0x0(%ebp,%ecx,1),%edx */
	{ "\x04\x0c",2,0}, /* 8b 04 0c                mov    (%esp,%ecx,1),%eax */
	{ "\x1c\x0c",2,0}, /* 8b 1c 0c                mov    (%esp,%ecx,1),%ebx */
	{ "\x0c\x0c",2,0}, /* 8b 0c 0c                mov    (%esp,%ecx,1),%ecx */
	{ "\x14\x0c",2,0}, /* 8b 14 0c                mov    (%esp,%ecx,1),%edx */
	{ "\x54\x0c",2,0}, /* 8b 54 0c 02             mov    0x2(%esp,%ecx,1),%edx */
	{ "\x04\x0a",2,0}, /* 8b 04 0a                mov    (%edx,%ecx,1),%eax */
	{ "\x1c\x0a",2,0}, /* 8b 1c 0a                mov    (%edx,%ecx,1),%ebx */
/*40*/	{ "\x0c\x0a",2,0}, /* 8b 0c 0a                mov    (%edx,%ecx,1),%ecx */
	{ "\x14\x0a",2,0}, /* 8b 14 0a                mov    (%edx,%ecx,1),%edx */
	{ "\x54\x0a",2,0}, /* 8b 54 0a 02             mov    0x2(%edx,%ecx,1),%edx */
	{ "\x04\x0e",2,0}, /* 8b 04 0e                mov    (%esi,%ecx,1),%eax */
	{ "\x1c\x0e",2,0}, /* 8b 1c 0e                mov    (%esi,%ecx,1),%ebx */
	{ "\x0c\x0e",2,0}, /* 8b 0c 0e                mov    (%esi,%ecx,1),%ecx */
	{ "\x14\x0e",2,0}, /* 8b 14 0e                mov    (%esi,%ecx,1),%edx */
	{ "\x54\x0e",2,0}, /* 8b 54 0e 02             mov    0x2(%esi,%ecx,1),%edx */
	{ "\x07",1,0	}, /* 8b 07                   mov    (%edi),%eax */
	{ "\x1f",1,0	}, /* 8b 1f                   mov    (%edi),%ebx */
/*50*/	{ "\x0f",1,0	}, /* 8b 0f                   mov    (%edi),%ecx */
	{ "\x47",1,0	}, /* 8b 47 02                mov    0x2(%edi),%eax */
	{ "\x5f",1,0	}, /* 8b 5f 08                mov    0x8(%edi),%ebx */
	{ "\x4f",1,0	}, /* 8b 4f 10                mov    0x10(%edi),%ecx */
	{ "\x57",1,0	}, /* 8b 57 20                mov    0x20(%edi),%edx */
	{ "\x06",1,0	}, /* 8b 06                   mov    (%esi),%eax */
	{ "\x1e",1,0	}, /* 8b 1e                   mov    (%esi),%ebx */
	{ "\x0e",1,0	}, /* 8b 0e                   mov    (%esi),%ecx */
	{ "\x16",1,0	}  /* 8b 16                   mov    (%esi),%edx */
};
