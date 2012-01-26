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

#include "counter.h"
#include "jump.h"
#include "indirect.h"
#include "opcodes.h"

void CO_Init(void){
	return;
}

int CO_CountOperation(char *data,int datasize) {
	register int i;

	for(i = 0;i< IA32_OPERATION_OPCODES;i++)
		if (strncmp(data,ST_OperationOpcodes[i].opcode,ST_OperationOpcodes[i].len) == 0)
			return TRUE;
	return FALSE;
} 

/**
 * This function should be implemented by a tree or other structure
 * @todo optimize
 */
int CO_CountSuspiciousOpcodes(char *data, int datasize) {
        int startoffset,endoffset;
        int count;
        char *ptr,*ptrant;
        register int i,j;
        int jumpopcodes = 0;
        int indirectopcodes = 0;
	int current_byte;
	int prev_byte;
	int prev_prev_byte;
	int indirection16bits = 103;
	int index_bytes;

        startoffset = 0;
        endoffset = datasize;
        count = 0;
        ptr = data;
			
        while(startoffset < endoffset) {
//		ptr = &data[startoffset];
		if(strncmp(ptr,"\xcd\x80",2) ==	0 ) {
			printf("*");	
			return 2;
		}
//		ptr++;
//		startoffset++;
//		continue;
		if (jumpopcodes == 0 )
                        for (i = 0;i<IA32_JUMPS;i++)
                                if (strncmp(ptr,ST_IntelJumps[i].opcode,ST_IntelJumps[i].len) == 0 ) {
                                        jumpopcodes ++;
                                        break;
                                }

		index_bytes = 0;
		current_byte = (char*)ptr[startoffset];
		if (current_byte < 0)
			current_byte = 256 - abs(current_byte);
					
		if((current_byte > 0)&&(current_byte < 192)){ // es un byte de indireccion
			//printf("Indirection Byte(0x%2.2x)(%d)\n",current_byte,current_byte);			
			if (startoffset > 0) { // hay que mirar el byte anterior
				if (CO_CountOperation(&ptr[startoffset-1],1) == TRUE) {
			//		printf("OPCODE(0x%2.2x 0x%2.2x)(%d)offset(%d)\n",ptr[startoffset-1],ptr[startoffset],index_bytes,startoffset);
					indirectopcodes ++;	
					count ++;
				} 
			}
		}

		if ((jumpopcodes > 1)&&(indirectopcodes > 0)) {
			count = jumpopcodes + indirectopcodes;
			return count;
		}

		if (indirectopcodes > 1) 
			return indirectopcodes;		
			
                startoffset++ ;
		ptr++;
        }
        return count;
}

// TODO this function should be optimized, by a tree or any other 
// structure. check performance with valgrind
int CO_CountSuspiciousOpcodesNew(char *data, int datasize) {
	register int i;
	register int j;
        int startoffset,endoffset,count,opcode_length;
	ST_Opcode *current_opcode;
	ST_Lookup *table;
	char *current_pointer;

        startoffset = 0;
        endoffset = datasize;
        count = 0;
        current_pointer = data;

        while(startoffset < endoffset) {
		current_pointer = (char*)&data[startoffset];
		table = &ST_LookupOpcodeTable[0];
		i = 0;
		while(table->name!= NULL){
			current_opcode = &table->op_table[0];
			j = 0;
			while(current_opcode->opcode!= NULL){	
				opcode_length = current_opcode->len;
				if(strncmp(current_pointer,current_opcode->opcode,opcode_length) == 0) {
					if(current_opcode->op_table == NULL) {
						DEBUG0("Opcode '%s' detected;offset=%d;architecture %d\n",
							current_opcode->instruction,startoffset,table->arch);
						return 1;
					}
				}
				j++;	
				current_opcode = &table->op_table[j];
			}
			i++;	
			table = &ST_LookupOpcodeTable[i];
		}
		startoffset ++;
	}			
	return 0;
}
