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

#include "counter.h"
#include <pcre.h>

/* TODO 
 * This function should be a big regular expresion with all the 
 * possible opcodes, may be a special tree also could be a good idea
 * but sometimes its better to reuse than create.
 */
 
void COSU_Init(void){
	register int i;
        ST_Lookup *table;

	i = 0;
	table = &(ST_LookupOpcodeTable[0]);
	while(table->name!= NULL) {

		DEBUG0("Using opcodes '%s';architecture %d\n",
			table->name,table->arch); 

		i++;
		table = &(ST_LookupOpcodeTable[i]);
	}
	
	return;
}

#define REGEX_BUFFER 1024 * 32 

void COSU_Init2(void) {
	register int i,j,k,ii;
	char *buffer;
	unsigned char *ptr;
	int buffersize;
        ST_Opcode *current_opcode,*indirect_opcode;
        ST_Lookup *table;
	int opcode_length,len;
	char opcode[32];
	char opcode_aux[32];

	buffer = malloc(REGEX_BUFFER);
	bzero(buffer,REGEX_BUFFER);	
	i = 0;
        table = &ST_LookupOpcodeTable[0];
	sprintf(buffer,"(");
	while(table->name!= NULL){
        	current_opcode = &table->op_table[0];
                j = 0;
                while(current_opcode->opcode!= NULL){
                	opcode_length = current_opcode->len;
			ptr = current_opcode->opcode;
			bzero(&opcode,32);
			for (ii = 0;ii<opcode_length;ii++) {
				sprintf(opcode,"%s\\x%02x",opcode,*ptr);
				ptr++;
			}	
			sprintf(buffer,"%s%s|",buffer,opcode);
			if(current_opcode->op_table != NULL) {
                                indirect_opcode = &(current_opcode->op_table[0]);
				k = 0;
				ptr = indirect_opcode->opcode;
                                while(indirect_opcode->opcode!= NULL) {
					bzero(&opcode_aux,32);
					for (ii = 0;ii<indirect_opcode->len;ii++) {
						sprintf(opcode_aux,"%s\\x%02x",opcode_aux,*ptr);
						ptr++;
					}	
					sprintf(buffer,"%s%s%s|",buffer,opcode,opcode_aux);
						
					k++;
                                	indirect_opcode = &(current_opcode->op_table[k]);
				}		
			}
			j++;
                        current_opcode = &table->op_table[j];
		}
                i++;
                table = &ST_LookupOpcodeTable[i];
	}
	len = strlen(buffer);
	buffer[len-1] = '\0';
	sprintf(buffer,"%s)",buffer);
	printf("regex=%s\n",buffer);
	free(buffer);
	return;
}




/****************************** OLD METHOD ********************
int CO_CountOperation(char *data,int datasize) {
	register int i;

	for(i = 0;i< IA32_OPERATION_OPCODES;i++)
		if (strncmp(data,ST_OperationOpcodes[i].opcode,ST_OperationOpcodes[i].len) == 0)
			return TRUE;
	return FALSE;
} 

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
		if(strncmp(ptr,"\xcd\x80",2) ==	0 ) {
			printf("*");	
			return 2;
		}
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
			if (startoffset > 0) { // hay que mirar el byte anterior
				if (CO_CountOperation(&ptr[startoffset-1],1) == TRUE) {
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
*/


// TODO this function should be optimized, by a tree or any other 
// structure. check performance with valgrind
int COSU_CheckSuspiciousOpcodes(char *data, int datasize) {
	register int i,j,k;
        int startoffset,endoffset,count,opcode_length,len;
	ST_Opcode *current_opcode,*indirect_opcode;
	ST_Lookup *table;
	char *current_pointer;
	char *aux_pointer;

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
					}else{
						k= 0;
						indirect_opcode = &(current_opcode->op_table[0]);
						aux_pointer = (current_pointer + opcode_length);
						while(indirect_opcode->opcode!= NULL) {
							 if(strncmp(aux_pointer,indirect_opcode->opcode,
								indirect_opcode->len) == 0) {
								DEBUG0("Opcode '%s %s' detected;offset=%d;architecture %d\n",
									current_opcode->instruction,
									indirect_opcode->instruction,
									startoffset,table->arch);
								return 1;
							}
							k++;
							indirect_opcode = &(current_opcode->op_table[k]);
						}		
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
