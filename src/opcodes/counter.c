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

ST_OpcodeCounter op_count;

void COSU_Init(void) {
	register int i,j,k,ii;
	unsigned char *ptr;
	int buffersize,erroffset;
        ST_Opcode *current_opcode,*indirect_opcode;
        ST_Lookup *table;
	int opcode_length,len;
	char opcode[32];
	char opcode_aux[32];
	char *errorstr;

	op_count.total_process = 0;
	op_count.total_matchs = 0;
	bzero(op_count.regular_expresion,REGEX_BUFFER);	
	sprintf(op_count.regular_expresion,"(");
	i = 0;
        table = &ST_LookupOpcodeTable[0];
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
			sprintf(op_count.regular_expresion,"%s%s|",op_count.regular_expresion,opcode);
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
					sprintf(op_count.regular_expresion,"%s%s%s|",op_count.regular_expresion,opcode,opcode_aux);
						
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
	len = strlen(op_count.regular_expresion);
	op_count.regular_expresion[len-1] = '\0';
	sprintf(op_count.regular_expresion,"%s)",op_count.regular_expresion);

	op_count.opcode_regex = pcre_compile((char*)op_count.regular_expresion, PCRE_DOTALL, &errorstr, &erroffset, 0);

#ifdef PCRE_HAVE_JIT
        op_count.opcode_regex_study = pcre_study(op_count.opcode_regex,PCRE_STUDY_JIT_COMPILE,&errorstr);
	if(op_count.opcode_regex_study == NULL){
		WARNING("PCRE study with JIT support failed '%s'\n",errorstr);
		return;
	}
	int jit = 0;
	int ret;

	ret = pcre_fullinfo(op_count.opcode_regex,op_count.opcode_regex_study, PCRE_INFO_JIT,&jit);
    	if (ret != 0 || jit != 1) {
		INFOMSG("PCRE JIT compiler does not support the expresion on the Opcoder\n");
	}
#else
	op_count.opcode_regex_study = pcre_study(op_count.opcode_regex,0,&errorstr);
	if(op_count.opcode_regex_study == NULL)
		WARNING("pcre study failed '%s'\n",errorstr);
#endif 
	return;
}




void printfhex(char *payload,int size) {
        char buffer[10];
        int i,fd;
        const u_char *ptr;
        int online = 0;

        ptr = payload;
//        write(0,"\n",1);
        for ( i= 0;i<size;i++) {
                if ( online == 16 ) {
                        write(0,"\n",1);
                        online = 0;
                }
                online ++;
                sprintf(buffer,"%02x ",*ptr);
                write(0,buffer,strlen(buffer));
                ptr++;
        }
        write(0,"\n",1);
        return;
}

int COSU_CheckSuspiciousOpcodes(char *data, int datasize) {
        int ret = 0;

	op_count.total_process++;
        ret = pcre_exec(op_count.opcode_regex, op_count.opcode_regex_study,(const char*)data, datasize, 0, 0, op_count.ovector, OVECCOUNT);
        if (ret < 0) {
                switch (ret) {
                        case PCRE_ERROR_NOMATCH:
      //      printf("String didn't match");
                        break;

                        default:
     //       printf("Error while matching: %d\n", ret);
                        break;
                }
                return 0;
        }
	op_count.total_matchs++;
#ifdef DEBUG
	int offset = op_count.ovector[0];
	int size = op_count.ovector[1]-offset;
	char *opcode = data + offset;
	DEBUG0("opcode detected on offset %d\n",offset);
//	printfhex(opcode,size);
#endif
	return 1;

}

void COSU_Destroy(){
	pcre_free(op_count.opcode_regex);
#if PCRE_MAYOR == 8 && PCRE_MINOR >= 20
        pcre_free_study(op_count.opcode_regex_study);
#else
        pcre_free(op_count.opcode_regex_study);
#endif
	return;
}

void COSU_Stats(){
        fprintf(stdout,"Opcode counter statistics\n");
        fprintf(stdout,"\ttotal process %ld\n",op_count.total_process);
        fprintf(stdout,"\ttotal matchs %ld\n",op_count.total_matchs);

	return;
}




// TODO this function should be optimized, by a tree or any other 
// structure. check performance with valgrind
int COSU_CheckSuspiciousOpcodes2(char *data, int datasize) {
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
