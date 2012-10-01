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

#include "segment.h"

ST_ExecutableSegment *EXSG_InitExecutableSegment() {
	ST_ExecutableSegment *sx = NULL;

	sx = (ST_ExecutableSegment*)malloc(sizeof(ST_ExecutableSegment));
	if(sx == NULL) {
		perror("malloc");
		return NULL;
	}
        sx->original_segment = NULL;
        sx->segment_with_opcodes = NULL;
        sx->executable_segment = NULL;
        sx->original_segment_size = 0;
        sx->executable_segment_size = 0;

	return sx;
}

void EXSG_PrepareExecutableSegment(ST_ExecutableSegment *sx,char *buffer, int size) {
	int offset,jump_size,real_size,init_regs_size;

	offset = 1;
	
#if __WORDSIZE == 64 // 64 Bits machine
        jump_size = 5;
        init_regs_size = 12;
        real_size = size + init_regs_size + jump_size;
#else
        jump_size = 5;
        init_regs_size = 8;
        real_size = size + init_regs_size + jump_size;
#endif
        sx->executable_segment_size = real_size;
       	sx->executable_segment = mmap(0, sx->executable_segment_size,
                PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED|SEGMENT_EXECUTABLE|SEGMENT_ANONYMOUS, -1, 0);
        if (sx->executable_segment == MAP_FAILED) {
                perror("mmap");
                return NULL;
        }

        memset(sx->executable_segment,"\x90",real_size); /* Init all with nops */
#if __WORDSIZE == 64
        memcpy(sx->executable_segment,"\x48\x31\xc0" "\x48\x31\xdb" "\x48\x31\xc9" "\x48\x31\xd2",init_regs_size);/* Init Registers */
#else
        memcpy(sx->executable_segment,"\x31\xc0" "\x31\xc9" "\x31\xdb" "\x31\xd2",init_regs_size);/* Init Registers */
#endif
        /* Makes a jmp to next instruction */
        memcpy(sx->executable_segment + init_regs_size ,"\xe9\x00\x00\x00\x00",jump_size);
        /* Copy the offset Jmp Jump */
        memcpy(sx->executable_segment + (init_regs_size + 1) ,&offset ,4);
        /* Copy the Buffer */
        memcpy(sx->executable_segment + init_regs_size + jump_size ,buffer,sx->executable_segment_size);

        sx->segment_with_opcodes = malloc(sx->executable_segment_size);
        memcpy(sx->segment_with_opcodes,sx->executable_segment,sx->executable_segment_size);

	return sx;
}

void EXSG_DestroyExecutableSegment(ST_ExecutableSegment *sx){

	free(sx->segment_with_opcodes);
        munmap(sx->executable_segment,sx->executable_segment_size);
      	free(sx);
	sx = NULL;
	return; 
}

void EXSG_ExecuteExecutableSegment(ST_ExecutableSegment *sx){
        void (*function)();

        function = (void (*)(void)) sx->executable_segment;
        (*function)();
	return;
}

/*
void printfhex(char *payload,int size) {
        char buffer[10];
        int i,fd;
        unsigned char *ptr;
        int online = 0;

        ptr = payload;
        write(0,"\n",1);
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
*/
void EXSG_PrintExecutableSegment(ST_ExecutableSegment *sx) {

//	printfhex(sx->executable_segment,sx->executable_segment_size);

	return;
}
