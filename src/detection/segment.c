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

/**
 * EXSG_InitExecutableSegment - Inits a executable segment for the suspicious opcodes  
 *
 * @return ST_ExecutableSegment  
 */

ST_ExecutableSegment *EXSG_InitExecutableSegment() {
	ST_ExecutableSegment *sg = NULL;

	sg = (ST_ExecutableSegment*)malloc(sizeof(ST_ExecutableSegment));
	if(sg == NULL) {
		perror("malloc");
		return NULL;
	}
        sg->original_segment = NULL;
        sg->segment_with_opcodes = NULL;
        sg->executable_segment = NULL;
        sg->original_segment_size = 0;
        sg->executable_segment_size = 0;
	sg->virtualeip = 0;
	sg->registers_size = 0;
	return sg;
}


/**
 * EXSG_PrepareExecutableSegment - Prepare the executable segment for execution 
 *
 * @param sg
 * @param buffer
 * @param size
 * 
 */

void EXSG_PrepareExecutableSegment(ST_ExecutableSegment *sg,char *buffer, int size) {
	int offset,jump_size,real_size;

	offset = 1;
	
#if __WORDSIZE == 64 // 64 Bits machine
        jump_size = 5;
	sg->registers_size = 12;
#else
        jump_size = 5;
        sg->registers_size = 8;
#endif
        real_size = size + sg->registers_size + jump_size;

        sg->executable_segment_size = real_size;
       	sg->executable_segment = mmap(0, sg->executable_segment_size,
                PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED|SEGMENT_EXECUTABLE|SEGMENT_ANONYMOUS, -1, 0);
        if (sg->executable_segment == MAP_FAILED) {
                perror("mmap");
                return NULL;
        }

        memset(sg->executable_segment,"\x90",real_size); /* Init all with nops */
#if __WORDSIZE == 64
        memcpy(sg->executable_segment,"\x48\x31\xc0" "\x48\x31\xdb" "\x48\x31\xc9" "\x48\x31\xd2",sg->registers_size);/* Init Registers */
#else
        memcpy(sg->executable_segment,"\x31\xc0" "\x31\xc9" "\x31\xdb" "\x31\xd2",sg->registers_size);/* Init Registers */
#endif
        /* Makes a jmp to next instruction */
        memcpy(sg->executable_segment + sg->registers_size ,"\xe9\x00\x00\x00\x00",jump_size);

        /* Copy the offset Jmp Jump */
        memcpy(sg->executable_segment + (sg->registers_size + 1) ,&offset ,4);

        /* Copy the suspicious buffer */
        memcpy(sg->executable_segment + sg->registers_size + jump_size ,buffer,sg->executable_segment_size);

        sg->segment_with_opcodes = malloc(sg->executable_segment_size);
        memcpy(sg->segment_with_opcodes,sg->executable_segment,sg->executable_segment_size);
	
	sg->virtualeip = 0;
	return sg;
}

/**
 * EXSG_IncreaseEIPOnExecutableSegment - Increase the jump for execution
 *
 * @param sg
 *
 */

void EXSG_IncreaseEIPOnExecutableSegment(ST_ExecutableSegment *sg){

        memcpy(sg->executable_segment ,
        	sg->segment_with_opcodes,sg->executable_segment_size);              /* Copy the Buffer */
        sg->virtualeip ++;
        memcpy(sg->executable_segment + (sg->registers_size + 1) ,&(sg->virtualeip),4);

	return;
}

/**
 * EXSG_DestroyExecutableSegment - Free the ST_ExecutableSegment struct 
 *
 * @param sg
 *
 */

void EXSG_DestroyExecutableSegment(ST_ExecutableSegment *sg){

	free(sg->segment_with_opcodes);
        munmap(sg->executable_segment,sg->executable_segment_size);
      	free(sg);
	sg = NULL;
	return; 
}

/**
 * EXSG_ExecuteExecutableSegment - Executes the ST_ExecutableSegment struct
 *
 * @param sg
 *
 */

void EXSG_ExecuteExecutableSegment(ST_ExecutableSegment *sg){
        void (*function)();

        function = (void (*)(void)) sg->executable_segment;
        (*function)();
	return;
}

/**
 * EXSG_PrintExecutableSegment - Prints the ST_ExecutableSegment struct
 *
 * @param sg
 *
 */

void EXSG_PrintExecutableSegment(ST_ExecutableSegment *sg) {
        char buffer[10];
        int i,fd;
        unsigned char *ptr;
        int online = 0;
	int size = sg->executable_segment_size;

        ptr = sg->executable_segment;
        printf("\neip(%d)size(%d)",sg->virtualeip,size);
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
