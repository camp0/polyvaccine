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

#include "memory.h"

/**
 * MESG_InitWithSize - Inits a ST_MemorySegment to store layer 7 data with a specific size. 
 *
 * @param size
 *
 * @return ST_MemorySegment 
 * 
 */

ST_MemorySegment *MESG_InitWithSize(int size){
        ST_MemorySegment *m = g_new(ST_MemorySegment,1);
        m->mem = g_malloc0(size);
        m->real_size = size;
        m->virtual_size = 0;
        MESG_Reset(m);
        return m;
}

/**
 * MESG_Init - Inits a ST_MemorySegment to store layer 7 data. 
 *
 * @return ST_MemorySegment 
 * 
 */

ST_MemorySegment *MESG_Init(){

	return MESG_InitWithSize(MAX_SEGMENT_SIZE);
}

void MESG_Destroy(ST_MemorySegment *m){
	g_free(m->mem);
	g_free(m);
	m = NULL;
}

void MESG_Reset(ST_MemorySegment *m){
	if(m->mem == NULL) {
		m->virtual_size = 0;
		return;
	}
	memset(m->mem,0,m->real_size);
	m->virtual_size = 0;
}

void MESG_Realloc(ST_MemorySegment *m, int size) {

	m->mem = g_realloc(m->mem,size);
	if(m->mem == NULL){ 
		perror("realloc");
                exit(-1);
        }
	m->real_size = size;
	return;
}


void MESG_AppendPayload(ST_MemorySegment *m, unsigned char *payload, int size) {
	int value;

	value = m->virtual_size + size;
	if (value > m->real_size) {
		MESG_Realloc(m,value);
	}
		
	memcpy((m->mem+m->virtual_size),payload,size);
	m->virtual_size += size; 
	return;
}

