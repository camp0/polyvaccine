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

ST_MemorySegment *MESG_Init(){
	ST_MemorySegment *m = g_new(ST_MemorySegment,1);
	m->mem = malloc(MAX_SEGMENT_SIZE);
	m->real_size = MAX_SEGMENT_SIZE;
	MESG_Reset(m);
	return m;
}

ST_MemorySegment *MESG_InitWithSize(int size){
        ST_MemorySegment *m = g_new(ST_MemorySegment,1);
        m->mem = (unsigned char *)malloc(size);
        m->real_size = size;
        MESG_Reset(m);
        return m;
}

void MESG_Destroy(ST_MemorySegment *m){
	free(m->mem);
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

	m->mem = (unsigned char*)realloc(m->mem,size);
	if(m->mem == NULL){ 
		perror("realloc");
                exit(-1);
        }
	m->real_size = size;
	return;
}


void MESG_AppendPayloadNew(ST_MemorySegment *m, unsigned char *payload, int size) {
	int value;

	value = m->virtual_size + size;
	if (value > m->real_size) {
		MESG_Realloc(m,value);
	}
		
	memcpy((m->mem+m->virtual_size),payload,size);
	m->virtual_size += size; 
	return;
}

void MESG_AppendPayload(ST_MemorySegment *m,unsigned char *payload,int size){
	int offset = 0;
	int extra_bytes = 0;

	if (size <= 0)
		return;

	if (m->virtual_size == 0) { // First type packet copy
		if(m->real_size < size) {
			extra_bytes = size - m->real_size;
			MESG_Realloc(m,size);
			m->real_size = size;
		}
	}
	extra_bytes = m->virtual_size + size;
	if (extra_bytes > m->real_size) { // more segments to add
		extra_bytes = extra_bytes - m->real_size;
		MESG_Realloc(m,extra_bytes);
		m->real_size += extra_bytes;
	}

	memcpy((m->mem+m->virtual_size),payload,size);
	m->virtual_size += size;
	return;
}

void MESG_UpdateSize(ST_MemorySegment *m,int size){

	if(size<=0)
		return;

	m->virtual_size += size;
	if (m->virtual_size > m->real_size) { // Need to realloc memory 
		MESG_Realloc(m,m->real_size-m->virtual_size);
	}
	return;
}
