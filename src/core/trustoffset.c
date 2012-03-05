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

#include "trustoffset.h"

ST_TrustOffsets *TROF_Init(void){
	ST_TrustOffsets *t = NULL;
	register int i;

	t = g_new(ST_TrustOffsets,1);
	t->index = 0;

        for (i = 0;i<MAX_OFFSETS_ALLOCATED;i++){
		t->offsets_start[i] = 0;
		t->offsets_end[i] = 0;
	}
	return t;
}

void TROF_Destroy(ST_TrustOffsets *t){
	g_free(t);
	return;	
}

void TROF_Reset(ST_TrustOffsets *t){
	register int i;

	for (i = 0;i<t->index;i++) {
		t->offsets_start[i] = 0;
		t->offsets_end[i] = 0;
	}
	t->index = 0;
	return;
}
void TROF_AddTrustOffset(ST_TrustOffsets *t, int start, int end){
	int prev_index = 0;

	if(t->index == MAX_OFFSETS_ALLOCATED) {
		//DEBUG0("Can not allocate more trust offsets\n");
		return;
	}
	if(t->index >0) 
		prev_index = t->index -1; 
	if(t->offsets_end[prev_index] == start) { // only need to update the chunk
		t->offsets_end[prev_index] == end;
		return;
	} 
	t->offsets_start[t->index] = start;
	t->offsets_end[t->index] = end;
	t->index++;
	return;

}

int *TROF_GetStartOffsets(ST_TrustOffsets *t){
	return t->offsets_start;
}

int *TROF_GetEndOffsets(ST_TrustOffsets *t){
	return t->offsets_end;
}


void TROF_Printf(ST_TrustOffsets *t) {
	register int i;

	for (i = 0;i<t->index;i++) {
		fprintf(stdout,"off(%d,%d)",t->offsets_start[i],t->offsets_end[i]);
	}
	fprintf(stdout,"\n");	
	return;
}

void TROF_SetStartOffsets(ST_TrustOffsets *t,int *s){
	register int i;

	for (i=0;i<MAX_OFFSETS_ALLOCATED;i++)t->offsets_start[i] = s[i];
}

void TROF_SetEndOffsets(ST_TrustOffsets *t, int *e){
	register int i;

	for (i=0;i<MAX_OFFSETS_ALLOCATED;i++)t->offsets_end[i] = e[i];

}

