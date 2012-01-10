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

#include "memorypool.h"

/**
 * MEPO_Init - Inits the memory pool 
 *
 */
ST_MemoryPool *MEPO_Init() {
	ST_MemoryPool *mp = NULL;

	mp = (ST_MemoryPool*)g_new(ST_MemoryPool,1);
	mp->mem = NULL;	
        mp->total_releases = 0;
        mp->total_release_bytes = 0;
        mp->total_acquires = 0;
        mp->total_acquire_bytes = 0;
        mp->total_errors = 0;

	MEPO_IncrementMemoryPool(mp,MAX_MEMORY_SEGMENTS_PER_POOL);
	return mp;
}

/**
 * MEPO_Destroy - Destroy the memory pool 
 *
 * @param mp the ST_MemoryPool to destroy 
 */
void MEPO_Destroy(ST_MemoryPool *mp){
	MEPO_DecrementMemoryPool(mp,g_slist_length(mp->mem));
	g_slist_free(mp->mem);
	g_free(mp);
}

int MEPO_GetNumberMemorySegments(ST_MemoryPool *mp){
	return g_slist_length(mp->mem);
}

/**
 * MEPO_IncrementMemoryPool - Increments the items of the memory pool 
 *
 * @param mp the ST_MemoryPool to destroy 
 * @param value 
 */

int MEPO_IncrementMemoryPool(ST_MemoryPool *mp,int value){
	int i;

        if (value < 1)
                return FALSE;

        for (i = 0;i<value;i++){
		ST_MemorySegment *m = MESG_Init();
		mp->total_release_bytes += m->real_size;
                mp->mem = g_slist_prepend(mp->mem,m);
	}
        return TRUE;
}

/**
 * MEPO_DecrementMemoryPool - Decrements the items of the memory pool 
 *
 * @param mp the ST_MemoryPool to destroy 
 * @param value 
 */

int MEPO_DecrementMemoryPool(ST_MemoryPool *mp,int value) {
	ST_MemorySegment *m;
	int i,r;

        if (value > g_slist_length(mp->mem))
                r = g_slist_length(mp->mem);
        else
                r = value;

        for (i = 0;i<r;i++){
                GSList *item = g_slist_nth(mp->mem,0);
                if (item != NULL) {
                        mp->mem = g_slist_remove_link(mp->mem,item);
                        m = (ST_MemorySegment*)item->data;
			mp->total_acquire_bytes += m->real_size;
			MESG_Destroy(m);
                }
        }
	return TRUE;
}

void MEPO_AddMemorySegment(ST_MemoryPool *mp,ST_MemorySegment *m){
        MESG_Reset(m);
        mp->total_releases++;
	mp->total_release_bytes += m->real_size;
        mp->mem = g_slist_prepend(mp->mem,m);
}

ST_MemorySegment *MEPO_GetMemorySegment(ST_MemoryPool *mp){
        GSList *item = NULL;

        item = g_slist_nth(mp->mem,0);
        if (item!= NULL) {
		ST_MemorySegment *m = (ST_MemorySegment*)item->data;
		
                mp->mem = g_slist_remove_link(mp->mem,item);
                mp->total_acquires++;
		mp->total_acquire_bytes += m->real_size;
                return m;
        }
        mp->total_errors++;
        return NULL;
}

void MEPO_Stats(ST_MemoryPool *mp){
	fprintf(stdout,"Memory pool statistics\n");
	fprintf(stdout,"\tacquire bytes:%d\n\treleases bytes:%d\n",mp->total_release_bytes,mp->total_acquire_bytes);
        fprintf(stdout,"\tblocks:%d\n\treleases:%d\n",g_slist_length(mp->mem),mp->total_releases);
        fprintf(stdout,"\tacquires:%d\n\terrors:%d\n",mp->total_acquires,mp->total_errors);
	return;
}
