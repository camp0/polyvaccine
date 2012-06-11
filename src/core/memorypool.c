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
 * MEPO_ResizeFlowPool - Reize the memorypool with a specific value 
 *
 * @param p
 * @param value
 * 
 */

void MEPO_ResizeMemoryPool(ST_MemoryPool *mp,int value){
	int items;

	items = g_slist_length(mp->pool->items);

	if(value > items) { // increment the pool
       		MEPO_IncrementMemoryPool(mp,(value-items));
	}else{
		if(value < items) { // decrement the pool
        		MEPO_DecrementMemoryPool(mp,(items-value));	
		}
	} 
	POOL_Reset(mp->pool);
        return ;
}


/**
 * MEPO_Init - Inits the memory pool 
 *
 */
ST_MemoryPool *MEPO_Init() {
	ST_MemoryPool *mp = NULL;

	mp = (ST_MemoryPool*)g_new(ST_MemoryPool,1);
	mp->pool = POOL_Init();
        mp->total_release_bytes = 0;
        mp->total_acquire_bytes = 0;
	mp->total_allocated = 0;
	MEPO_IncrementMemoryPool(mp,MAX_MEMORY_SEGMENTS_PER_POOL);
	return mp;
}

/**
 * MEPO_Destroy - Destroy the memory pool 
 *
 * @param mp the ST_MemoryPool to destroy 
 */
void MEPO_Destroy(ST_MemoryPool *mp){
	MEPO_DecrementMemoryPool(mp,POOL_GetNumberItems(mp->pool));
	POOL_Destroy(mp->pool);
	g_free(mp);
}

int MEPO_GetNumberMemorySegments(ST_MemoryPool *mp){
	return POOL_GetNumberItems(mp->pool);
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
		POOL_AddItem(mp->pool,m);
		mp->total_allocated++;
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

        if (value > POOL_GetNumberItems(mp->pool))
                r = POOL_GetNumberItems(mp->pool);
        else
                r = value;

        for (i = 0;i<r;i++){
		m = (ST_MemorySegment*)POOL_GetItem(mp->pool);
		if(m) {
			mp->total_acquire_bytes += m->real_size;
			MESG_Destroy(m);
			mp->total_allocated--;
		}
        }
	return TRUE;
}

void MEPO_AddMemorySegment(ST_MemoryPool *mp,ST_MemorySegment *m){

	if(m == NULL) 
		return;
        MESG_Reset(m);
	mp->total_release_bytes += m->real_size;
	POOL_AddItem(mp->pool,m);
}

ST_MemorySegment *MEPO_GetMemorySegment(ST_MemoryPool *mp){
	ST_MemorySegment *m = NULL;

	m = POOL_GetItem(mp->pool);
	if(m)
		mp->total_acquire_bytes += m->real_size;
        return m;
}

void MEPO_Stats(ST_MemoryPool *mp,FILE *out){
	int32_t value = mp->total_allocated * (sizeof(ST_MemorySegment)+MAX_SEGMENT_SIZE);
	char *unit = "Bytes";

	if((value / 1024)>0){
		unit = "KBytes";
		value = value / 1024;
	}
	if((value / 1024)>0){
		unit = "MBytes";
		value = value / 1024;
	}
	
	fprintf(out,"Memory pool statistics\n");
	fprintf(out,"\tmemory size:%d bytes\n",sizeof(ST_MemorySegment));
	fprintf(out,"\tallocate memory:%d %s\n",value,unit);
	fprintf(out,"\tacquire bytes:%d\n\treleases bytes:%d\n",mp->total_release_bytes,mp->total_acquire_bytes);
        fprintf(out,"\tblocks:%d\n\treleases:%d\n",POOL_GetNumberItems(mp->pool),mp->pool->total_releases);
        fprintf(out,"\tacquires:%d\n\terrors:%d\n",mp->pool->total_acquires,mp->pool->total_errors);
	return;
}
