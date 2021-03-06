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

#include "flowpool.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_FILTER_FLOWPOOL_INTERFACE
#include "log.h"


/**
 * FLPO_ResizeFlowPool - Reize the flowpool with a specific value 
 *
 * @param p
 * @param value
 * 
 */

void FLPO_ResizeFlowPool(ST_FlowPool *p,int value){
	ST_GenericFlow *f;
	int items;
	register int i;

	items = g_slist_length(p->pool->items);

	if(value > items) { // increment the pool
		FLPO_IncrementFlowPool(p,(value-items));
	}else{
		if(value < items) { // decrement the pool
        		FLPO_DecrementFlowPool(p,(items-value));	
		}
	} 
	POOL_Reset(p->pool);
        return ;
}

/**
 * FLPO_Init - Initialize a flow pool 
 *
 * @return ST_FlowPool
 */

ST_FlowPool *FLPO_Init() {
	ST_FlowPool *pool = NULL;

	pool = g_new(ST_FlowPool,1);
	pool->pool = POOL_Init(); 

	pool->total_allocated = 0;
	FLPO_IncrementFlowPool(pool,MAX_FLOWS_PER_POOL);
	return pool;
}

/**
 * FLPO_Stats - Shows statistics of a ST_FlowPool
 *
 */

void FLPO_Stats(ST_FlowPool *p,FILE *out){
	int items = g_slist_length(p->pool->items);
	int32_t value = p->total_allocated * sizeof(ST_GenericFlow);
        char *unit = "Bytes";

        if((value / 1024)>0){
                unit = "KBytes";
                value = value / 1024;
        }
        if((value / 1024)>0){
                unit = "MBytes";
                value = value / 1024;
        }

	fprintf(out,"FlowPool statistics\n");
	fprintf(out,"\tflow size:%d bytes\n",sizeof(ST_GenericFlow));
	fprintf(out,"\tallocated memory:%d %s\n",value,unit);
	fprintf(out,"\tflows:%d\n\treleases:%d\n",items,p->pool->total_releases);
	fprintf(out,"\tacquires:%d\n\terrors:%d\n",p->pool->total_acquires,p->pool->total_errors);
	return;
}

/**
 * FLPO_Destroy - free a ST_FlowPool
 *
 * @param p the ST_FlowPool to free
 */
void FLPO_Destroy(ST_FlowPool *p){
	FLPO_DecrementFlowPool(p,POOL_GetNumberItems(p->pool));
	POOL_Destroy(p->pool);
	g_free(p);
	p = NULL;
}

int FLPO_GetNumberFlows(ST_FlowPool *p){
	return POOL_GetNumberItems(p->pool);
}

/**
 * FLPO_IncrementFlowPool - Increments the items of a ST_FlowPool 
 *
 * @param p the ST_FlowPool
 * @param value the number of new ST_GenericFlows to alloc
 */

int FLPO_IncrementFlowPool(ST_FlowPool *p,int value){
	int i;

        if (value < 1)
                return FALSE;
	LOG(POLYLOG_PRIORITY_INFO,
		"Allocating %d flows on pool, current flows on pool %d",value,POOL_GetNumberItems(p->pool));

        for (i = 0;i<value;i++){
		ST_GenericFlow *f = g_new0(ST_GenericFlow,1);
		f->memory = NULL;
		GEFW_Reset(f);	
		POOL_AddItem(p->pool,f);
		p->total_allocated++;
	}
        return TRUE;
}

/**
 * FLPO_DecrementFlowPool - Decrements the items of a ST_FlowPool 
 *
 * @param p the ST_FlowPool
 * @param value the number of new ST_GenericFlows to free 
 */

int FLPO_DecrementFlowPool(ST_FlowPool *p,int value) {
	ST_GenericFlow *f;
	int i,r;

        if (value > POOL_GetNumberItems(p->pool))
                r = POOL_GetNumberItems(p->pool);
        else
                r = value;

	LOG(POLYLOG_PRIORITY_INFO,
		"Freeing %d flows on pool",r);
        for (i = 0;i<r;i++){
		f = (ST_GenericFlow*)POOL_GetItem(p->pool);
		if(f){
			GEFW_Destroy(f);
			p->total_allocated--;
		}
        }
	return TRUE;
}

/**
 * FLPO_AddFlow - Adds a ST_GenericFlow to a ST_FlowPool 
 *
 * @param p the ST_FlowPool
 * @param flow e 
 */

void FLPO_AddFlow(ST_FlowPool *p,ST_GenericFlow *flow){
	if(flow != NULL){ 
        	GEFW_Reset(flow);
		POOL_AddItem(p->pool,flow);
	}
}

/**
 * FLPO_GetFlow - Gets a ST_GenericFlow from a ST_FlowPool 
 *
 * @param p the ST_FlowPool
 *
 * @return ST_GenericFlow  
 */

ST_GenericFlow *FLPO_GetFlow(ST_FlowPool *p){
	ST_GenericFlow *f = NULL;

	f = POOL_GetItem(p->pool);
	return f;
}


