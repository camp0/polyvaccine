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

#include "nfpacketpool.h"

/**
 * NFPO_Init - Inits the ST_Flow pool structs.
 *
 * @return ST_NfFlowPool 
 *
 */
ST_NfFlowPool *NFPO_Init() {
	ST_NfFlowPool *pool = NULL;

	pool = g_new(ST_NfFlowPool,1);
	pool->flows = NULL;	
        pool->total_releases = 0;
        pool->total_acquires = 0;
        pool->total_errors = 0;

	NFPO_IncrementFlowPool(pool,MAX_FLOWS_PER_POOL);
	return pool;
}

/**
 * NFPO_Stats - Show statistics of the pool.
 *
 * @param ST_NfFlowPool
 *
 */
void NFPO_Stats(ST_NfFlowPool *p){
	fprintf(stdout,"FlowPool statistics\n");
	fprintf(stdout,"\tflows:%d\n\treleases:%d\n",g_slist_length(p->flows),p->total_releases);
	fprintf(stdout,"\tacquires:%d\n\terrors:%d\n",p->total_acquires,p->total_errors);
	return;
}

/**
 * NFPO_Stats - Show statistics of the pool.
 *
 * @param ST_NfFlowPool
 *
 */
void NFPO_Destroy(ST_NfFlowPool *p){
	NFPO_DecrementFlowPool(p,g_slist_length(p->flows));
	g_slist_free(p->flows);
	g_free(p);
}

/**
 * NFPO_GetNumberFlows - returns the number of flows on the pool
 *
 * @return a integer
 *
 */
int NFPO_GetNumberFlows(ST_NfFlowPool *p){
	return g_slist_length(p->flows);
}

/**
 * NFPO_IncrementFlowPool 
 *
 * @param ST_NfFlowPool
 * @param value 
 *
 */
int NFPO_IncrementFlowPool(ST_NfFlowPool *p,int value){
	int i;

        if (value < 1)
                return FALSE;

        for (i = 0;i<value;i++){
		ST_Flow *f = g_new0(ST_Flow,1);
                p->flows = g_slist_prepend(p->flows,f);
	}
        return TRUE;
}

/**
 * NFPO_DecrementFlowPool 
 *
 * @param ST_NfFlowPool
 * @param value
 *
 */
int NFPO_DecrementFlowPool(ST_NfFlowPool *p,int value) {
	ST_Flow *f;
	int i,r;

        if (value > g_slist_length(p->flows))
                r = g_slist_length(p->flows);
        else
                r = value;

        for (i = 0;i<r;i++){
                GSList *item = g_slist_nth(p->flows,0);
                if (item != NULL) {
                        p->flows = g_slist_remove_link(p->flows,item);
                        f = (ST_Flow*)item->data;
                        g_free(f);
                }
        }
	return TRUE;
}

/**
 * NFPO_AddFlow
 *
 * @param ST_NfFlowPool
 * @param ST_Flow
 *
 */
void NFPO_AddFlow(ST_NfFlowPool *p,ST_Flow *flow){
        p->total_releases++;
        p->flows = g_slist_prepend(p->flows,flow);
}

/**
 * NFPO_GetFlow 
 *
 * @return ST_Flow
 *
 */
ST_Flow *NFPO_GetFlow(ST_NfFlowPool *p){
        GSList *item = NULL;

        item = g_slist_nth(p->flows,0);
        if (item!= NULL) {
                p->flows = g_slist_remove_link(p->flows,item);
                p->total_acquires++;
                return (ST_Flow*)item->data;
        }
        p->total_errors++;
        return NULL;
}


