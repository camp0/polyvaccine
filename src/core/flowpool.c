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

ST_FlowPool *FLPO_Init() {
	ST_FlowPool *pool = NULL;

	pool = (ST_FlowPool*)g_new(ST_FlowPool,1);
	pool->flows = NULL;	
        pool->total_releases = 0;
        pool->total_acquires = 0;
        pool->total_errors = 0;

	FLPO_IncrementFlowPool(pool,MAX_FLOWS_PER_POOL);
	return pool;
}

void FLPO_Stats(ST_FlowPool *p){
	fprintf(stdout,"FlowPool statistics\n");
	fprintf(stdout,"\tflows:%d\n\treleases:%d\n",g_slist_length(p->flows),p->total_releases);
	fprintf(stdout,"\tacquires:%d\n\terrors:%d\n",p->total_acquires,p->total_errors);
	return;
}
void FLPO_Destroy(ST_FlowPool *p){
	FLPO_DecrementFlowPool(p,g_slist_length(p->flows));
	g_slist_free(p->flows);
	g_free(p);
}

int FLPO_GetNumberFlows(ST_FlowPool *p){
	return g_slist_length(p->flows);
}

int FLPO_IncrementFlowPool(ST_FlowPool *p,int value){
	int i;

        if (value < 1)
                return FALSE;

        for (i = 0;i<value;i++){
		ST_HttpFlow *f = g_new0(ST_HttpFlow,1);
		f->memhttp = NULL;
		HTFL_Reset(f);	
                p->flows = g_slist_prepend(p->flows,f);
	}
        return TRUE;
}

int FLPO_DecrementFlowPool(ST_FlowPool *p,int value) {
	ST_HttpFlow *f;
	int i,r;

        if (value > g_slist_length(p->flows))
                r = g_slist_length(p->flows);
        else
                r = value;

        for (i = 0;i<r;i++){
                GSList *item = g_slist_nth(p->flows,0);
                if (item != NULL) {
                        p->flows = g_slist_remove_link(p->flows,item);
                        f = (ST_HttpFlow*)item->data;
                        g_free(f);
                }
        }
	return TRUE;
}

void FLPO_AddFlow(ST_FlowPool *p,ST_HttpFlow *flow){
        HTFL_Reset(flow);
        p->total_releases++;
        p->flows = g_slist_prepend(p->flows,flow);
}

ST_HttpFlow *FLPO_GetFlow(ST_FlowPool *p){
        GSList *item = NULL;

        item = g_slist_nth(p->flows,0);
        if (item!= NULL) {
                p->flows = g_slist_remove_link(p->flows,item);
                p->total_acquires++;
                return (ST_HttpFlow*)item->data;
        }
        p->total_errors++;
        return NULL;
}


