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

#include "pool.h"

/**
 * POOL_Reset - Resets the counters of an ST_Pool
 *
 * @param p
 * 
 */
void POOL_Reset(ST_Pool *p){

        p->total_releases = 0;
        p->total_acquires = 0;
        p->total_errors = 0;
	return;
}


/**
 * POOL_Init - Initialize a pool 
 *
 * @return ST_Pool
 */

ST_Pool *POOL_Init() {
	ST_Pool *pool = NULL;

	pool = (ST_Pool*)g_new(ST_Pool,1);
	pool->items = NULL;
	POOL_Reset(pool);	

	return pool;
}

/**
 * POOL_Destroy - free a ST_Pool
 *
 * @param p the ST_Pool to free
 */
void POOL_Destroy(ST_Pool *p){
	register int i;
	GSList *item = NULL;

        for (i = 0;i<POOL_GetNumberItems(p);i++){
                item = g_slist_nth(p->items,0);
                if (item != NULL) {
                        p->items = g_slist_remove_link(p->items,item);
                        g_free(item->data);
			g_slist_free_1(item);
			item = NULL;
                }
        }
	g_slist_free(p->items);
	g_free(p);
	p = NULL;
	return;
}

int POOL_GetNumberItems(ST_Pool *p){
	return g_slist_length(p->items);
}

/**
 * POOL_AddItem - Adds a item to a ST_Pool 
 *
 * @param p the ST_Pool
 * @param item  
 */

void POOL_AddItem(ST_Pool *p,void *item){
	if(item != NULL){ 
        	p->total_releases++;
        	p->items = g_slist_prepend(p->items,item);
	}
}

/**
 * POOL_GetItem - Gets a item from a ST_Pool 
 *
 * @param p the ST_Pool
 *
 * @return item
 */

void *POOL_GetItem(ST_Pool *p){
        GSList *item = NULL;
	void *value;

        item = g_slist_nth(p->items,0);
        if (item!= NULL) {
               	p->items = g_slist_remove_link(p->items,item);
                p->total_acquires++;
		value = item->data;
                return value;
        }
        p->total_errors++;
        return NULL;
}


