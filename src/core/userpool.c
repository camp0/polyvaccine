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

#include "userpool.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_FILTER_USERPOOL_INTERFACE
#include "log.h"

/**
 * USPO_Init - Initialize a user pool 
 *
 * @return ST_UserPool
 */

ST_UserPool *USPO_Init() {
	ST_UserPool *pool = NULL;

	pool = g_new(ST_UserPool,1);
	pool->pool = POOL_Init(); 

	USPO_IncrementUserPool(pool,MAX_USERS_PER_POOL);
	return pool;
}

/**
 * USPO_Stats - Shows statistics of a ST_UserPool
 *
 * @param p
 * @param out
 */

void USPO_Stats(ST_UserPool *p,FILE *out){
	int32_t value = MAX_USERS_PER_POOL * sizeof(ST_User);
        char *unit = "Bytes";

        if((value / 1024)>0){
                unit = "KBytes";
                value = value / 1024;
        }
        if((value / 1024)>0){
                unit = "MBytes";
                value = value / 1024;
        }

	fprintf(out,"UserPool statistics\n");
	fprintf(out,"\tuser size:%d bytes\n",sizeof(ST_User));
	fprintf(out,"\tallocated memory:%d %s\n",value,unit);
	fprintf(out,"\tusers:%d\n\treleases:%d\n",POOL_GetNumberItems(p->pool),p->pool->total_releases);
	fprintf(out,"\tacquires:%d\n\terrors:%d\n",p->pool->total_acquires,p->pool->total_errors);
	return;
}

/**
 * USPO_Destroy - free a ST_UserPool
 *
 * @param p the ST_UserPool to free
 */
void USPO_Destroy(ST_UserPool *p){

	USPO_DecrementUserPool(p,POOL_GetNumberItems(p->pool));
	POOL_Destroy(p->pool);
	g_free(p);
	p = NULL;
}

int USPO_GetNumberUsers(ST_UserPool *p){
	return POOL_GetNumberItems(p->pool);
}

/**
 * USPO_IncrementUserPool - Increments the items of a ST_UserPool 
 *
 * @param p the ST_UserPool
 * @param value the number of new ST_User to alloc
 */

int USPO_IncrementUserPool(ST_UserPool *p,int value){
	int i;

        if (value < 1)
                return FALSE;
	LOG(POLYLOG_PRIORITY_INFO,
		"Allocating %d users on pool, current users on pool %d",value,POOL_GetNumberItems(p->pool));

        for (i = 0;i<value;i++){
		ST_User *user = USER_Init();
		POOL_AddItem(p->pool,user);
	}
        return TRUE;
}

/**
 * USPO_DecrementUserPool - Decrements the items of a ST_UserPool 
 *
 * @param p the ST_UserPool
 * @param value the number of new ST_User to free 
 */

int USPO_DecrementUserPool(ST_UserPool *p,int value) {
	ST_User *user;
	int i,r;

        if (value > POOL_GetNumberItems(p->pool))
                r = POOL_GetNumberItems(p->pool);
        else
                r = value;

	LOG(POLYLOG_PRIORITY_INFO,
		"Freeing %d users on pool",r);
        for (i = 0;i<r;i++){
		user = (ST_User*)POOL_GetItem(p->pool);
		if(user)
			USER_Destroy(user);
        }
	return TRUE;
}

/**
 * USPO_AddUser - Adds a ST_User to a ST_UserPool 
 *
 * @param p the ST_UserPool
 * @param user 
 */

void USPO_AddUser(ST_UserPool *p,ST_User *user){
	if(user != NULL){ 
        	USER_Reset(user);
		POOL_AddItem(p->pool,user);
	}
}

/**
 * USPO_GetUser - Gets a ST_User from a ST_UserPool 
 *
 * @param p the ST_UserPool
 *
 * @return ST_User
 */

ST_User *USPO_GetUser(ST_UserPool *p){
	ST_User *user = NULL;

	user = POOL_GetItem(p->pool);
	return user;
}


