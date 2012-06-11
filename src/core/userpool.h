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

#ifndef _USERPOOL_H_
#define _USERPOOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <glib.h>
#include "pool.h"
#include "user.h"
#include "interfaces.h"

#define MAX_USERS_PER_POOL 1024 * 16 

struct ST_UserPool {
	ST_Pool *pool;
	int32_t total_allocated;
};

typedef struct ST_UserPool ST_UserPool;

ST_UserPool *USPO_Init(void);
void USPO_Destroy(ST_UserPool *p);
void USPO_AddUser(ST_UserPool *p,ST_User *user);
ST_User *USPO_GetUser(ST_UserPool *p);	
int USPO_GetNumberUsers(ST_UserPool *p);
int USPO_IncrementUserPool(ST_UserPool *p,int value);
int USPO_DecrementUserPool(ST_UserPool *p,int value);
void USPO_Stats(ST_UserPool *p,FILE *out);
void USPO_ResizeUserPool(ST_UserPool *p,int value);

#endif
