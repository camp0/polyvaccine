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

#ifndef _POOL_H_
#define _POOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <glib.h>

struct ST_Pool {
	GSList *items;
	int32_t total_releases;
	int32_t total_acquires;
	int32_t total_errors;
};

typedef struct ST_Pool ST_Pool;

ST_Pool *POOL_Init(void);
void POOL_Destroy(ST_Pool *p);
void POOL_AddItem(ST_Pool *p,void *item);
void *POOL_GetItem(ST_Pool *p);	
int POOL_GetNumberItems(ST_Pool *p);
void POOL_Reset(ST_Pool *p);

#endif
