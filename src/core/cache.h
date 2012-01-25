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

#ifndef _CACHE_H_
#define _CACHE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <glib.h>
#include "debug.h"

enum {
	NODE_TYPE_STATIC = 0,
	NODE_TYPE_DYNAMIC
};

enum {
	CACHE_HEADER = 0,
	CACHE_PARAMETER 
};

struct ST_CacheNode {
	int32_t matchs;
	int type;
};

typedef struct ST_CacheNode ST_CacheNode;

struct ST_Cache {
	GHashTable *header_cache;
	GHashTable *parameter_cache;
	int32_t header_hits;
	int32_t header_fails;
	int32_t parameter_hits;
	int32_t parameter_fails;
	/* Parameters related to opcodes */
	int32_t header_suspicious_opcodes;
	int32_t parameter_suspicious_opcodes;
};

typedef struct ST_Cache ST_Cache;

ST_Cache *CACH_Init(void);
void CACH_Destroy(ST_Cache *c);
void CACH_AddHeaderToCache(ST_Cache *c,char *value,int type);
void CACH_AddParameterToCache(ST_Cache *c,char *value,int type);
ST_CacheNode *CACH_GetHeaderFromCache(ST_Cache *c,char *value);
ST_CacheNode *CACH_GetParameterFromCache(ST_Cache *c,char *value);
void CACH_Stats(ST_Cache *c);

int32_t CACH_GetNumberHeaders(ST_Cache *c);
int32_t CACH_GetNumberParameters(ST_Cache *c);

#endif
