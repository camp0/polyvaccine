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

#ifndef _HTTPCACHE_H_
#define _HTTPCACHE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <glib.h>
#include "debug.h"

enum {
	HTTP_NODE_TYPE_STATIC = 0,
	HTTP_NODE_TYPE_DYNAMIC
};

enum {
	HTTP_CACHE_HEADER = 0,
	HTTP_CACHE_PARAMETER 
};

struct ST_HttpNode {
	int32_t matchs;
	int type;
};

typedef struct ST_HttpNode ST_HttpNode;

struct ST_HttpCache {
	GHashTable *http_header_cache;
	GHashTable *http_parameter_cache;
	int32_t header_hits;
	int32_t header_fails;
	int32_t parameter_hits;
	int32_t parameter_fails;
	/* Parameters related to opcodes */
	int32_t header_suspicious_opcodes;
	int32_t parameter_suspicious_opcodes;
};

typedef struct ST_HttpCache ST_HttpCache;

ST_HttpCache *HTCC_Init(void);
void HTCC_Destroy(ST_HttpCache *c);
void HTCC_AddHeaderToCache(ST_HttpCache *c,char *value,int type);
void HTCC_AddParameterToCache(ST_HttpCache *c,char *value,int type);
ST_HttpNode *HTCC_GetHeaderFromCache(ST_HttpCache *c,char *value);
ST_HttpNode *HTCC_GetParameterFromCache(ST_HttpCache *c,char *value);
void HTCC_Stats(ST_HttpCache *c);

int32_t HTCC_GetNumberHttpHeaders(ST_HttpCache *c);
int32_t HTCC_GetNumberHttpParameters(ST_HttpCache *c);

#endif
