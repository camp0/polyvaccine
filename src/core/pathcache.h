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

#ifndef _PATHPACHE_H_
#define _PATHPACHE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <glib.h>
#include "debug.h"

struct ST_PathNode {
	gchar *path;
	int32_t hits;
};

typedef struct ST_PathNode ST_PathNode;

struct ST_PathCache {
	GHashTable *paths;
	int32_t total_paths;
	int32_t total_hits;
	int32_t total_fails;
	int statistics_level;
	int64_t size_memory; // total bytes allocated
};

typedef struct ST_PathCache ST_PathCache;

ST_PathCache *PACH_Init(void);
ST_PathNode *PACH_InitPathNode(void);
void PACH_Destroy(ST_PathCache *pc);
void PACH_Stats(ST_PathCache *pc);
ST_PathNode *PACH_GetPath(ST_PathCache *pc,char *path);
ST_PathNode *PACH_AddPath(ST_PathCache *pc,char *path);
void PACH_ShowPathCache(ST_PathCache *pc);
void PACH_SetStatisticsLevel(ST_PathCache *pc, int level);

#endif
