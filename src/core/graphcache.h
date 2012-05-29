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

#ifndef _GRAPHGACHE_H_
#define _GRAPHGACHE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <string.h>
#include <glib.h>
#include "debug.h"

enum node_types {
	NODE_TYPE_REGULAR = 0, // A simple resorce as a image,
	NODE_TYPE_MEDIUM, // The resource implies cpu has access to database, cgi, etc...
	NODE_TYPE_BIG // The resouce is a big file that implies bandwith comsumption, also a POST with the upload
} ;

struct ST_GraphNode {
	GString *uri;
	int id_uri;
	int cost;
	int32_t hits;
	enum node_types type;
};

typedef struct ST_GraphNode ST_GraphNode;

struct ST_GraphLink {
	GHashTable *uris;
	GString *uri;
	int id_uri,hited;
	enum node_types type;
};

typedef struct ST_GraphLink ST_GraphLink;

struct ST_GraphCache {
	GHashTable *uris;
	int32_t total_links;
	int32_t total_hits;
	int32_t total_fails;
	int32_t total_nodes;
	int32_t total_node_hits;
	int32_t total_ids;
	int statistics_level;
	int32_t size_memory; // total bytes allocated
};

typedef struct ST_GraphCache ST_GraphCache;

ST_GraphCache *GACH_Init(void);
void GACH_Destroy(ST_GraphCache *gc);
void GACH_Stats(ST_GraphCache *gc);
void GACH_SetStatisticsLevel(ST_GraphCache *gc, int level);
void GACH_AddLink(ST_GraphCache *gc,char *urisrc, char *uridst, int cost);
ST_GraphNode *GACH_AddGraphNodeFromLink(ST_GraphCache *gc,ST_GraphLink *link, char *uridst, int cost);
void GACH_AddBaseLink(ST_GraphCache *gc,char *uri);
ST_GraphLink *GACH_GetBaseLink(ST_GraphCache *gc,char *uri);
ST_GraphNode *GACH_GetGraphNodeFromLink(ST_GraphCache *gc,ST_GraphLink *link, char *uri); 
ST_GraphNode *GACH_GetGraphNode(ST_GraphCache *gc,char *urisrc, char *uridst); 
int GACH_GetLinkCost(ST_GraphCache *gc, char *urisrc, char *uridst); 

#endif
