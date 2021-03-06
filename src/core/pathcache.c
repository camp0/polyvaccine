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

#include "pathcache.h"
#include "debug.h"

/**
 * PACH_GetPath - Gets an existing path 
 *
 * @param pc The cache
 * @param path The header field
 */

ST_PathNode *PACH_GetPath(ST_PathCache *pc,char *path){
	ST_PathNode *path_n;

	path_n = (ST_PathNode*)g_hash_table_lookup(pc->paths,(gchar*)path);
	if(path_n == NULL) {
		pc->total_fails++;
	}else{
		path_n->hits++;
		pc->total_hits ++;
	}
	return path_n;
}

/**
 * PACH_InitPathNode 
 *
 * @return ST_PathNode 
 */

ST_PathNode *PACH_InitPathNode(){
	ST_PathNode *path_n = NULL;

	path_n = g_new0(ST_PathNode,1);
	path_n->hits = 0;
	path_n->path = NULL;

	return path_n;
}

/**
 * PACH_AddPath - Adds a path to the cache. 
 *
 * @param pc The ST_PathCache
 * @param path
 *
 * @return ST_PathNode 
 */
ST_PathNode *PACH_AddPath(ST_PathCache *pc, char *path){
	ST_PathNode *path_n = NULL;

	path_n = (ST_PathNode*)g_hash_table_lookup(pc->paths,(gchar*)path);
	if(path_n == NULL) {
		path_n = PACH_InitPathNode();

		path_n->path = g_strdup(path);
		g_hash_table_insert(pc->paths,path_n->path,path_n);
		pc->total_paths++;
		pc->size_memory += sizeof(path_n)+strlen(path);
	}
	return path_n;
}


void PACH_ShowPathCache(ST_PathCache *pc){
        GHashTableIter iter;
        gpointer k,v;
	ST_PathNode *node;

	fprintf(stdout,"\tPath nodes\n");
	g_hash_table_iter_init (&iter, pc->paths);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		node = (ST_PathNode*)v;
		fprintf(stdout,"\t\tPath(%s)Hits(%d)\n",node->path,node->hits);
	}
	return;
}


/**
 * PACH_Init - Initalize the pathcache
 *
 */
ST_PathCache *PACH_Init(){
	ST_PathCache *pc = NULL;

	pc = (ST_PathCache*)g_new(ST_PathCache,1);

	pc->paths = g_hash_table_new(g_str_hash,g_str_equal);
	pc->total_paths = 0;
	pc->total_fails = 0;
	pc->total_hits = 0;
	pc->statistics_level = 0;	
	pc->size_memory = 0;
	return pc;
}

/**
 * PACH_Destroy - Destroy all the fields of the pathcache
 */
void PACH_Destroy(ST_PathCache *pc) {
	GHashTableIter iter;
	gpointer k,v;
	ST_PathNode *node;

	g_hash_table_iter_init (&iter, pc->paths);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		node = (ST_PathNode*)v;
	
		g_free(node->path);
		node->path = NULL;
		g_free(node);
	} 
	g_hash_table_destroy(pc->paths);
	g_free(pc);
	pc = NULL;
	return;
}

/**
 * PACH_Stats - Shows the statistcis of a ST_PathCache 
 * 
 * @param c The pathcache
 * 
 */
void PACH_Stats(ST_PathCache *pc) {
	int effectiveness;
	int32_t value = pc->size_memory;
        char *unit = "Bytes";

        if((value / 1024)>0){
                unit = "KBytes";
                value = value / 1024;
        }
        if((value / 1024)>0){
                unit = "MBytes";
                value = value / 1024;
        }

	effectiveness = 0;
	if((pc->total_hits+pc->total_fails)>0){
		effectiveness = (pc->total_hits*100)/(pc->total_hits+pc->total_fails);
	}	
	fprintf(stdout,"PathCache(0x%x) statistics, level %d\n",pc,pc->statistics_level);
	fprintf(stdout,"\tallocated memory:%d %s\n",value,unit);
	fprintf(stdout,"\tPaths = %"PRId32" \n",pc->total_paths);
	fprintf(stdout,"\tPath hits = %"PRId32"\n\tPath fails = %"PRId32"\n",pc->total_hits,pc->total_fails);
	fprintf(stdout,"\tPath effectiveness = %d%%\n",effectiveness);

	if(pc->statistics_level > 1 ) {
		PACH_ShowPathCache(pc);
	}
	return;
}

/**
 * PACH_SetStatisticsLevel - Sets the statistcis level of a ST_PathCache 
 * 
 * @param pc The pathcache
 * @param level 
 */
void PACH_SetStatisticsLevel(ST_PathCache *gc,int level) {gc->statistics_level = level;};
