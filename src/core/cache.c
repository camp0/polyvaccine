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

#include "cache.h"
#include "debug.h"

/**
 * CACH_Init - Initalize the cache
 *
 */
ST_Cache *CACH_Init(){
	ST_Cache *c = NULL;
	c = (ST_Cache*)g_new(ST_Cache,1);

	c->header_cache = g_hash_table_new(g_str_hash,g_str_equal);
	c->parameter_cache = g_hash_table_new(g_str_hash,g_str_equal);
	c->header_hits = 0;
	c->header_fails = 0;
	c->parameter_hits = 0;
	c->parameter_fails = 0;
	c->memorysize = 0;
        c->header_suspicious_opcodes = 0;
        c->parameter_suspicious_opcodes = 0;

	return c;
}

static gboolean CACH_DestroyCallback(gpointer k , gpointer v, gpointer p ) {

        g_free(k);
        g_free(v);
        return TRUE;
}

/**
 * CACH_Destroy - Destroy all the fields of the cache
 */
void CACH_Destroy(ST_Cache *c) {
        g_hash_table_foreach_remove(c->header_cache,CACH_DestroyCallback,NULL);
        g_hash_table_foreach_remove(c->parameter_cache,CACH_DestroyCallback,NULL);
        g_hash_table_destroy(c->header_cache);
        g_hash_table_destroy(c->parameter_cache);
	g_free(c);	
}


void __CACH_AddToCache(ST_Cache *c, GHashTable *t, char *value, int type){
        ST_CacheNode *node = NULL;

        node = (ST_CacheNode*)g_hash_table_lookup(t,(gchar*)value);
        if(node == NULL) { 
                node = g_new(ST_CacheNode,1);
                node->type = type;
                node->matchs = 0;
                node->uri = g_strdup(value);

                c->memorysize += strlen(value);
                g_hash_table_insert(t,node->uri,node);
        }
        return;
}

/**
 * CACH_AddHeaderToCache - Adds a new header cacheable field to the cache
 * 
 * @param c The cache
 * @param value The header field
 * @param type
 */
void CACH_AddHeaderToCache(ST_Cache *c,char *value,int type) {

	__CACH_AddToCache(c,c->header_cache,value,type);
	return;
}

/**
 * CACH_AddParameterToCache - Adds a new parameter cacheable field to the cache
 * 
 * @param c The cache
 * @param value The header field
 * @param type
 */
void CACH_AddParameterToCache(ST_Cache *c,char *value,int type) {
	
	__CACH_AddToCache(c,c->parameter_cache,value,type);
	return; 
}

/**
 * CACH_GetHeaderFromCache - Gets a Header ST_CacheNode from the cache if exists
 * 
 * @param c The cache
 * @param value The header field
 * 
 */
ST_CacheNode *CACH_GetHeaderFromCache(ST_Cache *c,char *value) {
	ST_CacheNode *nod = NULL;

	nod = (ST_CacheNode*)g_hash_table_lookup(c->header_cache,(gchar*)value);
	if (nod != NULL) {
		c->header_hits++;
		nod->matchs++;
	}else{
		c->header_fails++;
	}
	return nod;
}

/**
 * CACH_GetParameterFromCache - Gets a Parameter ST_CacheNode from the cache if exists
 * 
 * @param c The cache
 * @param value The header field
 * 
 */
ST_CacheNode *CACH_GetParameterFromCache(ST_Cache *c,char *value) {
        ST_CacheNode *nod = NULL;

        nod = (ST_CacheNode*)g_hash_table_lookup(c->parameter_cache,(gchar*)value);
        if (nod != NULL) {
                c->parameter_hits++;
                nod->matchs++;
        }else{
                c->parameter_fails++;
        }
        return nod;
}

/**
 * CACH_Stats - Shows the statistcis of a ST_Cache 
 * 
 * @param c The cache
 * @param level of messages
 * 
 */
void CACH_Stats(ST_Cache *c,int level) {
	GHashTableIter iter;
	gpointer k,v;
	int h_effectiveness;
	int p_effectiveness;
	int32_t value = c->memorysize;
	char *unit = "Bytes";

        if((value / 1024)>0){
                unit = "KBytes";
                value = value / 1024;
        }
        if((value / 1024)>0){
                unit = "MBytes";
                value = value / 1024;
        }

	h_effectiveness = 0;
	p_effectiveness = 0;
	if((c->header_hits+c->header_fails)>0){
		h_effectiveness = (c->header_hits*100)/(c->header_hits+c->header_fails);
	}	
	if((c->parameter_hits+c->parameter_fails)>0){
		p_effectiveness = (c->parameter_hits*100)/(c->parameter_hits+c->parameter_fails);
	}	
	fprintf(stdout,"Cache(0x%x) statistics\n",c);
	fprintf(stdout,"\tallocated memory:%d %s\n",value,unit);
	fprintf(stdout,"\tHeader hits = %d\n\tHeader fails = %d\n",c->header_hits,c->header_fails);
	fprintf(stdout,"\tHeader effectiveness = %d%%\n",h_effectiveness);
	fprintf(stdout,"\tParameter hits = %d\n\tParameter fails = %d\n",c->parameter_hits,c->parameter_fails);
	fprintf(stdout,"\tParameter effectiveness = %d%%\n",p_effectiveness);
	fprintf(stdout,"\tSuspicious Headers = %d\n\tSuspicious parameters = %d\n",
		c->header_suspicious_opcodes,c->parameter_suspicious_opcodes);

	if(level >1){
		fprintf(stdout,"\tCache Headers\n");
		g_hash_table_iter_init (&iter, c->header_cache);
		while (g_hash_table_iter_next (&iter, &k, &v)) {
			ST_CacheNode *nod = (ST_CacheNode*)v;
			fprintf(stdout,"\t\tHeader(%s)matchs(%d)\n",(gchar*)k,nod->matchs);	
		}
		fprintf(stdout,"\tCache Parameters\n");
		g_hash_table_iter_init (&iter, c->parameter_cache);
		while (g_hash_table_iter_next (&iter, &k, &v)) {
			ST_CacheNode *nod = (ST_CacheNode*)v;
			fprintf(stdout,"\t\tParameter(%s)matchs(%d)\n",(gchar*)k,nod->matchs);	
		}
	}
	return;
}

int32_t CACH_GetNumberHeaders(ST_Cache *c){
	return g_hash_table_size(c->header_cache);
}

int32_t CACH_GetNumberParameters(ST_Cache *c){
	return g_hash_table_size(c->parameter_cache);
}

