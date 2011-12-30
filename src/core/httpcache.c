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

#include "httpcache.h"
#include "debug.h"

/**
 * HTCC_Init - Initalize the http cache
 *
 */
ST_HttpCache *HTCC_Init(){
	ST_HttpCache *c = NULL;
	c = (ST_HttpCache*)g_new(ST_HttpCache,1);

	c->http_header_cache = g_hash_table_new(g_str_hash,g_str_equal);
	c->http_parameter_cache = g_hash_table_new(g_str_hash,g_str_equal);
	c->header_hits = 0;
	c->header_fails = 0;
	c->parameter_hits = 0;
	c->parameter_fails = 0;
        c->header_suspicious_opcodes = 0;
        c->parameter_suspicious_opcodes = 0;

	DEBUG0("httpCache(0x%x)\n",c);
	return c;
}

static gboolean HTCC_DestroyCallback(gpointer k , gpointer v, gpointer p ) {
        g_free(k);
        g_free(v);
        return TRUE;
}

/**
 * HTCC_Destroy - Destroy all the fields of the http cache
 */
void HTCC_Destroy(ST_HttpCache *c) {
        g_hash_table_foreach_remove(c->http_header_cache,HTCC_DestroyCallback,NULL);
        g_hash_table_foreach_remove(c->http_parameter_cache,HTCC_DestroyCallback,NULL);
        g_hash_table_destroy(c->http_header_cache);
        g_hash_table_destroy(c->http_parameter_cache);
	g_free(c);	
}

/**
 * HTCC_AddHeaderToCache - Adds a new header cacheable field to the http cache
 * 
 * @param c The http cache
 * @param value The http header field
 * @param type
 */
void HTCC_AddHeaderToCache(ST_HttpCache *c,char *value,int type) {
	ST_HttpNode *nod = g_new(ST_HttpNode,1);
	nod->type = type;
	nod->matchs = 0;

	g_hash_table_insert(c->http_header_cache,g_strdup(value),nod);
}

/**
 * HTCC_AddParameterToCache - Adds a new parameter cacheable field to the http cache
 * 
 * @param c The http cache
 * @param value The http header field
 * @param type
 */
void HTCC_AddParameterToCache(ST_HttpCache *c,char *value,int type) {
        ST_HttpNode *nod = g_new(ST_HttpNode,1);
        nod->type = type;
        nod->matchs = 0;

        g_hash_table_insert(c->http_parameter_cache,g_strdup(value),nod);
}

/**
 * HTCC_GetHeaderFromCache - Gets a Header ST_HttpNode from the cache if exists
 * 
 * @param c The http cache
 * @param value The http header field
 * 
 */
ST_HttpNode *HTCC_GetHeaderFromCache(ST_HttpCache *c,char *value) {
	ST_HttpNode *nod = NULL;

	nod = (ST_HttpNode*)g_hash_table_lookup(c->http_header_cache,(gchar*)value);
	if (nod != NULL) {
		c->header_hits++;
		nod->matchs++;
	}else{
		c->header_fails++;
	}
	return nod;
}

/**
 * HTCC_GetParameterFromCache - Gets a Parameter ST_HttpNode from the cache if exists
 * 
 * @param c The http cache
 * @param value The http header field
 * 
 */
ST_HttpNode *HTCC_GetParameterFromCache(ST_HttpCache *c,char *value) {
        ST_HttpNode *nod = NULL;

        nod = (ST_HttpNode*)g_hash_table_lookup(c->http_parameter_cache,(gchar*)value);
        if (nod != NULL) {
                c->parameter_hits++;
                nod->matchs++;
        }else{
                c->parameter_fails++;
        }
        return nod;
}

/**
 * HTCC_Stats - Shows the statistcis of a ST_HttpCache 
 * 
 * @param c The http cache
 * 
 */
void HTCC_Stats(ST_HttpCache *c) {
	GHashTableIter iter;
	gpointer k,v;

	fprintf(stdout,"HTTP Cache(0x%x) statistics\n",c);
	fprintf(stdout,"\tHeader hits = %d\n\tHeader fails = %d\n",c->header_hits,c->header_fails);
	fprintf(stdout,"\tParameter hits = %d\n\tParameter fails = %d\n",c->parameter_hits,c->parameter_fails);
	fprintf(stdout,"\tSuspicious Headers = %d\n\tSuspicious parameters = %d\n",
		c->header_suspicious_opcodes,c->parameter_suspicious_opcodes);
	fprintf(stdout,"\tHTTP Cache Headers\n");
	g_hash_table_iter_init (&iter, c->http_header_cache);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_HttpNode *nod = (ST_HttpNode*)v;
		fprintf(stdout,"\t\tHeader(%s)matchs(%d)\n",(gchar*)k,nod->matchs);	
	}
	fprintf(stdout,"\tHTTP Cache Parameters\n");
	g_hash_table_iter_init (&iter, c->http_parameter_cache);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_HttpNode *nod = (ST_HttpNode*)v;
		fprintf(stdout,"\t\tParameter(%s)matchs(%d)\n",(gchar*)k,nod->matchs);	
	}

	return;
}

int32_t HTCC_GetNumberHttpHeaders(ST_HttpCache *c){
	return g_hash_table_size(c->http_header_cache);
}

int32_t HTCC_GetNumberHttpParameters(ST_HttpCache *c){
	return g_hash_table_size(c->http_parameter_cache);
}
