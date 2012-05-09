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

#include "graphcache.h"
#include "debug.h"

/**
 * GACH_GetLinkCost - Adds a new header cacheable field to the cache
 *
 * @param c The cache
 * @param value The header field
 * @param type
 */

int GACH_GetLinkCost(ST_GraphCache *gc, char *urisrc, char *uridst){
        ST_GraphLink *link;
        ST_GraphNode *node;

        link = (ST_GraphLink*)g_hash_table_lookup(gc->uris,(gchar*)urisrc);
        if (link != NULL) {
                node = (ST_GraphNode*)g_hash_table_lookup(link->uris,(gchar*)uridst);
                if(node != NULL) {
			gc->total_hits++;
			return node->cost; 
                }
        }
	gc->total_fails++;
        return -1;
}

/**
 * GACH_AddLink - Adds a new header cacheable field to the cache
 *
 * @param c The cache
 * @param value The header field
 * @param type
 */

void GACH_AddLink(ST_GraphCache *gc,char *urisrc, char *uridst, int cost){
	ST_GraphLink *link;
	ST_GraphNode *node;

	link = (ST_GraphLink*)g_hash_table_lookup(gc->uris,(gchar*)urisrc);
        if (link == NULL) {
		// There is no source uri
		link = g_new(ST_GraphLink,1);
		link->uris = g_hash_table_new(g_str_hash,g_str_equal);
		link->uri = g_string_new(""); 	
		g_string_printf(link->uri,"%s",urisrc);
		
		g_hash_table_insert(gc->uris,g_strdup(urisrc),link);

		node = g_new(ST_GraphNode,1);
		node->uri = g_string_new("");
		g_string_printf(node->uri,"%s",uridst);
		node->cost = cost;

		g_hash_table_insert(link->uris,g_strdup(uridst),node);
		gc->total_links ++;
	}else{
		node = (ST_GraphNode*)g_hash_table_lookup(link->uris,(gchar*)uridst);
		if(node == NULL) {
			node = g_new(ST_GraphNode,1);
			node->uri = g_string_new("");
			g_string_printf(node->uri,"%s",uridst);
			node->cost = cost;
			g_hash_table_insert(link->uris,g_strdup(uridst),node);
			gc->total_links ++;
		}else{
			// Update the cost of the link
			node->cost = cost;
		}
	}	
	return;
}

/**
 * GACH_AddBaseLink - Adds a new uri cacheable field to the graphcache
 *
 * @param c The graphcache
 * @param uri 
 */

void GACH_AddBaseLink(ST_GraphCache *gc,char *uri){
        ST_GraphLink *link;

        link = (ST_GraphLink*)g_hash_table_lookup(gc->uris,(gchar*)uri);
        if (link == NULL) {
                // There is no uri
                link = g_new(ST_GraphLink,1);
                link->uris = g_hash_table_new(g_str_hash,g_str_equal);
                link->uri = g_string_new("");
                g_string_printf(link->uri,"%s",uri);

                g_hash_table_insert(gc->uris,g_strdup(uri),link);
	}
	return;
} 


ST_GraphLink *GACH_GetBaseLink(ST_GraphCache *gc,char *uri){
	ST_GraphLink *link = NULL;

	link = (ST_GraphLink*)g_hash_table_lookup(gc->uris,(gchar*)uri);
       	return link; 
}

ST_GraphNode *GACH_GetGraphNodeFromLink(ST_GraphCache *gc,ST_GraphLink *link, char *uri){
	ST_GraphNode *node = NULL;

        node = (ST_GraphNode*)g_hash_table_lookup(link->uris,(gchar*)uri);
	if(node == NULL)
		gc->total_fails++;
	else
		gc->total_hits++;
	return node;
}

ST_GraphNode *GACH_GetGraphNode(ST_GraphCache *gc,char *urisrc,char *uridst){
	ST_GraphLink *link = GACH_GetBaseLink(gc,urisrc);
	ST_GraphNode *node = NULL;

	if(link != NULL) {
		node = GACH_GetGraphNodeFromLink(gc,link,uridst);
		if(node == NULL)
			gc->total_fails++;
		else
			gc->total_hits++;
		return node;	
	}
	return NULL;
}


/**
 * GACH_Init - Initalize the cache
 *
 */
ST_GraphCache *GACH_Init(){
	ST_GraphCache *gc = NULL;

	gc = (ST_GraphCache*)g_new(ST_GraphCache,1);

	gc->uris = g_hash_table_new(g_str_hash,g_str_equal);
	gc->total_links = 0;
	gc->total_fails = 0;
	gc->total_hits = 0;
	return gc;
}

/**
 * GACH_Destroy - Destroy all the fields of the graphcache
 */
void GACH_Destroy(ST_GraphCache *c) {
/*        g_hash_table_foreach_remove(c->header_cache,CACH_DestroyCallback,NULL);
        g_hash_table_foreach_remove(c->parameter_cache,CACH_DestroyCallback,NULL);
        g_hash_table_destroy(c->header_cache);
        g_hash_table_destroy(c->parameter_cache);
	g_free(c);
*/	
}

/**
 * GACH_Stats - Shows the statistcis of a ST_GraphCache 
 * 
 * @param c The graphcache
 * 
 */
void GACH_Stats(ST_GraphCache *gc) {
	GHashTableIter iter,initer;
	gpointer k,v,kk,vv;
	int effectiveness;
	int p_effectiveness;

	effectiveness = 0;
	if((gc->total_hits+gc->total_fails)>0){
		effectiveness = (gc->total_hits*100)/(gc->total_hits+gc->total_fails);
	}	
	fprintf(stdout,"GraphCache(0x%x) statistics\n",gc);
	fprintf(stdout,"\tLinks = %d \n",gc->total_links);
	fprintf(stdout,"\tLink hits = %d\n\tLink fails = %d\n",gc->total_hits,gc->total_fails);
	fprintf(stdout,"\tLink effectiveness = %d\%\n",effectiveness);
/*
	fprintf(stdout,"\tLink nodes\n");
	g_hash_table_iter_init (&iter, gc->uris);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_GraphLink *link = (ST_GraphLink*)v;
		g_hash_table_iter_init(&initer,link->uris);
		fprintf(stdout,"\t\tUri(%s)\n",link->uri->str);
		while (g_hash_table_iter_next (&initer, &kk, &vv)) {
			ST_GraphNode *node = (ST_GraphNode*)vv;
			fprintf(stdout,"\t\t\tUri(%s)Cost(%d)\n",node->uri->str,node->cost);
		}
	}
*/
	return;
}

