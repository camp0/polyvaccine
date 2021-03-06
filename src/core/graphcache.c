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
#include<fcntl.h>


/**
 * GACH_NewGraphLink - Creates a new grap link with a given URI 
 *
 * @param uri 
 *
 * @return ST_GraphLink
 */

ST_GraphLink *GACH_NewGraphLink(char *uri){
        ST_GraphLink *link = NULL;

        link = g_new(ST_GraphLink,1);
        link->uris = g_hash_table_new(g_str_hash,g_str_equal);
        link->uri = g_strdup(uri);
	link->type = NODE_TYPE_REGULAR;
	link->hited = 0;
	link->key = 0;

        return link;
}

/**
 * GACH_NewGraphNode - Creates a new grap node with a given URI and the cost 
 *
 * @param uri 
 * @param cost 
 *
 * @return ST_GraphNode
 */

ST_GraphNode *GACH_NewGraphNode(char *uri,int cost){
	ST_GraphNode *node = NULL;

        node = g_new(ST_GraphNode,1);
        node->uri = g_strdup(uri);
        node->cost = cost;
        node->hits = 0;
	node->type = NODE_TYPE_REGULAR;
	node->key = 0;
	return node;
}

/**
 * GACH_GetLinkCost - Return the cost between two uris if exists a link between them 
 *		This is the function called by the detection/normal mode of the polyfilter
 *
 * @param gc The cache
 * @param urisrc
 * @param uridst
 *
 * @return int
 */

int GACH_GetLinkCost(ST_GraphCache *gc, char *urisrc, char *uridst){
        ST_GraphLink *link;
        ST_GraphNode *node;

        link = (ST_GraphLink*)g_hash_table_lookup(gc->uris,(gchar*)urisrc);
        if (link != NULL) {
		if(link->hited == 0){
			link->hited = 1;
			gc->total_node_hits++;
		}
                node = (ST_GraphNode*)g_hash_table_lookup(link->uris,(gchar*)uridst);
                if(node != NULL) {
			gc->total_hits++;
			node->hits++;
			return node->cost; 
                }
        }else{
		gc->total_node_fails++;
	}
	gc->total_fails++;
        return -1;
}

/**
 * GACH_AddGraphNodeFromLinkUpdate - Adds a new graphnode from link and return it 
 *
 * @param gc The cache
 * @param link
 * @param uri
 * @param cost
 *
 * @return ST_GraphNode
 */

ST_GraphNode *GACH_AddGraphNodeFromLinkUpdate(ST_GraphCache *gc,ST_GraphLink *link, char *uri, int cost){
	ST_GraphNode *node = NULL;
	ST_GraphLink *linkdst = NULL;
	ST_GraphLink *linkaux = NULL;

	node = (ST_GraphNode*)g_hash_table_lookup(link->uris,(gchar*)uri);
        if(node == NULL) {
		/* First create the new node and the relation between the link */
                node = GACH_NewGraphNode(uri,cost);
                gc->size_memory += sizeof(ST_GraphNode)+strlen(uri);
                g_hash_table_insert(link->uris,node->uri,node);
                gc->total_links ++;

		linkaux = GACH_GetBaseLinkUpdate(gc,uri);
		if(linkaux != NULL){ // The node is a restransmition
			node->key = linkaux->key;
		}else{	
                	gc->total_ids++;
                	node->key=gc->total_ids;
		}
                linkdst = (ST_GraphLink *)g_hash_table_lookup(gc->uris,(gchar*)uri);
                if(linkdst == NULL) {
                	linkdst = GACH_NewGraphLink(uri);
                        gc->size_memory += sizeof(ST_GraphLink)+strlen(uri);
                        gc->total_nodes++;
                        linkdst->key = gc->total_ids;
                        g_hash_table_insert(gc->uris,linkdst->uri,linkdst);
                }else{
			linkdst->key = node->key;
		}
	}else{
		// Update the cost of the link because the relation exists
                node->cost = cost;
        }
	return node;
}

/**
 * GACH_AddLinkUpdate - Adds a link between to URIs given to the grapcache
 *	
 * 	This function is for UPDATE
 *
 * @param gc The Graph cache
 * @param urisrc the previous uri of the http path
 * @param uridst the current uri of the flow on the http path
 * @param cost the cost between the two uris 
 */

void GACH_AddLinkUpdate(ST_GraphCache *gc,char *urisrc, char *uridst, int cost){
	ST_GraphLink *link = NULL;
	ST_GraphNode *node;

        link = (ST_GraphLink*)g_hash_table_lookup(gc->uris,(gchar*)urisrc);
        if (link == NULL) {
                // There is no source uri
                link = GACH_NewGraphLink(urisrc);

                // increase counters    
                gc->size_memory += sizeof(ST_GraphLink)+strlen(urisrc);
                gc->total_nodes++;
                gc->total_ids ++;
                link->key = gc->total_ids; // Set the id value of the uri

                g_hash_table_insert(gc->uris,link->uri,link);
	}
	node = GACH_AddGraphNodeFromLinkUpdate(gc,link,uridst,cost);
	return;
}

/**
 * GACH_AddBaseLink - Adds a new uri cacheable field to the graphcache
 *
 * @param c The graphcache
 * @param uri 
 *
 * @return ST_GraphLink
 */

ST_GraphLink *GACH_AddBaseLinkUpdate(ST_GraphCache *gc,char *uri){
        ST_GraphLink *link;

        link = (ST_GraphLink*)g_hash_table_lookup(gc->uris,(gchar*)uri);
        if (link == NULL) {
                // There is no uri
		link = GACH_NewGraphLink(uri);

		gc->total_nodes++;
		gc->total_ids++;
		link->key = gc->total_ids;
		gc->size_memory += sizeof(link)+strlen(uri);
                g_hash_table_insert(gc->uris,link->uri,link);
	}
	return link;
} 

/**
 * GACH_GetBaseLinkUpdate - Gets a base link given a uri.
 *
 * @param c The graphcache
 * @param uri 
 *
 * @return ST_GraphLink
 */

ST_GraphLink *GACH_GetBaseLinkUpdate(ST_GraphCache *gc,char *uri){
        ST_GraphLink *link = NULL;

        link = (ST_GraphLink*)g_hash_table_lookup(gc->uris,(gchar*)uri);
        return link;
}

/**
 * GACH_GetBaseLink - Gets a base link given a uri, but updates counters.
 *
 * @param c The graphcache
 * @param uri 
 *
 * @return ST_GraphLink
 */

ST_GraphLink *GACH_GetBaseLink(ST_GraphCache *gc,char *uri){
	ST_GraphLink *link = NULL;

	link = GACH_GetBaseLinkUpdate(gc,uri); 
	if(link!= NULL) {
                if(link->hited == 0){
                        link->hited = 1;
                        gc->total_node_hits++;
                }
	}else{
		gc->total_node_fails++;
	}
       	return link; 
}

/**
 * GACH_GetGraphNodeFromLink - Gets a graph node from a base link.
 *
 * @param c The graphcache
 * @param link
 * @param uri 
 *
 * @return ST_GraphNode
 */

ST_GraphNode *GACH_GetGraphNodeFromLink(ST_GraphCache *gc,ST_GraphLink *link, char *uri){
	ST_GraphNode *node = NULL;

        node = (ST_GraphNode*)g_hash_table_lookup(link->uris,(gchar*)uri);
	if(node == NULL){
		gc->total_fails++;
	}else{
		gc->total_hits++;
		node->hits++;
	}
	return node;
}

/**
 * GACH_GetGraphNode - Gets a graph node from two char uris.
 *
 * @param c The graphcache
 * @param urisrc 
 * @param uridst 
 *
 * @return ST_GraphNode
 */

ST_GraphNode *GACH_GetGraphNode(ST_GraphCache *gc,char *urisrc,char *uridst){
	ST_GraphLink *link = NULL;
	ST_GraphNode *node = NULL;

	link = GACH_GetBaseLink(gc,urisrc);
	if(link != NULL) {
                if(link->hited == 0){
                        link->hited = 1;
                        gc->total_node_hits++;
                }
		node = GACH_GetGraphNodeFromLink(gc,link,uridst);
		if(node == NULL){
			gc->total_fails++;
		}else{
			gc->total_hits++;
			node->hits++;
		}
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
	gc->total_nodes = 0;
	gc->total_links = 0;
	gc->total_fails = 0;
	gc->total_hits = 0;
	gc->total_node_hits = 0;
	gc->total_node_fails = 0;
	gc->statistics_level = 0;
	gc->size_memory = 0;
	return gc;
}

/**
 * GACH_Destroy - Destroy all the fields of the graphcache
 *
 * @param gc
 */
void GACH_Destroy(ST_GraphCache *gc) {
        GHashTableIter iter,initer;
        gpointer k,v,kk,vv;
	ST_GraphLink *link;
	ST_GraphNode *node;

        g_hash_table_iter_init (&iter, gc->uris);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
        	link = (ST_GraphLink*)v;
                g_hash_table_iter_init(&initer,link->uris);
                while (g_hash_table_iter_next (&initer, &kk, &vv)) {
                	node = (ST_GraphNode*)vv;
		
			g_free(node->uri);
			g_free(node);
			node = NULL;
		}
		g_hash_table_destroy(link->uris);
		g_free(link->uri);
		g_free(link);
		link = NULL;
        }
	g_hash_table_destroy(gc->uris);
	g_free(gc);
	gc = NULL;
}


void __GACH_DumpGraphOnGraphviz(ST_GraphCache *gc) {
        GHashTableIter iter,initer;
        gpointer k,v,kk,vv;
	FILE *fd;

	fd = fopen("graphcache.viz","w");
	if(fd == NULL) return;

	fprintf(fd,"digraph graphcache {\n");	
        g_hash_table_iter_init (&iter, gc->uris);
       	while (g_hash_table_iter_next (&iter, &k, &v)) {
        	ST_GraphLink *link = (ST_GraphLink*)v;
                g_hash_table_iter_init(&initer,link->uris);
                while (g_hash_table_iter_next (&initer, &kk, &vv)) {
                	ST_GraphNode *node = (ST_GraphNode*)vv;
                        fprintf(fd,"\t\"%d\" -> \"%d\"\t[label=\"%d\"];\n",link->key,node->key,node->cost);
                }
        }
	fprintf(fd,"}\n");
	fclose(fd);
        return;
}

void GACH_ShowGraphCache(ST_GraphCache *gc){
	GHashTableIter iter,initer;
	ST_GraphLink *link;
	ST_GraphNode *node;
	gpointer k,v,kk,vv;

	fprintf(stdout,"\tLink nodes\n");
	g_hash_table_iter_init (&iter, gc->uris);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		link = (ST_GraphLink*)v;
		g_hash_table_iter_init(&initer,link->uris);
		fprintf(stdout,"\t\tUriSrc(%s)id(%d)\n",link->uri,link->key);
		while (g_hash_table_iter_next (&initer, &kk, &vv)) {
			node = (ST_GraphNode*)vv;
			fprintf(stdout,"\t\t\tUriDst(%s)id(%d)cost(%d)hits(%d)\n",node->uri,node->key,node->cost,node->hits);
		}
        }
	return;
}

/**
 * GACH_Stats - Shows the statistcis of a ST_GraphCache 
 * 
 * @param c The graphcache
 * 
 */
void GACH_Stats(ST_GraphCache *gc) {
	int effectiveness;
	int n_effectiveness;
	int32_t value = gc->size_memory;
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
	if((gc->total_hits+gc->total_fails)>0){
		effectiveness = (gc->total_hits*100)/(gc->total_hits+gc->total_fails);
	}	
	n_effectiveness = 0;
	if((gc->total_node_hits+gc->total_node_fails)>0){
		n_effectiveness = (gc->total_node_hits*100)/(gc->total_node_hits+gc->total_node_fails);
	}	
	fprintf(stdout,"GraphCache(0x%x) statistics, level %d\n",gc,gc->statistics_level);
	fprintf(stdout,"\tallocated memory:%d %s\n",value,unit);
	fprintf(stdout,"\tLinks = %d \n",gc->total_links);
	fprintf(stdout,"\tLink hits = %d\n\tLink fails = %d\n",gc->total_hits,gc->total_fails);
	fprintf(stdout,"\tLink effectiveness = %d\%\n",effectiveness);
	fprintf(stdout,"\tNodes = %d\n",gc->total_nodes);
	fprintf(stdout,"\tNode hits  = %"PRId32"\n",gc->total_node_hits);
	fprintf(stdout,"\tNode fails  = %"PRId32"\n",gc->total_node_fails);
	fprintf(stdout,"\tNode effectiveness = %d%%\n",n_effectiveness);

	if(gc->statistics_level > 1) {
		GACH_ShowGraphCache(gc);
		if(gc->statistics_level > 2) {
			fprintf(stdout,"Dumping graph to grapcache.viz file\n");
			__GACH_DumpGraphOnGraphviz(gc);
		}
	}
	return;
}

void GACH_SetStatisticsLevel(ST_GraphCache *gc,int level) {gc->statistics_level = level;};
