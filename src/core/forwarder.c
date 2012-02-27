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

#include "forwarder.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_FILTER_FORWARDER_INTERFACE
#include "log.h"

/**
 * FORD_Init - Inits the forwarder. 
 *
 */
ST_Forwarder *FORD_Init(){
	ST_Forwarder *fw = g_new(ST_Forwarder,1);
	
	fw->tcp_analyzers = g_hash_table_new(g_direct_hash,g_direct_equal);
	fw->udp_analyzers = g_hash_table_new(g_direct_hash,g_direct_equal);
	return fw;
}

/**
 * FORD_InitAnalyzers - Executes the init function of every analyzer. 
 *
 * @param ST_Forwarder
 */
void FORD_InitAnalyzers(ST_Forwarder *fw){
	GHashTableIter iter;
	gpointer k,v;

	g_hash_table_iter_init (&iter, fw->tcp_analyzers);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		LOG(POLYLOG_PRIORITY_INFO,"TCP %s plugged on port %d",ga->name,ga->port);
		ga->init();
	}
	g_hash_table_iter_init (&iter, fw->udp_analyzers);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		LOG(POLYLOG_PRIORITY_INFO,"UDP %s plugged on port %d",ga->name,ga->port);
		ga->init();
	}
	return;
}

/**
 * FORD_ShowAnalyzers - Shows the plugged analyzers. 
 *
 * @param ST_Forwarder
 */
void FORD_ShowAnalyzers(ST_Forwarder *fw){
        GHashTableIter iter;
        gpointer k,v;

        g_hash_table_iter_init (&iter, fw->tcp_analyzers);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
                fprintf(stdout,"\tTCP %s on port %d\n",ga->name,ga->port);
        }
        g_hash_table_iter_init (&iter, fw->udp_analyzers);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
                fprintf(stdout,"\tUDP %s on port %d\n",ga->name,ga->port);
        }
        return;
}


/**
 * FORD_InitAnalyzers - Executes the statistics of every analyzer. 
 *
 * @param ST_Forwarder
 */
void FORD_Stats(ST_Forwarder *fw){
        GHashTableIter iter;
        gpointer k,v;

        g_hash_table_iter_init (&iter, fw->tcp_analyzers);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
                ga->stats();
        }
        g_hash_table_iter_init (&iter, fw->udp_analyzers);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
                ga->stats();
        }
        return;
}

/**
 * FORD_Destroy - Executes the destroy function of every analyzer and destroys
 * 		the forwarder. 
 *
 * @param ST_Forwarder
 */

void FORD_Destroy(ST_Forwarder *fw){
	GHashTableIter iter;
	gpointer k,v;

	g_hash_table_iter_init (&iter, fw->tcp_analyzers);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		ga->destroy();
		g_free(ga);
	}
	g_hash_table_iter_init (&iter, fw->udp_analyzers);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		ga->destroy();
		g_free(ga);
	}
	g_hash_table_destroy(fw->tcp_analyzers);
	g_hash_table_destroy(fw->udp_analyzers);
	g_free(fw);	
	return;
}

/**
 * FORD_GetAnalyzer - Returns the analyzer pluged on the specific port
 *
 * @param ST_Forwarder
 * @param protocol 
 * @param sport
 * @param dport
 */
ST_GenericAnalyzer *FORD_GetAnalyzer(ST_Forwarder *fw, int16_t protocol,int16_t sport,int16_t dport){
	ST_GenericAnalyzer *ga = NULL;
	GHashTable *t = NULL;

	if(protocol == 6)
		t = fw->tcp_analyzers; 
	else
		t = fw->udp_analyzers;

	ga = (ST_GenericAnalyzer*)g_hash_table_lookup(t,GINT_TO_POINTER(sport));
	if(ga == NULL){ 
		ga = (ST_GenericAnalyzer*)g_hash_table_lookup(t,GINT_TO_POINTER(dport));
		ga->direction = FLOW_FORW;
	}else{
		ga->direction = FLOW_BACK;
	}	
	return ga;
}

/**
 * FORD_AddAnalyzer - Adss a analyzer to a specific port 
 *
 * @param fw
 * @param cache 
 * @param name
 * @param protocol
 * @param port
 * @param init
 * @param destroy
 * @param stats
 * @param analyze
 * @param learn 
 * 
 */
void FORD_AddAnalyzer(ST_Forwarder *fw, ST_Cache *cache, char *name,int16_t protocol,int16_t port,
	void (*init)(void), void (*destroy)(void),void (*stats)(void),
	void (*analyze)(ST_Cache *c,ST_GenericFlow *f,int *ret),
	void (*learn)(ST_Cache *c,ST_GenericFlow *f)){

	ST_GenericAnalyzer *ga = NULL;
	GHashTable *t = NULL;
	
	if(protocol == 6) 
		t = fw->tcp_analyzers;
	else
		t = fw->udp_analyzers;

	LOG(POLYLOG_PRIORITY_INFO,"Adding analyzer '%s' on port %d",name,port);
	ga = (ST_GenericAnalyzer*)g_hash_table_lookup(t,GINT_TO_POINTER(port));
	if (ga == NULL){ // the analyzer dont exist
		ga = g_new(ST_GenericAnalyzer,1);
		snprintf(ga->name,32,"%s",name);
		ga->cache = cache;
		ga->port = port;
		ga->direction = FLOW_FORW; // used to know the direction of the packet upstrem, donwstream;
		ga->init = init;
		ga->stats = stats;
		ga->destroy = destroy;
		ga->analyze = analyze;
		ga->learn = learn;
		g_hash_table_insert(t,GINT_TO_POINTER(port),ga);
		LOG(POLYLOG_PRIORITY_INFO,"Analyzer '%s' instanciated 0x%x",name,ga);
	}	
	return;
}

void FORD_ChangeAnalyzerToPlugOnPort(ST_Forwarder *fw,int16_t src_protocol, int16_t src_port,
        int16_t dst_protocol,int16_t dst_port){

	ST_GenericAnalyzer *ga = NULL;
	GHashTable *t = NULL;

	if(src_protocol == 6)
		t = fw->tcp_analyzers;
	else
		t = fw->udp_analyzers;

	ga = (ST_GenericAnalyzer*)g_hash_table_lookup(t,GINT_TO_POINTER(src_port));
	if (ga != NULL) {
		g_hash_table_remove(t,GINT_TO_POINTER(src_port));
		ga->port = dst_port;
		if(dst_protocol == 6)
			t = fw->tcp_analyzers;
		else
			t = fw->udp_analyzers;
		g_hash_table_insert(t,GINT_TO_POINTER(dst_port),ga);
	}
	return;
}
