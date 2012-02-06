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

/**
 * FORD_Init - Inits the forwarder. 
 *
 */
ST_Forwarder *FORD_Init(){
	ST_Forwarder *fw = g_new(ST_Forwarder,1);
	
	fw->analyzers = g_hash_table_new(g_direct_hash,g_direct_equal);
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

	g_hash_table_iter_init (&iter, fw->analyzers);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		ga->init();
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

        g_hash_table_iter_init (&iter, fw->analyzers);
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

	g_hash_table_iter_init (&iter, fw->analyzers);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		ga->destroy();
		g_free(ga);
	}
	g_free(fw);	
	return;
}

/**
 * FORD_GetAnalyzer - Returns the analyzer pluged on the specific port
 *
 * @param ST_Forwarder
 * @param port
 */
ST_GenericAnalyzer *FORD_GetAnalyzer(ST_Forwarder *fw, int16_t port){

	return (ST_GenericAnalyzer*)g_hash_table_lookup(fw->analyzers,GINT_TO_POINTER(port));
}

/**
 * FORD_AddAnalyzer - Adss a analyzer to a specific port 
 *
 * @param fw
 * @param name
 * @param port
 * @param init
 * @param destroy
 * @param stats
 * @param analyze
 * @param learn 
 * 
 */
void FORD_AddAnalyzer(ST_Forwarder *fw, char *name,int16_t port,
	void (*init)(), void (*destroy)(),void (*stats)(),
	void (*analyze)(ST_Cache *c,ST_GenericFlow *f,int *ret),
	void (*learn)(ST_Cache *c,ST_GenericFlow *f)){

	ST_GenericAnalyzer *ga = NULL;

	DEBUG0("Adding analyzer '%s' on port %d\n",name,port);
	ga = (ST_GenericAnalyzer*)g_hash_table_lookup(fw->analyzers,GINT_TO_POINTER(port));
	if (ga == NULL){ // the analyzer dont exist
		ga = g_new(ST_GenericAnalyzer,1);
		snprintf(ga->name,32,"%s",name);
		ga->port = port;
		ga->init = init;
		ga->stats = stats;
		ga->destroy = destroy;
		ga->analyze = analyze;
		ga->learn = learn;
		g_hash_table_insert(fw->analyzers,GINT_TO_POINTER(port),ga);
		DEBUG0("Analyzer '%s' instanciated 0x%x\n",name,ga);
	}	
	return;
}

