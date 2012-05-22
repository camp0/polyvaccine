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

	// analyzers that are running(enabled)	
	fw->tcp_analyzers = g_hash_table_new(g_direct_hash,g_direct_equal);
	fw->udp_analyzers = g_hash_table_new(g_direct_hash,g_direct_equal);
	// analyzers disabled
	fw->analyzers = g_hash_table_new(g_str_hash,g_str_equal);
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
		LOG(POLYLOG_PRIORITY_INFO,"Analyzer %s plugged on port %d",ga->name,ga->port);
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
 * FORD_InitAnalyzers - Executes the statistics of every enable analyzer. 
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
 * FORD_GetAnalyzerByName - Search a analyzer by name and return it 
 *
 * @param ST_Forwarder
 * @param name
 * 
 * @return ST_GenericAnalyzer 
 */

ST_GenericAnalyzer *FORD_GetAnalyzerByName(ST_Forwarder *fw,char *name){
	ST_GenericAnalyzer *ga = NULL;
	GHashTableIter iter;
	gpointer k,v;

	ga = (ST_GenericAnalyzer*)g_hash_table_lookup(fw->analyzers,(gchar*)name);
	if (ga != NULL){ 
		return ga;
	}
	g_hash_table_iter_init(&iter,fw->tcp_analyzers);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		if(strncmp(name,ga->name,strlen(name)) == 0) 
			return ga;
        }
	g_hash_table_iter_init(&iter,fw->udp_analyzers);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		if(strncmp(name,ga->name,strlen(name)) == 0) 
			return ga;
        }
	return NULL;
}

void FORD_EnableAnalyzerByName(ST_Forwarder *fw, char *name){
        ST_GenericAnalyzer *ga = NULL;
        GHashTable *t = NULL;
	gpointer k = NULL;
	gpointer v = NULL;

	if(g_hash_table_lookup_extended(fw->analyzers,(gchar*)name,&k,&v) == TRUE) {
		ga = (ST_GenericAnalyzer*)v;	
		if(g_hash_table_remove(fw->analyzers,k) == TRUE) {
			if(ga->protocol == 6)
				t = fw->tcp_analyzers;
			else
				t = fw->udp_analyzers;

			g_hash_table_insert(t,GINT_TO_POINTER(ga->port),ga);
			LOG(POLYLOG_PRIORITY_INFO,"Enable analyzer '%s' on port %d",name,ga->port);
		}
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

	g_hash_table_iter_init (&iter, fw->analyzers);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		ST_GenericAnalyzer *ga = (ST_GenericAnalyzer*)v;
		ga->destroy();
		g_string_free(v,TRUE);
		g_free(ga);
	} 
	g_hash_table_destroy(fw->tcp_analyzers);
	g_hash_table_destroy(fw->udp_analyzers);
	g_hash_table_destroy(fw->analyzers);
	g_free(fw);	
	return;
}

/**
 * FORD_GetAnalyzer - Returns the analyzer enable pluged on the specific port
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
		if(ga != NULL) 
			ga->direction = FLOW_FORW;
	}else{
		ga->direction = FLOW_BACK;
	}	
	return ga;
}

/**
 * FORD_AddAnalyzer - Adss a analyzer to the forwarder 
 *
 * @param fw
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
void FORD_AddAnalyzer(ST_Forwarder *fw, char *name,int16_t protocol,int16_t port,
	void (*init)(void), void (*destroy)(void),void (*stats)(void),
	void (*analyze)(ST_User *user,ST_GenericFlow *f,int *ret),
	void (*learn)(ST_User *user,ST_GenericFlow *f)){

	ST_GenericAnalyzer *ga = NULL;
	
	LOG(POLYLOG_PRIORITY_INFO,"Adding analyzer '%s' on port %d",name,port);
	ga = (ST_GenericAnalyzer*)g_hash_table_lookup(fw->analyzers,(gchar*)name);
	if (ga == NULL){ // the analyzer dont exist
		ga = g_new(ST_GenericAnalyzer,1);
		snprintf(ga->name,32,"%s",name);
		ga->port = port;
		ga->protocol = protocol;
		ga->direction = FLOW_FORW; // used to know the direction of the packet upstrem, donwstream;
		ga->init = init;
		ga->stats = stats;
		ga->destroy = destroy;
		ga->analyze = analyze;
		ga->learn = learn;
		g_hash_table_insert(fw->analyzers,g_strdup(name),ga);
		LOG(POLYLOG_PRIORITY_INFO,"Analyzer '%s' instanciated 0x%x disabled",name,ga);
	}	
	return;
}

/**
 * FORD_ChangeAnalyzerToPlugOnPort - Change the analyzer of port, usefull function when the daemon 
 * 	is running. This function should have a callback on the dbus in order to change the port
 *	without restarting the process. 
 *
 * @param fw
 * @param src_protocol 
 * @param src_port
 * @param dst_protocol
 * @param dst_port
 * 
 */
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


/**
 * FORD_AddPortToAnalyzer - Adss a new port to the analyzer plugedd on other port.
 *	This function is usefull for example for HTTP listen on two ports(80,8080).
 *
 * @param fw
 * @param name 
 * @param protocol
 * @param port
 * 
 */

void FORD_AddPortToAnalyzer(ST_Forwarder *fw,char *name,int16_t protocol,int16_t port){
        GHashTableIter iter;
        gpointer k,v;
	GHashTable *t = NULL;
	ST_GenericAnalyzer *ga = NULL;

	if(protocol == 6)
		t = fw->tcp_analyzers;
	else
		t = fw->udp_analyzers;

        g_hash_table_iter_init (&iter, t);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ga = (ST_GenericAnalyzer*)v;
		if(strncmp(ga->name,name,strlen(name)) == 0){
			LOG(POLYLOG_PRIORITY_INFO,"Adding analyzer '%s' on port %d",name,port);
			g_hash_table_insert(t,GINT_TO_POINTER(port),ga);               		 
		}
        }
        return;
}


void FORD_ChangePortToAnalyzer(ST_Forwarder *fw,char *name,int16_t port){
	ST_GenericAnalyzer *ga = NULL;

	ga = FORD_GetAnalyzerByName(fw,name);
	LOG(POLYLOG_PRIORITY_INFO,"Changing port %d to analyzer '%s'",port,name);
	ga->port = port;	 

	return;
}
