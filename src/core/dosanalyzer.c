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

#include "dosanalyzer.h"
#include "httpvalues.h"

#define HTTP_URI_END "HTTP/1.[0|1]"
#define HTTP_HEADER_PARAM "^(GET|POST|OPTIONS|HEAD|CONNECT|PUT|DELETE|TRACE).*" HTTP_URI_END

#define MAX_URI_LENGTH 2048

#define POLYLOG_CATEGORY_NAME POLYVACCINE_FILTER_DDOS_INTERFACE
#include "log.h"

static ST_DoSAnalyzer _dos;

/**
 * DSAZ_Init - Initialize all the fields of a small http dos analyzer
 */
void *DSAZ_Init() {
	register int i;
	int erroffset;
	ST_HTTPField *f;

	_dos.total_http_invalid_decode = 0;
        _dos.suspicious_headers = 0;
        _dos.suspicious_parameters = 0;
        _dos.total_http_bytes = 0;
        _dos.total_http_segments = 0;
	_dos.total_suspicious_segments = 0;
	_dos.total_valid_segments = 0;
	_dos.on_suspicious_header_break = TRUE;
	_dos.on_suspicious_parameter_break = TRUE; 
	_dos.analyze_post_data = FALSE;
	_dos.show_unknown_http = FALSE;

	_dos.expr_header = pcre_compile((char*)HTTP_HEADER_PARAM, PCRE_FIRSTLINE, &_dos.errstr, &erroffset, 0);
#ifdef PCRE_HAVE_JIT
	_dos.pe_header = pcre_study(_dos.expr_header,PCRE_STUDY_JIT_COMPILE,&_dos.errstr);
        if(_dos.pe_header == NULL){
                LOG(POLYLOG_PRIORITY_WARN,
			"PCRE study with JIT support failed '%s'",_dos.errstr);
        }
        int jit = 0;
        int ret;

        ret = pcre_fullinfo(_dos.expr_header,_dos.pe_header, PCRE_INFO_JIT,&jit);
        if (ret != 0 || jit != 1) {
                LOG(POLYLOG_PRIORITY_WARN,
                	"PCRE JIT compiler does not support the expresion on the DoS analyzer");
        }
#else
	_dos.pe_header = pcre_study(_dos.expr_header,0,&_dos.errstr);
        if(_dos.pe_header == NULL)
                LOG(POLYLOG_PRIORITY_WARN,
                	"PCRE study failed '%s'",_dos.errstr);
#endif

	_dos.methods = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
	_dos.parameters = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);

	return;
}


/**
 * DSAZ_Stats - Prints staticstics related to http
 */
void *DSAZ_Stats(void) {
	register int i;
/*
	fprintf(stdout,"DDoS analyzer statistics\n");
	fprintf(stdout,"\ttotal segments %ld\n",_http.total_http_segments);
	fprintf(stdout,"\ttotal bytes %ld\n",_http.total_http_bytes);
	fprintf(stdout,"\ttotal suspicious segments %ld\n",_http.total_suspicious_segments);
	fprintf(stdout,"\ttotal valid segments %ld\n",_http.total_valid_segments);
	fprintf(stdout,"\ttotal invalid decodes %ld\n",_http.total_http_invalid_decode);
	fprintf(stdout,"\tHeaders:\n");

        f = &ST_DSTPTypeHeaders[0];
        i = 0;
        while((f->name!= NULL)) {
		fprintf(stdout,"\t\t%s=%d\n",f->name,f->matchs);
                i ++;
                f = &ST_DSTPTypeHeaders[i];
        }
	fprintf(stdout,"\tParameters:\n");
	f = &ST_DSTPFields[0];
	i = 0;
	while((f->name!= NULL)) {
		fprintf(stdout,"\t\t%s=%d\n",f->name,f->matchs);
		i++;
		f = &ST_DSTPFields[i];
	}	
*/
	return;
}


/**
 * UT_TimevalSub - make the diferente between a and b ( r = a - b)
 *
 * @param a The timeval struct
 * @param b The timeval struct
 *
 * @param r Returns the diference between a and b
 *
 */
void UT_TimevalSub(struct timeval *r, struct timeval *a, struct timeval *b)
{
        if (a->tv_usec < b->tv_usec) {
                r->tv_usec = (a->tv_usec + 1000000) - b->tv_usec;
                r->tv_sec = a->tv_sec - b->tv_sec - 1;
        } else {
                r->tv_usec = a->tv_usec - b->tv_usec;
                r->tv_sec = a->tv_sec - b->tv_sec;
        }
}



/**
 * DSAZ_Destroy - Destroy the fields created by the init function
 */
void *DSAZ_Destroy() {
/*	TROF_Destroy(_http.t_off);
	g_hash_table_destroy(_http.methods);
	g_hash_table_destroy(_http.parameters);
	pcre_free(_http.expr_header);
#if PCRE_MAYOR == 8 && PCRE_MINOR >= 20
	pcre_free_study(_http.pe_header);
#else
	pcre_free(_http.pe_header);
#endif
*/
}

/**
 * DSAZ_AnalyzeHTTPRequest - Analyze the HTTP segment in order to evaluate if the fields exist on the http cache.
 * also tryes to find suspicious opcodes on the fields if it dont exist on the http cache.
 *
 * @param c The ST_Cache.
 * @param f The ST_GenericFlow to analyze.
 * @param ret the result of the analisys.
 */

void *DSAZ_AnalyzeHTTPRequest(ST_Cache *c,ST_User *user,ST_GenericFlow *f , int *ret){
	ST_MemorySegment *seg = f->memory;
        ST_GraphLink *link = NULL;
        ST_GraphNode *node = NULL;
	int lret,i,process_bytes;

#ifdef DEBUG
        LOG(POLYLOG_PRIORITY_DEBUG,
		"Analyzing flow(0x%x)user(0x%x)[bytes(%d)packets(%d)]segment(0x0%x)[realsize(%d)virtualsize(%d)]",
		f,user,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
#endif
	lret = pcre_exec(_dos.expr_header,_dos.pe_header,(char*)seg->mem,seg->virtual_size,
		0 /* Start offset */,
		0 /* options */ ,
		_dos.ovector, OVECCOUNT);
	if (lret>1) { // The packet contains a minimum http header	
		char method[16];
		char uri[MAX_URI_LENGTH];
		char *token;
		int methodlen,urilen,offset;

		process_bytes = 0;
		offset = 0;
		methodlen = _dos.ovector[3]-_dos.ovector[2];
		urilen = _dos.ovector[1]-_dos.ovector[0];
		
		if(urilen>MAX_URI_LENGTH) {
			urilen = MAX_URI_LENGTH-1;
		}
		memset(uri,0,MAX_URI_LENGTH);
		memcpy(uri,&(seg->mem[0]),urilen-5);
		uri[urilen] = '\0';

		if(f->lasturi == NULL) { // Is the first request of the flow
			link = GACH_GetBaseLink(c,uri);
			if(link != NULL) { // The uri is on the graphcache
				f->lasturi = link->uri->str;
			}			

		}else{
			node = GACH_GetGraphNode(c,f->lasturi,uri);
			if(node != NULL){ 
				// Check if the time is on the cost range
				// TODO

				f->lasturi = node->uri->str;
			}
		}
//		printf("URI(%s)\n",uri);


		_dos.total_http_bytes += seg->virtual_size;	
		_dos.total_http_segments ++;
	}else{
		(*ret) = 1;
		return ;
	}
	(*ret) = 0;
	return ;
}

/**
 * DSAZ_AnalyzeDummyHTTPRequest - Analyze the HTTP segment generated by the dummy and add to the graphcache
 *
 * @param c The ST_Cache.
 * @param c The ST_User.
 * @param f The ST_GenericFlow to analyze.
 */

void *DSAZ_AnalyzeDummyHTTPRequest(ST_Cache *c, ST_User *user,ST_GenericFlow *f){
	ST_MemorySegment *seg = f->memory;
	ST_GraphLink *link = NULL;
	ST_GraphNode *node = NULL;
	int lret;

#ifdef DEBUG
        LOG(POLYLOG_PRIORITY_DEBUG,
                "Analyzing flow(0x%x)user(0x%x)[bytes(%d)packets(%d)]segment(0x0%x)[realsize(%d)virtualsize(%d)]",
                f,user,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
#endif
        lret = pcre_exec(_dos.expr_header,_dos.pe_header,(char*)seg->mem,seg->virtual_size,
                0 /* Start offset */,
                0 /* options */ ,
                _dos.ovector, OVECCOUNT);
        if (lret>1) { // The packet contains a minimum http header
                char uri[MAX_URI_LENGTH];
                int methodlen,urilen,offset;

                offset = 0;
                methodlen = _dos.ovector[3]-_dos.ovector[2];
                urilen = _dos.ovector[1]-_dos.ovector[0];

                if(urilen>MAX_URI_LENGTH) {
                        urilen = MAX_URI_LENGTH-1;
                }
                memset(uri,0,MAX_URI_LENGTH);
                memcpy(uri,&(seg->mem[0]),urilen-4);
                uri[urilen] = '\0';

		// Updates the graphcache
		if(f->lasturi == NULL){
			GACH_AddBaseLink(c,uri);
			link = GACH_GetBaseLink(c,uri);
			f->lasturi = link->uri->str;
		}else{
			// At least is the second or more uri on the flow
			int value = 0; 
			struct timeval t_cost;

			UT_TimevalSub(&t_cost,&(f->current_time),&(f->last_uri_seen));
			value = t_cost.tv_sec/1000 + (t_cost.tv_usec);
			GACH_AddLink(c,f->lasturi,uri,value);
			node = GACH_GetGraphNode(c,f->lasturi,uri);
			f->lasturi = node->uri->str;	
		}
		f->last_uri_seen.tv_sec = f->current_time.tv_sec;
		f->last_uri_seen.tv_usec = f->current_time.tv_usec;
        }
	return;
}
