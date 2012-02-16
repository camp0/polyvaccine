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

#include "httpanalyzer.h"
#include "httpvalues.h"
#include "debug.h"

#define HTTP_URI_END "HTTP/1.[0|1]"
#define HTTP_HEADER_PARAM "^(GET|POST|OPTIONS|HEAD|CONNECT|PUT|DELETE|TRACE).*" HTTP_URI_END

#define MAX_HTTP_LINE_LENGTH 2048
#define MAX_URI_LENGTH 2048

static ST_HTTPAnalyzer _http;

/**
 * HTAZ_Init - Initialize all the fields of a small http analyzer
 */
void *HTAZ_Init() {
	register int i;
	int erroffset;
	ST_HTTPField *f;

        _http.suspicious_headers = 0;
        _http.suspicious_parameters = 0;
        _http.total_http_bytes = 0;
        _http.total_http_segments = 0;
	_http.total_suspicious_segments = 0;
	_http.total_valid_segments = 0;
	_http.on_suspicious_header_break = TRUE;
	_http.on_suspicious_parameter_break = TRUE; 
	_http.analyze_post_data = FALSE;
	_http.show_unknown_http = FALSE;

	_http.expr_header = pcre_compile((char*)HTTP_HEADER_PARAM, PCRE_FIRSTLINE, &_http.errstr, &erroffset, 0);
#ifdef PCRE_HAVE_JIT
	_http.pe_header = pcre_study(_http.expr_header,PCRE_STUDY_JIT_COMPILE,&_http.errstr);
        if(_http.pe_header == NULL){
                WARNING("PCRE study with JIT support failed '%s'\n",_http.errstr);
        }
        int jit = 0;
        int ret;

        ret = pcre_fullinfo(_http.expr_header,_http.pe_header, PCRE_INFO_JIT,&jit);
        if (ret != 0 || jit != 1) {
                INFOMSG("PCRE JIT compiler does not support the expresion on the HTTP analyzer\n");
        }
#else
	_http.pe_header = pcre_study(_http.expr_header,0,&_http.errstr);
        if(_http.pe_header == NULL)
                WARNING("PCRE study failed '%s'\n",_http.errstr);
#endif
	_http.t_off = TROF_Init(); // Init the stack offsets

	_http.methods = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
	_http.parameters = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);

	f = &ST_HTTPTypeHeaders[0];
	i = 0;
	while((f->name!= NULL)) {
		g_hash_table_insert(_http.methods,g_strdup(f->name),f);
		DEBUG1("Adding HTTP (%s)(0x%x) header type\n",f->name,f);
		i ++;
		f = &ST_HTTPTypeHeaders[i];
	}	
	f = &ST_HTTPFields[0];
	i = 0;
	while((f->name!= NULL)) {
		g_hash_table_insert(_http.parameters,g_strdup(f->name),f);
		DEBUG1("Adding HTTP (%s)(0x%x) parameter type\n",f->name,f);
		i++;
		f = &ST_HTTPFields[i];
	}	
	COSU_Init();
	return;
}


void HTAZ_ShowUnknownHTTP(int value){
	_http.show_unknown_http = value;
}

void HTAZ_SetForceAnalyzeHTTPPostData(int value){
	_http.analyze_post_data = value;
}

/**
 * HTAZ_Stats - Prints staticstics related to http
 */
void *HTAZ_Stats(void) {
	register int i;
	ST_HTTPField *f;

	fprintf(stdout,"HTTP analyzer statistics\n");
	fprintf(stdout,"\ttotal segments %ld\n",_http.total_http_segments);
	fprintf(stdout,"\ttotal bytes %ld\n",_http.total_http_bytes);
	fprintf(stdout,"\ttotal suspicious segments %ld\n",_http.total_suspicious_segments);
	fprintf(stdout,"\ttotal valid segments %ld\n",_http.total_valid_segments);
	fprintf(stdout,"\tHeaders:\n");

        f = &ST_HTTPTypeHeaders[0];
        i = 0;
        while((f->name!= NULL)) {
		fprintf(stdout,"\t\t%s=%d\n",f->name,f->matchs);
                i ++;
                f = &ST_HTTPTypeHeaders[i];
        }
	fprintf(stdout,"\tParameters:\n");
	f = &ST_HTTPFields[0];
	i = 0;
	while((f->name!= NULL)) {
		fprintf(stdout,"\t\t%s=%d\n",f->name,f->matchs);
		i++;
		f = &ST_HTTPFields[i];
	}	
	return;
}

/**
 * HTAZ_Destroy - Destroy the fields created by the init function
 */
void *HTAZ_Destroy() {
	TROF_Destroy(_http.t_off);
	g_hash_table_destroy(_http.methods);
	g_hash_table_destroy(_http.parameters);
	pcre_free(_http.expr_header);
#if PCRE_MAYOR == 8 && PCRE_MINOR >= 20
	pcre_free_study(_http.pe_header);
#else
	pcre_free(_http.pe_header);
#endif
}

/**
 * HTAZ_AnalyzeHTTPRequest - Analyze the HTTP segment in order to evaluate if the fields exist on the http cache.
 * also tryes to find suspicious opcodes on the fields if it dont exist on the http cache.
 *
 * @param c The ST_Cache.
 * @param f The ST_GenericFlow to analyze.
 * @param ret the result of the analisys.
 */

void *HTAZ_AnalyzeHTTPRequest(ST_Cache *c,ST_GenericFlow *f , int *ret){
	ST_MemorySegment *seg = f->memory;
	ST_CacheNode *nod = NULL;
	int lret,i,process_bytes;
	int have_data = FALSE;
	ST_HTTPField *h_field = NULL;
	ST_HTTPField *p_field = NULL;
	gpointer pointer = NULL;

	DEBUG0("Analyzing flow(0x%x)[bytes(%d)packets(%d)]segment(0x0%x)[realsize(%d)virtualsize(%d)]\n",
		f,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
	lret = pcre_exec(_http.expr_header,_http.pe_header,(char*)seg->mem,seg->virtual_size,
		0 /* Start offset */,
		0 /* options */ ,
		_http.ovector, OVECCOUNT);
	if (lret>1) { // The packet contains a minimum http header	
		char method[16];
		char uri[MAX_URI_LENGTH];
		int methodlen,urilen,offset;

		process_bytes = 0;
		offset = 0;
		methodlen = _http.ovector[3]-_http.ovector[2];
		urilen = _http.ovector[1]-_http.ovector[0];

                TROF_Reset(_http.t_off); // Reset the trust offsets candidates

		_http.total_http_bytes += seg->virtual_size;	
		_http.total_http_segments ++;
		if (methodlen>15){
			exit(-1);
		} 
		memcpy(method,&(seg->mem[0]), methodlen);
		method[methodlen] = '\0';
		if(g_hash_table_lookup_extended(_http.methods,(gchar*)method,NULL,&pointer) == TRUE){
			h_field = (ST_HTTPField*)pointer;
			h_field->matchs++;
			if(h_field->have_data)
				have_data = TRUE;
		}else{
			ST_HTTPTypeHeaders[HTTP_HEADER_UNKNOWN].matchs++;
			if(_http.show_unknown_http)
				WARNING("Unknown HTTP header(%.*s)\n",128,method);
				
		}	
		if(urilen>MAX_URI_LENGTH) {
			urilen = MAX_URI_LENGTH-1;
		}
		memcpy(uri,&(seg->mem[0]),urilen);
		uri[urilen] = '\0';
		DEBUG0("flow(0x%x) HTTP uri(%s)offset(%d)length(%d)\n",f,uri,offset,urilen);
		nod = CACH_GetHeaderFromCache(c,uri);
		if (nod ==NULL ) { // The uri is not in the cache we should analyze
			int suspicious_opcodes = COSU_CheckSuspiciousOpcodes(uri,urilen);
			if(suspicious_opcodes>1) {
				DEBUG0("flow(0x%x) uri(%s) have %d suspicious bytes\n",f,uri,suspicious_opcodes);
				_http.suspicious_headers++;
				c->header_suspicious_opcodes ++;
				/* Most of the exploits have the next body
				 * 	GET \x00\xaa\xbb.......
				 * So there is no need to continue parsing the rest of the http header
				 */
				if(_http.on_suspicious_header_break == TRUE) {
					_http.total_suspicious_segments++;
					(*ret) = 1;
					return;
				}
			} 	
		}else{
			// The header is on the cache, marked the trust offsets
			TROF_AddTrustOffset(_http.t_off,0,process_bytes);
		}
		process_bytes += urilen+2;
		char *init = &seg->mem[urilen+2];
		char http_line[MAX_HTTP_LINE_LENGTH];
		int http_line_length;
		char *ptrend = NULL;
		while(init != NULL) {
			ptrend = strstr(init,CRLF);
			if (ptrend != NULL) { // got it
				http_line_length = (ptrend-init)+1;
				ptrend = ptrend + 2; // from strlen(CRLF);
			
				memcpy(http_line,init,http_line_length);
				http_line[http_line_length-1] = '\0';
				if(strlen(http_line)>0) {
					/* retrieve the parameter name of the http line */
					char parameter[MAX_HTTP_LINE_LENGTH];
					char *pend = strstr(init,":");
					if(pend != NULL) {
						int parameter_length = (pend-init)+1;
				
						memcpy(parameter,init,parameter_length);
						parameter[parameter_length-1] = '\0';	
						//snprintf(parameter,parameter_length,"%s",init);
						DEBUG0("flow(0x%x) HTTP parameter(%s)value(%s)offset(%d)length(%d)\n",f,
							parameter,http_line,process_bytes,http_line_length);

						if(g_hash_table_lookup_extended(_http.parameters,(gchar*)parameter,NULL,&pointer) == TRUE){
							p_field = (ST_HTTPField*)pointer;
							p_field->matchs++;
						}else{
							ST_HTTPFields[HTTP_FIELD_UNKNOWN].matchs++;
							if(_http.show_unknown_http)
								WARNING("Unknown parameter(%s)offset(%d)\n",http_line,process_bytes);
						}
						nod = CACH_GetParameterFromCache(c,http_line);
						if(nod == NULL) { // The parameter value is not in the cache
							int suspicious_opcodes = COSU_CheckSuspiciousOpcodes(parameter,parameter_length);
							if(suspicious_opcodes>1) {
								DEBUG0("flow(0x%x) parameter have %d suspicious bytes\n",f,suspicious_opcodes);
								c->parameter_suspicious_opcodes ++;
								_http.suspicious_parameters++;
								if(_http.on_suspicious_parameter_break == TRUE){
									_http.total_suspicious_segments++;
									(*ret) = 1;
									return;
								}
							}
						}else{
			                        	// The parameter is on the cache, marked the trust offsets
                        				TROF_AddTrustOffset(_http.t_off,process_bytes,http_line_length+process_bytes);
						}
					}
				}
				process_bytes += http_line_length;
			}else{
				if(have_data == TRUE){ // The payload of a post request
					int len = seg->virtual_size - process_bytes;
					if(_http.analyze_post_data) { // the data of the post should be analyzed.
						DEBUG0("flow(0x%x) POST data forced to be suspicious\n",f);
                                                c->parameter_suspicious_opcodes ++;
                                                _http.suspicious_parameters++;
                                                if(_http.on_suspicious_parameter_break == TRUE){
                                                        _http.total_suspicious_segments++;
							(*ret) = 1;
                                                        return ;
                                                }	
					}	
					int suspicious_opcodes = COSU_CheckSuspiciousOpcodes(init,len);
					if(suspicious_opcodes>1) {
						DEBUG0("flow(0x%x) POST data have %d suspicious bytes\n",f,suspicious_opcodes);
                                                c->parameter_suspicious_opcodes ++;
                                                _http.suspicious_parameters++;
                                                if(_http.on_suspicious_parameter_break == TRUE){
                                                	_http.total_suspicious_segments++;
							(*ret) = 1;
							return;
						}
					}	
					//printf("post data %d\n",suspicious_opcodes);
					//printf("%s\n",init);
				}
				//printf("no more parameters, process bytes %d of %d\n",process_bytes,seg->virtual_size);
				break;
			}
			init = ptrend;
		}	
	}else{
		if(_http.show_unknown_http)
			WARNING("Unknown HTTP header(%.*s)\n",128,seg->mem);
                ST_HTTPTypeHeaders[HTTP_HEADER_UNKNOWN].matchs++;
		_http.total_suspicious_segments++;
		(*ret) = 1;
		return ;
	}
	_http.total_valid_segments++;
	(*ret) = 0;
	return ;
}

/**
 * HTAZ_AnalyzeDummyHTTPRequest - Analyze the HTTP segment generated by the dummy and add to the cache
 *
 * @param c The ST_Cache.
 * @param f The ST_GenericFlow to analyze.
 */

void *HTAZ_AnalyzeDummyHTTPRequest(ST_Cache *c, ST_GenericFlow *f){
        ST_MemorySegment *seg = f->memory;
        ST_CacheNode *nod = NULL;
        int lret,i;
        ST_HTTPField *h_field = NULL;
        ST_HTTPField *p_field = NULL;
        gpointer pointer = NULL;

        DEBUG0("Analyzing authorized flow(0x%x)[bytes(%d)packets(%d)]segment(0x0%x)[realsize(%d)virtualsize(%d)]\n",
                f,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
        lret = pcre_exec(_http.expr_header,_http.pe_header,(char*)seg->mem,seg->virtual_size,
                0 /* Start offset */,
                0 /* options */ ,
                _http.ovector, OVECCOUNT);
        if (lret>1) { // The packet contains a minimum http header       
                char method[16];
                char uri[MAX_URI_LENGTH];
                int methodlen,urilen,offset;

                offset = 0;
                methodlen = _http.ovector[3]-_http.ovector[2];
                urilen = _http.ovector[1]-_http.ovector[0];
                _http.total_http_bytes += seg->virtual_size;
		_http.total_http_segments ++;

                if(urilen>MAX_URI_LENGTH) {
                        urilen = MAX_URI_LENGTH-1;
                }
		memcpy(uri,&(seg->mem[0]),urilen);
		uri[urilen] = '\0';
                DEBUG0("authorized flow(0x%x) HTTP uri(%s)offset(%d)\n",f,uri,offset);
		/* Adds the uri to the http cache */
                CACH_AddHeaderToCache(c,uri,NODE_TYPE_DYNAMIC);
		
		/* analyze the parameters of the http request */
                char *init = &seg->mem[urilen+2];
                char http_line[MAX_HTTP_LINE_LENGTH];
                int http_line_length;
                char *ptrend = NULL;
                while(init != NULL) {
                        ptrend = strstr(init,CRLF);
                        if (ptrend != NULL) { // got it
                                http_line_length = (ptrend-init)+1;
                                ptrend = ptrend + 2; // from strlen(CRLF);
				memcpy(http_line,init,http_line_length);
				http_line[http_line_length-1] = '\0';
                                if(strlen(http_line)>0) {
                                        /* retrieve the parameter name */
                                        char parameter[MAX_HTTP_LINE_LENGTH];
                                        char *pend = strstr(init,":");
                                        if(pend != NULL) {
						int parameter_length = (pend-init)+1;
						memcpy(parameter,init,parameter_length);
						parameter[parameter_length-1] = '\0';
                                                if(g_hash_table_lookup_extended(_http.parameters,(gchar*)parameter,NULL,&pointer) == TRUE){
                                                        p_field = (ST_HTTPField*)pointer;
							if(p_field->check_cache == TRUE) {
								/* The value could be cacheable so add to the cache */
                                                		DEBUG0("authorized flow(0x%x) HTTP parameter(%s)\n",f,http_line);
								/* Adds the parameter to the httpcache */
								CACH_AddParameterToCache(c,http_line,NODE_TYPE_DYNAMIC);
							}
						}
                                        }
                                }
                        }else{
                                break;
                        }
                        init = ptrend;
                }
	}
	return;
}

/* Service functions */
int32_t HTAZ_GetNumberValidHTTPHeaders(){
	register int i;
	int32_t value = 0;

        for(i = 0;i<HTTP_HEADER_UNKNOWN;i++)
		value += ST_HTTPTypeHeaders[i].matchs;

	return value; 
}
int32_t HTAZ_GetNumberUnknownHTTPHeaders(){

	return ST_HTTPTypeHeaders[HTTP_HEADER_UNKNOWN].matchs;
}

int32_t HTAZ_GetNumberValidHTTPParameters(){
	register int i;
	int32_t value = 0;
	
	for (i = 0;i<HTTP_FIELD_UNKNOWN;i++) 
		value += ST_HTTPFields[i].matchs;	

	return value;	
}

int32_t HTAZ_GetNumberUnknownHTTPParameters(){

	return ST_HTTPFields[HTTP_FIELD_UNKNOWN].matchs;
}

int32_t HTAZ_GetNumberSuspiciousHTTPHeaders(){
	return _http.suspicious_headers;
}

int32_t HTAZ_GetNumberSuspiciousHTTPParameters(){
	return _http.suspicious_parameters;
}

int32_t HTAZ_GetNumberSuspiciousSegments() { return _http.total_suspicious_segments;}
int32_t HTAZ_GetNumberValidSegments() { return _http.total_valid_segments;}

ST_TrustOffsets *HTAZ_GetTrustOffsets(void){
	return _http.t_off;
}
