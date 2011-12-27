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

#define HTTP_URI_END "HTTP/1.1"
#define HTTP_HEADER_PARAM "^(GET|POST|OPTIONS|HEAD|CONNECT).*" HTTP_URI_END

#define MAX_URI_LENGTH 2048

static ST_HttpAnalyzer _http;

/**
 * Initialize all the fields of a small http analyzer
 */
void HTAZ_Init() {
	register int i;
	int erroffset;

        _http.suspicious_headers = 0;
        _http.suspicious_parameters = 0;
        _http.total_http_bytes = 0;
        _http.total_http_segments = 0;
	_http.on_suspicious_header_break = TRUE;
	_http.on_suspicious_parameter_break = TRUE;

	_http.expr_header = pcre_compile((char*)HTTP_HEADER_PARAM, PCRE_DOTALL, &_http.errstr, &erroffset, 0);
	_http.pe_header = NULL;

	_http.methods = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
	_http.parameters = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
	for(i = 0;i<HTTP_MAX_HEADER;i++) {
		g_hash_table_insert(_http.methods,g_strdup(ST_HttpTypeHeaders[i].name),&(ST_HttpTypeHeaders[i]));
		DEBUG1("Adding HTTP (%s)(0x%x) header type\n",ST_HttpTypeHeaders[i].name,&(ST_HttpTypeHeaders[i]));
	}	
	for (i = 0;i<HTTP_MAX_FIELD;i++) {
		g_hash_table_insert(_http.parameters,g_strdup(ST_HttpFields[i].name),&(ST_HttpFields[i]));
		DEBUG1("Adding HTTP (%s)(0x%x) parameter type\n",ST_HttpFields[i].name,&(ST_HttpFields[i]));
	}	
}

/**
 * Prints staticstics related to http
 */
void HTAZ_PrintfStats() {
	register int i;

	fprintf(stdout,"HTTP Analyzer Statistics\n");
	fprintf(stdout,"\ttotal segments %ld\n",_http.total_http_segments);
	fprintf(stdout,"\ttotal bytes %ld\n",_http.total_http_bytes);
	fprintf(stdout,"\tHeaders:\n");
	for (i = 0;i<HTTP_MAX_HEADER;i++) {
		fprintf(stdout,"\t\t%s=%d\n",ST_HttpTypeHeaders[i].name,ST_HttpTypeHeaders[i].matchs);
	}	
	fprintf(stdout,"\tParameters:\n");
	for (i = 0;i<HTTP_MAX_FIELD;i++) {
		fprintf(stdout,"\t\t%s=%d\n",ST_HttpFields[i].name,ST_HttpFields[i].matchs);
	}	
	return;
}

/**
 * Destroy the fields created by the init function
 */
void HTAZ_Destroy() {
	g_hash_table_destroy(_http.methods);
	g_hash_table_destroy(_http.parameters);
	pcre_free(_http.expr_header);
	pcre_free(_http.pe_header);
}

/**
 * Analyze the HTTP segment in order to evaluate if the fields exist on the http cache.
 * also tryes to find suspicious opcodes on the fields if it dont exist on the http cache.
 *
 * @param c The ST_HttpCache.
 * @param f The ST_HttpFlow to analyze.
 *
 */

int HTAZ_AnalyzeHttpRequest(ST_HttpCache *c,ST_HttpFlow *f){
	ST_MemorySegment *seg = f->memhttp;
	ST_HttpNode *nod = NULL;
	int ret,i;
	ST_HttpField *h_field = NULL;
	ST_HttpField *p_field = NULL;
	gpointer pointer = NULL;

	DEBUG0("Analyzing flow(0x%x)[bytes(%d)packets(%d)]segment(0x0%x)[realsize(%d)virtualsize(%d)]\n",
		f,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
	ret = pcre_exec(_http.expr_header,_http.pe_header,(char*)seg->mem,seg->virtual_size,
		0 /* Start offset */,
		0 /* options */ ,
		_http.ovector, OVECCOUNT);
	if (ret>1) { // The packet contains a minimum http header	
		char method[16];
		char uri[MAX_URI_LENGTH];
		int methodlen,urilen,offset;

		offset = 0;
		methodlen = _http.ovector[3]-_http.ovector[2];
		urilen = _http.ovector[1]-_http.ovector[0];

		_http.total_http_bytes += seg->virtual_size;	
		_http.total_http_segments ++;
		if (methodlen>1024){
			exit(-1);
		} 
		snprintf(method,methodlen+1,"%s",&(seg->mem[offset]));
		if(g_hash_table_lookup_extended(_http.methods,(gchar*)method,NULL,&pointer) == TRUE){
			h_field = (ST_HttpField*)pointer;
			h_field->matchs++;
		}else{
			WARNING("Unkown HTTP header(%s)\n",method);
			ST_HttpTypeHeaders[HTTP_HEADER_UNKNOWN].matchs++;
		}	
		if(urilen>MAX_URI_LENGTH) {
			urilen = MAX_URI_LENGTH;
		}
		snprintf(uri,urilen+1,"%s",&(seg->mem[offset]));
		DEBUG0("flow(0x%x) HTTP uri(%s)offset(%d)\n",f,uri,offset);
		nod = HTCC_GetHeaderFromCache(c,uri);
		if (nod ==NULL ) { // The uri is not in the cache we should analyze
			int suspicious_opcodes = CO_CountSuspiciousOpcodes(uri,urilen);
			if(suspicious_opcodes>1) {
				DEBUG0("flow(0x%x) header have %d suspicious bytes\n",f,suspicious_opcodes);
				_http.suspicious_headers++;
				c->header_suspicious_opcodes ++;
				/* Most of the exploits have the next body
				 * 	GET \x00\xaa\xbb.......
				 * So there is no need to continue parsing the rest of the http header
				 */
				if(_http.on_suspicious_header_break == TRUE)
					return 1;
			} 	
			printf("suspicious_opcodes = %d\n",suspicious_opcodes);	
		}
		char *init = &seg->mem[urilen+2];
		char parameter_value[1024];
		int parameter_length;
		char *ptrend = NULL;
		while(init != NULL) {
			ptrend = strstr(init,CRLF);
			if (ptrend != NULL) { // got it
				parameter_length = (ptrend-init)+1;
				ptrend = ptrend + 2; // from strlen(CRLF);
				snprintf(parameter_value,parameter_length,"%s",init);
				if(strlen(parameter_value)>0) {
					/* retrieve the parameter name */
					char p_value[1024];
					char *pend = strstr(init,":");
					if(pend != NULL) {
						snprintf(p_value,(pend-init)+1,"%s",init);
						DEBUG1("flow(0x%x) HTTP parameter(%s)\n",f,parameter_value);

						if(g_hash_table_lookup_extended(_http.parameters,(gchar*)p_value,NULL,&pointer) == TRUE){
							p_field = (ST_HttpField*)pointer;
							p_field->matchs++;
						}else{
							ST_HttpFields[HTTP_FIELD_UNKNOWN].matchs++;
							WARNING("Unknown parameter (%s)\n",parameter_value);
						}
						nod = HTCC_GetParameterFromCache(c,parameter_value);
						if(nod == NULL) { // The parameter is not in the cache
					//		DEBUG0("flow(0x%x) parameter(%s) out cache\n",f,parameter_value);
							int suspicious_opcodes = CO_CountSuspiciousOpcodes(parameter_value,parameter_length);
							if(suspicious_opcodes>1) {
								DEBUG1("flow(0x%x) parameter have %d suspicious bytes\n",f,suspicious_opcodes);
								c->parameter_suspicious_opcodes ++;
								_http.suspicious_parameters++;
								if(_http.on_suspicious_parameter_break == TRUE)
									return 1;
							}
                                        	}else{
						//	DEBUG0("flow(0x%x) parameter(%s) on cache\n",f,parameter_value);
						}
					}
				}
			}else{
				//printf("no more parameters\n");
				break;
			}
			init = ptrend;
		}	
	}else{
		printf("joder\n");
                WARNING("Unkown HTTP header\n");
                ST_HttpTypeHeaders[HTTP_HEADER_UNKNOWN].matchs++;
		return 1;
	}
	return 0;
}

void HTAZ_AnalyzeDummyHttpRequest(ST_HttpCache *c, ST_HttpFlow *f){
        ST_MemorySegment *seg = f->memhttp;
        ST_HttpNode *nod = NULL;
        int ret,i;
        ST_HttpField *h_field = NULL;
        ST_HttpField *p_field = NULL;
        gpointer pointer = NULL;

        DEBUG0("Analyzing authorized flow(0x%x)[bytes(%d)packets(%d)]segment(0x0%x)[realsize(%d)virtualsize(%d)]\n",
                f,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
        ret = pcre_exec(_http.expr_header,_http.pe_header,(char*)seg->mem,seg->virtual_size,
                0 /* Start offset */,
                0 /* options */ ,
                _http.ovector, OVECCOUNT);
        if (ret>1) { // The packet contains a minimum http header       
                char method[16];
                char uri[1024];
                int methodlen,urilen,offset;

                offset = 0;
                methodlen = _http.ovector[3]-_http.ovector[2];
                urilen = _http.ovector[1]-_http.ovector[0];
                _http.total_http_bytes += seg->virtual_size;
		_http.total_http_segments ++;

                if(urilen>1024) {
                        urilen = 1023;
                }
                snprintf(uri,urilen+1,"%s",&(seg->mem[offset]));
                DEBUG0("authorized flow(0x%x) HTTP uri(%s)offset(%d)\n",f,uri,offset);
		/* Adds the uri to the http cache */
                HTCC_AddHeaderToCache(c,uri,HTTP_NODE_TYPE_DYNAMIC);
		
		/* analyze the parameters of the http request */
                char *init = &seg->mem[urilen+2];
                char parameter_value[1024];
                int parameter_length;
                char *ptrend = NULL;
                while(init != NULL) {
                        ptrend = strstr(init,CRLF);
                        if (ptrend != NULL) { // got it
                                parameter_length = (ptrend-init)+1;
                                ptrend = ptrend + 2; // from strlen(CRLF);
                                snprintf(parameter_value,parameter_length,"%s",init);
                                if(strlen(parameter_value)>0) {
                                        /* retrieve the parameter name */
                                        char p_value[1024];
                                        char *pend = strstr(init,":");
                                        if(pend != NULL) {
                                                snprintf(p_value,(pend-init)+1,"%s",init);
                                                DEBUG0("authorized flow(0x%x) HTTP parameter(%s)\n",f,parameter_value);
						/* Adds the parameter to the httpcache */
						HTCC_AddParameterToCache(c,parameter_value,HTTP_NODE_TYPE_DYNAMIC);
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
		value += ST_HttpTypeHeaders[i].matchs;

	return value; 
}
int32_t HTAZ_GetNumberUnknownHTTPHeaders(){

	return ST_HttpTypeHeaders[HTTP_HEADER_UNKNOWN].matchs;
}

int32_t HTAZ_GetNumberValidHTTPParameters(){
	register int i;
	int32_t value = 0;
	
	for (i = 0;i<HTTP_FIELD_UNKNOWN;i++) 
		value += ST_HttpFields[i].matchs;	

	return value;	
}

int32_t HTAZ_GetNumberUnknownHTTPParameters(){

	return ST_HttpFields[HTTP_FIELD_UNKNOWN].matchs;
}

int32_t HTAZ_GetNumberSuspiciousHTTPHeaders(){
	return _http.suspicious_headers;
}

int32_t HTAZ_GetNumberSuspiciousHTTPParameters(){
	return _http.suspicious_parameters;
}
