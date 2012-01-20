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
#define HTTP_HEADER_PARAM "^(GET|POST|OPTIONS|HEAD|CONNECT).*" HTTP_URI_END

#define MAX_HTTP_LINE_LENGTH 2048
#define MAX_URI_LENGTH 2048

static ST_HttpAnalyzer _http;

/**
 * HTAZ_Init - Initialize all the fields of a small http analyzer
 */
void HTAZ_Init() {
	register int i;
	int erroffset;

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


void HTAZ_ShowUnknownHttp(int value){
	_http.show_unknown_http = value;
}

void HTAZ_SetForceAnalyzeHttpPostData(int value){
	_http.analyze_post_data = value;
}

/**
 * HTAZ_PrintfStats - Prints staticstics related to http
 */
void HTAZ_PrintfStats() {
	register int i;

	fprintf(stdout,"HTTP analyzer statistics\n");
	fprintf(stdout,"\ttotal segments %ld\n",_http.total_http_segments);
	fprintf(stdout,"\ttotal bytes %ld\n",_http.total_http_bytes);
	fprintf(stdout,"\ttotal suspicious segments %ld\n",_http.total_suspicious_segments);
	fprintf(stdout,"\ttotal valid segments %ld\n",_http.total_valid_segments);
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
 * HTAZ_Destroy - Destroy the fields created by the init function
 */
void HTAZ_Destroy() {
	g_hash_table_destroy(_http.methods);
	g_hash_table_destroy(_http.parameters);
	pcre_free(_http.expr_header);
	pcre_free(_http.pe_header);
}

/**
 * HTAZ_AnalyzeHttpRequest - Analyze the HTTP segment in order to evaluate if the fields exist on the http cache.
 * also tryes to find suspicious opcodes on the fields if it dont exist on the http cache.
 *
 * @param c The ST_HttpCache.
 * @param f The ST_HttpFlow to analyze.
 *
 */

int HTAZ_AnalyzeHttpRequest(ST_HttpCache *c,ST_HttpFlow *f){
	ST_MemorySegment *seg = f->memhttp;
	ST_HttpNode *nod = NULL;
	int ret,i,process_bytes;
	int have_data = FALSE;
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

		process_bytes = 0;
		offset = 0;
		methodlen = _http.ovector[3]-_http.ovector[2];
		urilen = _http.ovector[1]-_http.ovector[0];

		_http.total_http_bytes += seg->virtual_size;	
		_http.total_http_segments ++;
		if (methodlen>15){
			exit(-1);
		} 
		snprintf(method,methodlen+1,"%s",&(seg->mem[offset]));
		if(g_hash_table_lookup_extended(_http.methods,(gchar*)method,NULL,&pointer) == TRUE){
			h_field = (ST_HttpField*)pointer;
			h_field->matchs++;
			if(h_field->have_data)
				have_data = TRUE;
		}else{
			ST_HttpTypeHeaders[HTTP_HEADER_UNKNOWN].matchs++;
			if(_http.show_unknown_http)
				WARNING("Unknown HTTP header(%.*s)\n",128,method);
				
		}	
		if(urilen>MAX_URI_LENGTH) {
			urilen = MAX_URI_LENGTH-1;
		}
		snprintf(uri,urilen+1,"%s",&(seg->mem[offset]));
		DEBUG0("flow(0x%x) HTTP uri(%s)offset(%d)length(%d)\n",f,uri,offset,urilen);
		nod = HTCC_GetHeaderFromCache(c,uri);
		if (nod ==NULL ) { // The uri is not in the cache we should analyze
			int suspicious_opcodes = CO_CountSuspiciousOpcodes(uri,urilen);
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
					return 1;
				}
			} 	
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
				snprintf(http_line,http_line_length,"%s",init);
				if(strlen(http_line)>0) {
					/* retrieve the parameter name of the http line */
					char parameter[MAX_HTTP_LINE_LENGTH];
					char *pend = strstr(init,":");
					if(pend != NULL) {
						int parameter_length = (pend-init)+1;
					
						snprintf(parameter,parameter_length,"%s",init);
						DEBUG1("flow(0x%x) HTTP parameter(%s)value(%s)offset(%d)length(%d)\n",f,
							parameter,http_line,process_bytes,http_line_length);

						if(g_hash_table_lookup_extended(_http.parameters,(gchar*)parameter,NULL,&pointer) == TRUE){
							p_field = (ST_HttpField*)pointer;
							p_field->matchs++;
						}else{
							ST_HttpFields[HTTP_FIELD_UNKNOWN].matchs++;
							if(_http.show_unknown_http)
								WARNING("Unknown parameter(%s)offset(%d)\n",http_line,process_bytes);
						}
						nod = HTCC_GetParameterFromCache(c,http_line);
						if(nod == NULL) { // The parameter value is not in the cache
							int suspicious_opcodes = CO_CountSuspiciousOpcodes(parameter,parameter_length);
							if(suspicious_opcodes>1) {
								DEBUG1("flow(0x%x) parameter have %d suspicious bytes\n",f,suspicious_opcodes);
								c->parameter_suspicious_opcodes ++;
								_http.suspicious_parameters++;
								if(_http.on_suspicious_parameter_break == TRUE){
									_http.total_suspicious_segments++;
									return 1;
								}
							}
						}
					}
				}
				process_bytes += http_line_length;
			}else{
				if(have_data == TRUE){ // The payload of a post request
					int len = seg->virtual_size - process_bytes;
					if(_http.analyze_post_data) { // the data of the post should be analyzed.
						DEBUG1("flow(0x%x) POST data forced to be suspicious\n",f);
                                                c->parameter_suspicious_opcodes ++;
                                                _http.suspicious_parameters++;
                                                if(_http.on_suspicious_parameter_break == TRUE){
                                                        _http.total_suspicious_segments++;
                                                        return 1;
                                                }	
					}	
					int suspicious_opcodes = CO_CountSuspiciousOpcodes(init,len);
					if(suspicious_opcodes>1) {
						DEBUG1("flow(0x%x) POST data have %d suspicious bytes\n",f,suspicious_opcodes);
                                                c->parameter_suspicious_opcodes ++;
                                                _http.suspicious_parameters++;
                                                if(_http.on_suspicious_parameter_break == TRUE){
                                                	_http.total_suspicious_segments++;
							return 1;
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
                ST_HttpTypeHeaders[HTTP_HEADER_UNKNOWN].matchs++;
		_http.total_suspicious_segments++;
		return 1;
	}
	_http.total_valid_segments++;
	return 0;
}

/**
 * HTAZ_AnalyzeDummyHttpRequest - Analyze the HTTP segment generated by the dummy and add to the cache
 *
 * @param c The ST_HttpCache.
 * @param f The ST_HttpFlow to analyze.
 *
 */

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
                snprintf(uri,urilen+1,"%s",&(seg->mem[offset]));
                DEBUG0("authorized flow(0x%x) HTTP uri(%s)offset(%d)\n",f,uri,offset);
		/* Adds the uri to the http cache */
                HTCC_AddHeaderToCache(c,uri,HTTP_NODE_TYPE_DYNAMIC);
		
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
                                snprintf(http_line,http_line_length,"%s",init);
                                if(strlen(http_line)>0) {
                                        /* retrieve the parameter name */
                                        char parameter[MAX_HTTP_LINE_LENGTH];
                                        char *pend = strstr(init,":");
                                        if(pend != NULL) {
                                                snprintf(parameter,(pend-init)+1,"%s",init);
                                                DEBUG0("authorized flow(0x%x) HTTP parameter(%s)\n",f,http_line);
						/* Adds the parameter to the httpcache */
						HTCC_AddParameterToCache(c,http_line,HTTP_NODE_TYPE_DYNAMIC);
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

int32_t HTAZ_GetNumberSuspiciousSegments() { return _http.total_suspicious_segments;}
int32_t HTAZ_GetNumberValidSegments() { return _http.total_valid_segments;}

