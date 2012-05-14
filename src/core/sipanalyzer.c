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

#include "sipanalyzer.h"
#include "sipvalues.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_FILTER_SIP_INTERFACE
#include "log.h"

#define SIP_URI_END "SIP/2.[0|1]"
#define SIP_HEADER_PARAM "^(REGISTER|INVITE|ACK|CANCEL|BYE|OPTIONS|MESSAGE).*" SIP_URI_END

#define MAX_SIP_LINE_LENGTH 2048
#define MAX_URI_LENGTH 2048

static ST_SIPAnalyzer _sip;

/**
 * SPAZ_Init - Initialize all the fields of a small sip analyzer
 */
void *SPAZ_Init() {
	register int i;
	int erroffset;
	ST_SIPField *f;

        _sip.suspicious_headers = 0;
        _sip.suspicious_parameters = 0;
        _sip.total_sip_bytes = 0;
        _sip.total_sip_segments = 0;
	_sip.total_suspicious_segments = 0;
	_sip.total_valid_segments = 0;
	_sip.on_suspicious_header_break = FALSE;
	_sip.on_suspicious_parameter_break = FALSE; 
	_sip.analyze_sdp_data = FALSE;
	_sip.show_unknown_sip = FALSE;

	_sip.expr_header = pcre_compile((char*)SIP_HEADER_PARAM, PCRE_FIRSTLINE, &_sip.errstr, &erroffset, 0);
#ifdef PCRE_HAVE_JIT
        _sip.pe_header = pcre_study(_sip.expr_header,PCRE_STUDY_JIT_COMPILE,&_sip.errstr);
        if(_sip.pe_header == NULL){
		LOG(POLYLOG_PRIORITY_WARN,
                	"PCRE study with JIT support failed '%s'.\n",_sip.errstr);
        }
        int jit = 0;
        int ret;

        ret = pcre_fullinfo(_sip.expr_header,_sip.pe_header, PCRE_INFO_JIT,&jit);
        if (ret != 0 || jit != 1) {
		LOG(POLYLOG_PRIORITY_WARN,
                	"PCRE JIT compiler does not support the expresion on the SIP analyzer.\n");
        }
#else
        _sip.pe_header = pcre_study(_sip.expr_header,0,&_sip.errstr);
        if(_sip.pe_header == NULL)
		LOG(POLYLOG_PRIORITY_WARN,
                	"PCRE study failed '%s'\n",_sip.errstr);
#endif
	_sip.t_off = TROF_Init(); // Init the stack offsets

	_sip.methods = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
	_sip.parameters = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);

	f = &ST_SIPTypeHeaders[0];
	i = 0;
	while((f->name!= NULL)) {
		g_hash_table_insert(_sip.methods,g_strdup(f->name),f);
		i ++;
		f = &ST_SIPTypeHeaders[i];
	}	
	f = &ST_SIPFields[0];
	i = 0;
	while((f->name!= NULL)) {
		g_hash_table_insert(_sip.parameters,g_strdup(f->name),f);
		i++;
		f = &ST_SIPFields[i];
	}	
	COSU_Init();
	_sip.sipcache = CACH_Init();
	return;
}


void SPAZ_ShowUnknownSIP(int value){
	_sip.show_unknown_sip = value;
}

void SPAZ_SetForceAnalyzeSIPPostData(int value){
	_sip.analyze_sdp_data = value;
}

/**
 * SPAZ_Stats - Prints staticstics related to sip
 */
void *SPAZ_Stats() {
	register int i;
	ST_SIPField *f;

	fprintf(stdout,"SIP analyzer statistics\n");
	fprintf(stdout,"\ttotal segments %ld\n",_sip.total_sip_segments);
	fprintf(stdout,"\ttotal bytes %ld\n",_sip.total_sip_bytes);
	fprintf(stdout,"\ttotal suspicious segments %ld\n",_sip.total_suspicious_segments);
	fprintf(stdout,"\ttotal valid segments %ld\n",_sip.total_valid_segments);
	fprintf(stdout,"\tHeaders:\n");

        f = &ST_SIPTypeHeaders[0];
        i = 0;
        while((f->name!= NULL)) {
		fprintf(stdout,"\t\t%s=%d\n",f->name,f->matchs);
                i ++;
                f = &ST_SIPTypeHeaders[i];
        }
	fprintf(stdout,"\tParameters:\n");
	f = &ST_SIPFields[0];
	i = 0;
	while((f->name!= NULL)) {
		fprintf(stdout,"\t\t%s=%d\n",f->name,f->matchs);
		i++;
		f = &ST_SIPFields[i];
	}	
	CACH_Stats(_sip.sipcache);
	return;
}

/**
 * SPAZ_Destroy - Destroy the fields created by the init function
 */
void *SPAZ_Destroy() {
	TROF_Destroy(_sip.t_off);
	g_hash_table_destroy(_sip.methods);
	g_hash_table_destroy(_sip.parameters);
	pcre_free(_sip.expr_header);
#if PCRE_MAYOR == 8 && PCRE_MINOR >= 20
        pcre_free_study(_sip.pe_header);
#else
        pcre_free(_sip.pe_header);
#endif
	CACH_Destroy(_sip.sipcache);
}

/**
 * SPAZ_AnalyzeSIPRequest - Analyze the SIP segment in order to evaluate if the fields exist on the sip cache.
 * also tryes to find suspicious opcodes on the fields if it dont exist on the sip cache.
 *
 * @param user The ST_user information.
 * @param f The ST_GenericFlow to analyze.
 * @param ret the result of the analisys.
 */

void *SPAZ_AnalyzeSIPRequest(ST_User *user,ST_GenericFlow *f , int *ret){
	ST_MemorySegment *seg = f->memory;
	ST_CacheNode *nod = NULL;
	int lret,i,process_bytes;
	int have_data = FALSE;
	ST_SIPField *h_field = NULL;
	ST_SIPField *p_field = NULL;
	gpointer pointer = NULL;

#ifdef DEBUG
	LOG(POLYLOG_PRIORITY_DEBUG,
		"User(0x%x)flow(0x%x)[bytes(%d)packets(%d)]segment(0x0%x)[realsize(%d)virtualsize(%d)]\n",
		user,f,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
#endif
	lret = pcre_exec(_sip.expr_header,_sip.pe_header,(char*)seg->mem,seg->virtual_size,
		0 /* Start offset */,
		0 /* options */ ,
		_sip.ovector, OVECCOUNT);
	if (lret>1) { // The packet contains a minimum sip header	
		char method[16];
		char uri[MAX_URI_LENGTH];
		int methodlen,urilen,offset;

		process_bytes = 0;
		offset = 0;
		methodlen = _sip.ovector[3]-_sip.ovector[2];
		urilen = _sip.ovector[1]-_sip.ovector[0];
               
		TROF_Reset(_sip.t_off); // Reset the trust offsets candidates

		_sip.total_sip_bytes += seg->virtual_size;	
		_sip.total_sip_segments ++;
		if (methodlen>15){
			exit(-1);
		} 
		memcpy(method,&(seg->mem[0]), methodlen);
		if(g_hash_table_lookup_extended(_sip.methods,(gchar*)method,NULL,&pointer) == TRUE){
			h_field = (ST_SIPField*)pointer;
			h_field->matchs++;
			if(h_field->have_data)
				have_data = TRUE;
		}else{
			ST_SIPTypeHeaders[SIP_HEADER_UNKNOWN].matchs++;
			if(_sip.show_unknown_sip)
				WARNING("Unknown SIP header(%.*s)\n",128,method);
				
		}	
		if(urilen>MAX_URI_LENGTH) {
			urilen = MAX_URI_LENGTH-1;
		}
		memcpy(uri,&(seg->mem[0]),urilen);
#ifdef DEBUG
		LOG(POLYLOG_PRIORITY_DEBUG,
			"flow(0x%x) SIP uri(%s)offset(%d)length(%d)\n",f,uri,offset,urilen);
#endif
		nod = CACH_GetHeaderFromCache(_sip.sipcache,uri);
		if (nod ==NULL ) { // The uri is not in the cache we should analyze
			int suspicious_opcodes = COSU_CheckSuspiciousOpcodes(uri,urilen);
			if(suspicious_opcodes>1) {
#ifdef DEBUG
				LOG(POLYLOG_PRIORITY_DEBUG,
					"flow(0x%x) uri(%s) have %d suspicious bytes\n",f,uri,suspicious_opcodes);
#endif
				_sip.suspicious_headers++;
				_sip.sipcache->header_suspicious_opcodes ++;
				/* Most of the exploits have the next body
				 * 	GET \x00\xaa\xbb.......
				 * So there is no need to continue parsing the rest of the sip header
				 */
				if(_sip.on_suspicious_header_break == TRUE) {
					_sip.total_suspicious_segments++;
					(*ret) = 1;
					return;
				}
			} 	
		}else{
			// The header is on the cache, marked the trust offsets
			TROF_AddTrustOffset(_sip.t_off,0,process_bytes);
		}
		process_bytes += urilen+2;
		char *init = &seg->mem[urilen+2];
		char sip_line[MAX_SIP_LINE_LENGTH];
		int sip_line_length;
		char *ptrend = NULL;
		while(init != NULL) {
			ptrend = strstr(init,CRLF);
			if (ptrend != NULL) { // got it
				sip_line_length = (ptrend-init)+1;
				ptrend = ptrend + 2; // from strlen(CRLF);
				snprintf(sip_line,sip_line_length,"%s",init);
				if(strlen(sip_line)>0) {
					/* retrieve the parameter name of the sip line */
					char parameter[MAX_SIP_LINE_LENGTH];
					char *pend = strstr(init,":");
					if(pend != NULL) {
						int parameter_length = (pend-init)+1;
					
						snprintf(parameter,parameter_length,"%s",init);
#ifdef DEBUG
						LOG(POLYLOG_PRIORITY_DEBUG,
							"flow(0x%x) SIP parameter(%s)value(%s)offset(%d)length(%d)\n",f,
							parameter,sip_line,process_bytes,sip_line_length);
#endif
						if(g_hash_table_lookup_extended(_sip.parameters,(gchar*)parameter,NULL,&pointer) == TRUE){
							p_field = (ST_SIPField*)pointer;
							p_field->matchs++;
						}else{
							ST_SIPFields[SIP_FIELD_UNKNOWN].matchs++;
							if(_sip.show_unknown_sip)
								WARNING("Unknown parameter(%s)offset(%d)\n",sip_line,process_bytes);
						}
						nod = CACH_GetParameterFromCache(_sip.sipcache,sip_line);
						if(nod == NULL) { // The parameter value is not in the cache
							int suspicious_opcodes = COSU_CheckSuspiciousOpcodes(parameter,parameter_length);
							if(suspicious_opcodes>1) {
#ifdef DEBUG
								LOG(POLYLOG_PRIORITY_DEBUG,
									"flow(0x%x) parameter have %d suspicious bytes\n",f,suspicious_opcodes);
#endif
								_sip.sipcache->parameter_suspicious_opcodes ++;
								_sip.suspicious_parameters++;
								if(_sip.on_suspicious_parameter_break == TRUE){
									_sip.total_suspicious_segments++;
									(*ret) = 1;
									return;
								}
							}
						}else{
			                        	// The parameter is on the cache, marked the trust offsets
                        				TROF_AddTrustOffset(_sip.t_off,process_bytes,sip_line_length+process_bytes);
						}
					}
				}
				process_bytes += sip_line_length;
			}else{
				if(have_data == TRUE){ // The payload of a post request
					int len = seg->virtual_size - process_bytes;
					if(_sip.analyze_sdp_data) { // the data of the post should be analyzed.
#ifdef DEBUG
						LOG(POLYLOG_PRIORITY_DEBUG,
							"flow(0x%x) SDP data forced to be suspicious\n",f);
#endif
                                                _sip.sipcache->parameter_suspicious_opcodes ++;
                                                _sip.suspicious_parameters++;
                                                if(_sip.on_suspicious_parameter_break == TRUE){
                                                        _sip.total_suspicious_segments++;
							(*ret) = 1;
                                                        return ;
                                                }	
					}	
					int suspicious_opcodes = COSU_CheckSuspiciousOpcodes(init,len);
					if(suspicious_opcodes>1) {
#ifdef DEBUG
						LOG(POLYLOG_PRIORITY_DEBUG,
							"flow(0x%x) SDP data have %d suspicious bytes\n",f,suspicious_opcodes);
#endif
                                                _sip.sipcache->parameter_suspicious_opcodes ++;
                                                _sip.suspicious_parameters++;
                                                if(_sip.on_suspicious_parameter_break == TRUE){
                                                	_sip.total_suspicious_segments++;
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
		if(_sip.show_unknown_sip)
			WARNING("Unknown SIP header(%.*s)\n",128,seg->mem);
                ST_SIPTypeHeaders[SIP_HEADER_UNKNOWN].matchs++;
		_sip.total_suspicious_segments++;
		(*ret) = 1;
		return ;
	}
	_sip.total_valid_segments++;
	(*ret) = 0;
	return ;
}

/**
 * SPAZ_AnalyzeDummySIPRequest - Analyze the SIP segment generated by the dummy and add to the cache
 *
 * @param user The ST_User information.
 * @param f The ST_GenericFlow to analyze.
 */

void *SPAZ_AnalyzeDummySIPRequest(ST_User *user,ST_GenericFlow *f){
        ST_MemorySegment *seg = f->memory;
        ST_CacheNode *nod = NULL;
        int lret,i;
        ST_SIPField *h_field = NULL;
        ST_SIPField *p_field = NULL;
        gpointer pointer = NULL;

#ifdef DEBUG
	LOG(POLYLOG_PRIORITY_DEBUG,
        	"UserAuthorized(0x%x)flow(0x%x)[bytes(%d)packets(%d)]segment(0x0%x)[realsize(%d)virtualsize(%d)]\n",
                user,f,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
#endif
        lret = pcre_exec(_sip.expr_header,_sip.pe_header,(char*)seg->mem,seg->virtual_size,
                0 /* Start offset */,
                0 /* options */ ,
                _sip.ovector, OVECCOUNT);
        if (lret>1) { // The packet contains a minimum sip header       
                char method[16];
                char uri[MAX_URI_LENGTH];
                int methodlen,urilen,offset;

                offset = 0;
                methodlen = _sip.ovector[3]-_sip.ovector[2];
                urilen = _sip.ovector[1]-_sip.ovector[0];
                _sip.total_sip_bytes += seg->virtual_size;
		_sip.total_sip_segments ++;

                if(urilen>MAX_URI_LENGTH) {
                        urilen = MAX_URI_LENGTH-1;
                }
                snprintf(uri,urilen+1,"%s",&(seg->mem[offset]));
		LOG(POLYLOG_PRIORITY_DEBUG,
                	"authorized flow(0x%x) SIP uri(%s)offset(%d)\n",f,uri,offset);
		/* Adds the uri to the sip cache */
                CACH_AddHeaderToCache(_sip.sipcache,uri,NODE_TYPE_DYNAMIC);
		
		/* analyze the parameters of the sip request */
                char *init = &seg->mem[urilen+2];
                char sip_line[MAX_SIP_LINE_LENGTH];
                int sip_line_length;
                char *ptrend = NULL;
                while(init != NULL) {
                        ptrend = strstr(init,CRLF);
                        if (ptrend != NULL) { // got it
                                sip_line_length = (ptrend-init)+1;
                                ptrend = ptrend + 2; // from strlen(CRLF);
                                snprintf(sip_line,sip_line_length,"%s",init);
                                if(strlen(sip_line)>0) {
                                        /* retrieve the parameter name */
                                        char parameter[MAX_SIP_LINE_LENGTH];
                                        char *pend = strstr(init,":");
                                        if(pend != NULL) {
                                                snprintf(parameter,(pend-init)+1,"%s",init);
#ifdef DEBUG
						LOG(POLYLOG_PRIORITY_DEBUG,
                                                	"authorized flow(0x%x) SIP parameter(%s)\n",f,sip_line);
#endif
						/* Adds the parameter to the sipcache */
						CACH_AddParameterToCache(_sip.sipcache,sip_line,NODE_TYPE_DYNAMIC);
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
int32_t SPAZ_GetNumberValidSIPHeaders(){
	register int i;
	int32_t value = 0;

        for(i = 0;i<SIP_HEADER_UNKNOWN;i++)
		value += ST_SIPTypeHeaders[i].matchs;

	return value; 
}
int32_t SPAZ_GetNumberUnknownSIPHeaders(){

	return ST_SIPTypeHeaders[SIP_HEADER_UNKNOWN].matchs;
}

int32_t SPAZ_GetNumberValidSIPParameters(){
	register int i;
	int32_t value = 0;
	
	for (i = 0;i<SIP_FIELD_UNKNOWN;i++) 
		value += ST_SIPFields[i].matchs;	

	return value;	
}

int32_t SPAZ_GetNumberUnknownSIPParameters(){

	return ST_SIPFields[SIP_FIELD_UNKNOWN].matchs;
}

int32_t SPAZ_GetNumberSuspiciousSIPHeaders(){
	return _sip.suspicious_headers;
}

int32_t SPAZ_GetNumberSuspiciousSIPParameters(){
	return _sip.suspicious_parameters;
}

int32_t SPAZ_GetNumberSuspiciousSegments() { return _sip.total_suspicious_segments;}
int32_t SPAZ_GetNumberValidSegments() { return _sip.total_valid_segments;}

ST_TrustOffsets *SPAZ_GetTrustOffsets(void){
	return _sip.t_off;
}
