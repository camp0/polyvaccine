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

	_dos.statistics_level = 0;
        _dos.total_http_bytes = 0;
        _dos.total_http_request = 0;
        _dos.http_request_per_minute = 0;
	_dos.total_exist_links = 0;
	_dos.total_exist_uri = 0;
	_dos.total_nonexist_uri = 0;
	_dos.total_nonexist_links = 0;
	_dos.total_valid_links = 0;
	_dos.total_invalid_links = 0;
	_dos.prev_sample.tv_sec = 0;
	_dos.prev_sample.tv_usec = 0;
	_dos.users_statistics_reach = 0;
	gettimeofday(&_dos.curr_sample,NULL);

	_dos.statistics_index = 0;
	for(i = 0;i<SAMPLE_TIME;i++) {
        	_dos.max_request_per_user[i] = 0;
        	_dos.max_flows_per_user[i] = 0;
		_dos.current_requests[i] = 0;
		_dos.current_flows[i] = 0;
	}

	DSAZ_AddMaxRequestPerMinuteFull(35);
	DSAZ_AddMaxFlowsPerMinuteFull(35);

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
	_dos.pathcache = PACH_Init();
	_dos.graphcache = GACH_Init();
	return;
}


void __DSAZ_DumpTimeStatistics(void){
        FILE *fd;
	register int i;

        fd = fopen("request.per.minute","w");
        if(fd == NULL) return;

	for (i=0;i<SAMPLE_TIME;i++) {
        	fprintf(fd,"%d %d %d\n",i,_dos.current_requests[i],_dos.current_flows[i]);
       	} 
        fprintf(fd,"\n");
        fclose(fd);
        return;
}

/**
 * DSAZ_Stats - Prints staticstics related to http
 */
void *DSAZ_Stats(void) {
	register int i;

	fprintf(stdout,"DDoS analyzer statistics\n");
	fprintf(stdout,"\ttotal request %ld\n",_dos.total_http_request);
	fprintf(stdout,"\ttotal bytes %ld\n",_dos.total_http_bytes);
	fprintf(stdout,"\ttotal valid links %ld\n",_dos.total_valid_links);
	fprintf(stdout,"\ttotal invalid links %ld\n",_dos.total_invalid_links);
	fprintf(stdout,"\ttotal exist links %ld\n",_dos.total_exist_links);
	fprintf(stdout,"\ttotal nonexist links %ld\n",_dos.total_nonexist_links);
	fprintf(stdout,"\ttotal exist URIs %ld\n",_dos.total_exist_uri);
	fprintf(stdout,"\ttotal nonexist URIs %ld\n",_dos.total_nonexist_uri);
	fprintf(stdout,"\ttotal statistic reach by users %ld\n",_dos.users_statistics_reach);
	if(_dos.statistics_level>0){
		PACH_Stats(_dos.pathcache);
		GACH_Stats(_dos.graphcache);
	}
	if(_dos.statistics_level>1)
		__DSAZ_DumpTimeStatistics();
	return;
}


void DSAZ_SetGraphStatisticsLevel(int level){

	_dos.statistics_level = level;	
	GACH_SetStatisticsLevel(_dos.graphcache,level);
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

	pcre_free(_dos.expr_header);
#if PCRE_MAYOR == 8 && PCRE_MINOR >= 20
	pcre_free_study(_dos.pe_header);
#else
	pcre_free(_dos.pe_header);
#endif
	GACH_Destroy(_dos.graphcache);
	PACH_Destroy(_dos.pathcache);
}

/**
 * DSAZ_AnalyzeHTTPRequest - Analyze the HTTP segment in order to evaluate if the fields exist on the http cache.
 * also tryes to find suspicious opcodes on the fields if it dont exist on the http cache.
 *
 * @param user The ST_User.
 * @param f The ST_GenericFlow to analyze.
 * @param ret the result of the analisys.
 */

void *DSAZ_AnalyzeHTTPRequest(ST_User *user,ST_GenericFlow *f , int *ret){
	ST_MemorySegment *seg = f->memory;
        ST_GraphLink *link = NULL;
        ST_GraphNode *node = NULL;
	int lret,i,process_bytes;
	int cost,idx;

#ifdef DEBUG
        LOG(POLYLOG_PRIORITY_DEBUG,
		"User(0x%x)flow(0x%x)[bytes(%d)packets(%d)]seg(0x0%x)[rsize(%d)vsize(%d)]",
		user,f,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
#endif
	lret = pcre_exec(_dos.expr_header,_dos.pe_header,(char*)seg->mem,seg->virtual_size,
		0 /* Start offset */,
		0 /* options */ ,
		_dos.ovector, OVECCOUNT);
	if (lret>1) { // The packet contains a minimum http header	
		char method[16];
		char pathhash[1024];
		char uri[MAX_URI_LENGTH];
		char *token;
		int methodlen,urilen,offset;

		offset = 0;
		idx = _dos.statistics_index;
		methodlen = _dos.ovector[3]-_dos.ovector[2];
		urilen = _dos.ovector[1]-_dos.ovector[0];
		
		if(urilen>MAX_URI_LENGTH) {
			urilen = MAX_URI_LENGTH-1;
		}
		memset(uri,0,MAX_URI_LENGTH);
		memcpy(uri,&(seg->mem[0]),urilen-4);
		uri[urilen] = '\0';

		if(f->lasturi == NULL) { // Is the first request of the flow
			link = GACH_GetBaseLink(_dos.graphcache,uri);
			if(link != NULL) { // The uri is on the graphcache
				f->lasturi = link->uri->str;
				f->lasturi_id = link->id_uri;
				_dos.total_exist_uri++;
				user->request_hits++;
			}else{
				_dos.total_nonexist_uri++;
				user->request_fails++;
			}
#ifdef DEBUG
        		LOG(POLYLOG_PRIORITY_DEBUG,
                		"User(0x%x)flow(0x%x)first uri cached %s\n",
                		user,f,link==NULL?"no":"yes");
#endif
		}else{
			node = GACH_GetGraphNode(_dos.graphcache,f->lasturi,uri);
			if(node != NULL){
				user->request_hits++;
				_dos.total_exist_links++;
				// Check if the time is on the cost range
				// TODO
	                        int value = 0;
                        	struct timeval t_cost;

                        	UT_TimevalSub(&t_cost,&(f->current_time),&(f->last_uri_seen));
                        	value = t_cost.tv_sec/1000 + (t_cost.tv_usec);
	
				if(value < node->cost){ // The speed is not correct	
					user->acumulated_cost += node->cost - value;
					_dos.total_invalid_links++;
#ifdef DEBUG
        				LOG(POLYLOG_PRIORITY_DEBUG,
                				"User(0x%x) flow(0x%x) total cost(%d)",user,f,user->acumulated_cost);
#endif
				}else{
					_dos.total_valid_links++;
				}				

                        	// Check the path of the flow on the pathcache
				memset(pathhash,0,1024);
				if(f->path != NULL){ // The flow contains a path reference
					snprintf(pathhash,1024,"%s %d",f->path->path->str,node->id_uri);
				}else{
					snprintf(pathhash,1024,"%d %d",f->lasturi_id,node->id_uri);
                        	}
                        	f->path =(ST_PathNode*)PACH_GetPath(_dos.pathcache,&pathhash);
				f->lasturi = node->uri->str;
				f->lasturi_id = node->id_uri;
				user->path_hits++;
			}else{
				_dos.total_nonexist_links++;
				user->path_fails++;
				user->request_fails++;
			}
#ifdef DEBUG
                        LOG(POLYLOG_PRIORITY_DEBUG,
                                "User(0x%x)flow(0x%x)link cached %s",
                                user,f,node==NULL?"no":"yes");
#endif
		}
		if(f->is_analyzed == FALSE) {
			_dos.current_flows[idx]++;
			user->flows_per_minute[idx]++;
		}

                f->last_uri_seen.tv_sec = f->current_time.tv_sec;
                f->last_uri_seen.tv_usec = f->current_time.tv_usec;
                user->total_request++;
                user->current_requests ++;
                user->requests_per_minute[idx]++;
		_dos.current_requests[idx]++;

		if(_dos.prev_sample.tv_sec + 60 < f->current_time.tv_sec) {
                        struct tm *t;
	
			if((user->requests_per_minute[idx] > _dos.max_request_per_user[idx])&& 
			(user->flows_per_minute[idx] > _dos.max_flows_per_user[idx])){
				/* is the first time */
				if(user->statistics_reach == 0){
					_dos.users_statistics_reach++;
                        		LOG(POLYLOG_PRIORITY_INFO,
                                		"User(0x%x)flow(0x%x) reach request(%d) per minute(%d)",
                                		user,f,_dos.max_request_per_user[idx],idx);
				}
				user->statistics_reach++;
			}
                        t = localtime(&(f->current_time.tv_sec));
                        _dos.statistics_index = ((t->tm_hour+1) * 60)+ t->tm_min;
                        _dos.prev_sample.tv_sec = f->current_time.tv_sec;
                        _dos.prev_sample.tv_usec = f->current_time.tv_usec;
		} 
		_dos.total_http_bytes += seg->virtual_size;	
		_dos.total_http_request ++;
		f->is_analyzed = TRUE;
	}else{
		(*ret) = 0;
		return ;
	}
	(*ret) = 0;
	return ;
}

/**
 * DSAZ_AnalyzeDummyHTTPRequest - Analyze the HTTP segment generated by the dummy and add to the graphcache
 *
 * @param c The ST_User.
 * @param f The ST_GenericFlow to analyze.
 */

void *DSAZ_AnalyzeDummyHTTPRequest(ST_User *user,ST_GenericFlow *f){
	ST_MemorySegment *seg = f->memory;
	ST_GraphLink *link = NULL;
	ST_GraphNode *node = NULL;
	int lret,costvalue,idx;
	int uri_id;

#ifdef DEBUG
        LOG(POLYLOG_PRIORITY_DEBUG,
                "UserAuthorized(0x%x)flow(0x%x)[bytes(%d)packets(%d)]seg(0x0%x)[rsize(%d)vsize(%d)]",
                user,f,f->total_bytes,f->total_packets,seg,seg->real_size,seg->virtual_size);
#endif
        lret = pcre_exec(_dos.expr_header,_dos.pe_header,(char*)seg->mem,seg->virtual_size,
                0 /* Start offset */,
                0 /* options */ ,
                _dos.ovector, OVECCOUNT);
        if (lret>1) { // The packet contains a minimum http header
                char uri[MAX_URI_LENGTH];
		char pathhash[1024];
                int methodlen,urilen,offset;

		idx = _dos.statistics_index;
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
		costvalue = 0;
		if(f->lasturi == NULL){
			link = GACH_AddBaseLink(_dos.graphcache,uri);
			f->lasturi = link->uri->str;
			uri_id = link->id_uri;
		}else{
			// At least is the second or more uri on the flow
			struct timeval t_cost;

			UT_TimevalSub(&t_cost,&(f->current_time),&(f->last_uri_seen));
			costvalue = t_cost.tv_sec/1000 + (t_cost.tv_usec);
			link = GACH_GetBaseLink(_dos.graphcache,f->lasturi);
			node = GACH_AddGraphNodeFromLink(_dos.graphcache,link,uri,costvalue);
			//node = GACH_GetGraphNodeFromLink(_dos.graphcache,link,uri);
			f->lasturi = node->uri->str;
			uri_id = node->id_uri;	

			// Updates the pathcache;
			// Only updates when two uris appears;
			memset(pathhash,0,1024);
			if(f->path != NULL){ // The flow contains a path reference
				snprintf(pathhash,1024,"%s %d",f->path->path->str,node->id_uri);
			}else{
				snprintf(pathhash,1024,"%d %d",link->id_uri,node->id_uri);
			}
			f->path = PACH_AddPath(_dos.pathcache,&pathhash);
		}


#ifdef DEBUG
                LOG(POLYLOG_PRIORITY_DEBUG,
                        "User(0x%x)Flow(0x%x) Updating the graph cost(%d)",user,f,costvalue);
#endif
		if(f->is_analyzed == FALSE){
			_dos.current_flows[idx]++;
			user->flows_per_minute[idx]++;
		}

		f->last_uri_seen.tv_sec = f->current_time.tv_sec;
		f->last_uri_seen.tv_usec = f->current_time.tv_usec;
		user->total_request++;
		user->current_requests ++;
		_dos.current_requests[idx]++;
		user->requests_per_minute[idx]++;	

		/* Use the current time of the flow for update the
		 * statistics of the analyzer and the user
		 */
                if(_dos.prev_sample.tv_sec + 60 < f->current_time.tv_sec) {
                        struct tm *t;

                        LOG(POLYLOG_PRIORITY_INFO,
                                "DDoS updating request/min(%d) flows/min(%d)",_dos.current_requests[idx],
				_dos.current_flows[idx]);
                        t = localtime(&(f->current_time.tv_sec));
                        _dos.statistics_index = ((t->tm_hour+1) * 60)+ t->tm_min;
                        _dos.prev_sample.tv_sec = f->current_time.tv_sec;
                        _dos.prev_sample.tv_usec = f->current_time.tv_usec;
                }

		f->is_analyzed = TRUE;
                _dos.total_http_bytes += seg->virtual_size;
                _dos.total_http_request ++;
                _dos.http_request_per_minute ++;
        }
	return;
}

/* Service functions for receive the statistics value from and outside process */

void DSAZ_AddMaxRequestPerMinuteDelta(int delta,int requests){

	if((delta>=0)&&(delta<SAMPLE_TIME))
		_dos.max_request_per_user[delta] = requests;
	return;
}

void DSAZ_AddMaxFlowsPerMinuteDelta(int delta,int flows){

        if((delta>=0)&&(delta<SAMPLE_TIME))
                _dos.max_flows_per_user[delta] = flows;
        return;
}

void DSAZ_AddMaxRequestPerMinuteFull(int requests){
	register int i;

	for (i=0;i<SAMPLE_TIME;i++)
		_dos.max_request_per_user[i] = requests;

	return;
}

void DSAZ_AddMaxFlowsPerMinuteFull(int flows){
	register int i;

	for (i=0;i<SAMPLE_TIME;i++)
		_dos.max_flows_per_user[i] = flows;

	return;
}

int32_t DSAZ_GetGraphCacheLinks(void) { return _dos.graphcache->total_links;}
int32_t DSAZ_GetGraphCacheLinkHits(void) { return _dos.graphcache->total_hits;}
int32_t DSAZ_GetGraphCacheLinkFails(void) { return _dos.graphcache->total_fails;}
int32_t DSAZ_GetPathCachePaths(void) { return _dos.pathcache->total_paths;}
int32_t DSAZ_GetPathCachePathHits(void){ return _dos.pathcache->total_hits;}
int32_t DSAZ_GetPathCachePathFails(void){ return _dos.pathcache->total_fails;}

