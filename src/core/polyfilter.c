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

#include "polyfilter.h"
#include "polydbus.h"
#include "callbacks.h"
#include "genericflow.h"
#include "connection.h"
#include "tcpanalyzer.h"
#include "httpanalyzer.h"
#include "sipanalyzer.h"
#include "dosanalyzer.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_FILTER_INTERFACE
#include "log.h"

static ST_PolyFilter *_polyFilter = NULL;

static int timeout_checker = 180;

/**
 * POFR_Init - Initialize the main structures of the polyfilter
 */
void POFR_Init() {
	register int i,j;
	ST_Callback *current = NULL;
	ST_Interface *interface = NULL;

	_polyFilter = (ST_PolyFilter*)g_new0(ST_PolyFilter,1);

	POLG_Init();
	PODS_Init();
	_polyFilter->polyfilter_status = POLYFILTER_STATE_STOP;
	_polyFilter->mode = POLYFILTER_MODE_NONCACHE;
	_polyFilter->is_pcap_file = FALSE;
	_polyFilter->when_pcap_done_exit = FALSE;
	_polyFilter->pcapfd = 0;
	_polyFilter->pcap = NULL;
	_polyFilter->source = g_string_new("");
	_polyFilter->bus = PODS_Connect(POLYVACCINE_FILTER_INTERFACE,(void*)_polyFilter);

	/* Only load the callbacks if dbus is running */ 
	if(_polyFilter->bus != NULL) {
		i = 0;
		interface = &ST_PublicInterfaces[0];
		while(interface->name != NULL) {
			/* Loads the methods first */
			current = (ST_Callback*)&(interface->methods[0]);
			j = 0;
			while((current != NULL)&&(current->name != NULL)) {
				PODS_AddPublicMethod(interface,current);
				j++;
				current = (ST_Callback*)&(interface->methods[j]);
			}
			j = 0;
			current = (ST_Callback*)&(interface->signals[0]);
			while((current != NULL)&&(current->name != NULL)) {
				PODS_AddPublicMethod(interface,current);
				j++;
				current = (ST_Callback*)&(interface->signals[j]);
			} 
			j = 0;
			current = (ST_Callback*)&(interface->properties[0]);
			while((current!=NULL)&&(current->name != NULL)){
				PODS_AddPublicProperty(interface,current);
				j++;
				current = (ST_Callback*)&(interface->properties[j]);
			}
			i++;
			interface = &ST_PublicInterfaces[i];
		}		
	}
	
	PKCX_Init();
	SYIN_Init();
	TCAZ_Init();

	_polyFilter->conn = COMN_Init();
	_polyFilter->users = USTA_Init();
	_polyFilter->flowpool = FLPO_Init();
	_polyFilter->memorypool = MEPO_Init();
	_polyFilter->userpool = USPO_Init();
	_polyFilter->hosts = AUHT_Init();
	_polyFilter->forwarder = FORD_Init();

	COMN_SetFlowPool(_polyFilter->conn,_polyFilter->flowpool);
	COMN_SetMemoryPool(_polyFilter->conn,_polyFilter->memorypool);
	USTA_SetUserPool(_polyFilter->users,_polyFilter->userpool);
#ifdef DEBUG
	LOG(POLYLOG_PRIORITY_DEBUG,"Initialized engine....");
	LOG(POLYLOG_PRIORITY_DEBUG,"connection manager (0x%x)",_polyFilter->conn);
	LOG(POLYLOG_PRIORITY_DEBUG,"user manager (0x%x)",_polyFilter->users);
	LOG(POLYLOG_PRIORITY_DEBUG,"flowpool (0x%x)",_polyFilter->flowpool);
	LOG(POLYLOG_PRIORITY_DEBUG,"memorypool (0x%x)",_polyFilter->memorypool);
	LOG(POLYLOG_PRIORITY_DEBUG,"userpool (0x%x)",_polyFilter->userpool);
#endif
	// Plugin the analyzers

        FORD_AddAnalyzer(_polyFilter->forwarder,
                "ddos",IPPROTO_TCP,80,
                (void*)DSAZ_Init,
                (void*)DSAZ_Destroy,
                (void*)DSAZ_Stats,
                (void*)DSAZ_AnalyzeHTTPRequest,
                (void*)DSAZ_AnalyzeDummyHTTPRequest);

	FORD_AddAnalyzer(_polyFilter->forwarder,
		"http",IPPROTO_TCP,8080,
		(void*)HTAZ_Init,
		(void*)HTAZ_Destroy,
		(void*)HTAZ_Stats,	
		(void*)HTAZ_AnalyzeHTTPRequest,
		(void*)HTAZ_AnalyzeDummyHTTPRequest);

	FORD_AddAnalyzer(_polyFilter->forwarder,
		"sip",IPPROTO_UDP,5060,
		(void*)SPAZ_Init,
		(void*)SPAZ_Destroy,
		(void*)SPAZ_Stats,	
		(void*)SPAZ_AnalyzeSIPRequest,
		(void*)SPAZ_AnalyzeDummySIPRequest);

	FORD_InitAnalyzers(_polyFilter->forwarder);
	return;
}

void POFR_ShowGraphCacheLinksLevel(int value){

	// TODO
	//GACH_ShowGraphCacheLinks(_polyFilter->graphcache,value);
	return;
}

void POFR_EnableAnalyzers(char *analyzers){

	// Tells the forwarder to enable the analyzers
	// TODO
	FORD_EnableAnalyzerByName(_polyFilter->forwarder,analyzers);
	return;
}

void POFR_SetStatisticsLevel(int level){
	USTA_SetStatisticsLevel(_polyFilter->users,level);
	return;
}

/**
 * POFR_ShowUnknownHTTP - Shows the unknown http traffic. 
 *
 * @param value
 */

void POFR_ShowUnknownHTTP(int value){
	HTAZ_ShowUnknownHTTP(value);
	return;
}

/**
 * POFR_SetSource - Sets the source of the network packets
 *
 * @param source a pcap file or a ethernet device
 */
void POFR_SetSource(char *source){
	g_string_printf(_polyFilter->source,"%s",source);
}

/**
 * POFR_SetHTTPSourcePort - Sets the source port of the webserver 
 *
 * @param port the new port to analyze 
 */
void POFR_SetHTTPSourcePort(int port){

	FORD_ChangePortToAnalyzer(_polyFilter->forwarder,"http",port);
	return;
}

/**
 * POFR_SetSIPSourcePort - Sets the source port of the sipserver
 *
 * @param port the new port to analyze
 */
void POFR_SetSIPSourcePort(int port){
	FORD_ChangePortToAnalyzer(_polyFilter->forwarder,"sip",port);
        return;
}


/**
 * POFR_SetForceAnalyzeHTTPPostData - Force to send to the pvde the post request with data. 
 *
 * @param value TRUE of FALSE 
 */

void POFR_SetForceAnalyzeHTTPPostData(int value){
	HTAZ_SetForceAnalyzeHTTPPostData(value);
	return;	
}


/**
 * POFR_Start - Starts the polyfilter 
 */

void POFR_Start() {

	LOG(POLYLOG_PRIORITY_INFO,
		"Trying to start the engine, status=%s, mode=%s",polyfilter_states_str[_polyFilter->polyfilter_status],
		polyfilter_modes_str[_polyFilter->mode]);	
	if(_polyFilter->polyfilter_status == POLYFILTER_STATE_STOP) {
		char errbuf[PCAP_ERRBUF_SIZE];

		_polyFilter->is_pcap_file = FALSE;
		_polyFilter->pcap = pcap_open_live(_polyFilter->source->str, PCAP_ERRBUF_SIZE, 1, -1, errbuf);
		if(_polyFilter->pcap == NULL) {
			_polyFilter->pcap = pcap_open_offline(_polyFilter->source->str,errbuf);
			if(_polyFilter->pcap == NULL) {
				fprintf(stderr, "Could not open device/file \"%s\": %s\n", _polyFilter->source->str, errbuf);
				return;
			}
			_polyFilter->is_pcap_file = TRUE;
		}

		if(pcap_setnonblock(_polyFilter->pcap, 1, errbuf) == 1){
			fprintf(stderr, "Could not set device \"%s\" to non-blocking: %s\n", _polyFilter->source->str,errbuf);
			pcap_close(_polyFilter->pcap);
                	_polyFilter->pcap = NULL;
                	return;
        	}
		_polyFilter->pcapfd = pcap_get_selectable_fd(_polyFilter->pcap);
		_polyFilter->polyfilter_status = POLYFILTER_STATE_RUNNING;
                LOG(POLYLOG_PRIORITY_INFO,"Starting engine",NULL);
	}
}

/**
 * POFR_Stop - Stops the polyfilter
 */
void POFR_Stop() {
	
	LOG(POLYLOG_PRIORITY_INFO,
		"Trying to stop the engine, status=%s, mode=%s",polyfilter_states_str[_polyFilter->polyfilter_status],	
		polyfilter_modes_str[_polyFilter->mode]);	
	if(_polyFilter->polyfilter_status == POLYFILTER_STATE_RUNNING) {
		// printf("pcap = 0x%x\n",_polyFilter->pcap);
		//if(_polyFilter->pcap != NULL);
		pcap_close(_polyFilter->pcap);
		_polyFilter->pcap = NULL;
		_polyFilter->pcapfd = -1;
		_polyFilter->polyfilter_status = POLYFILTER_STATE_STOP;
                LOG(POLYLOG_PRIORITY_INFO,"Stoping engine",NULL);
	}
}

/**
 * POFR_StopAndExit - Stops and exit the polyfilter
 */
void POFR_StopAndExit() {
	POFR_Stop();
	POFR_Destroy();
	exit(0);
}

/**
 * POFR_Destroy - Destroy the ST_PolyFilter type
 */
void POFR_Destroy() {
	PODS_Destroy();
	// TODO: the flows stored on the connection manager
	// should be returned to the pools.
	// COMN_ReleaseFlows(_polyFilter->conn);
	COMN_ReleaseFlows(_polyFilter->conn);

	// TODO 
	USTA_ReleaseUsers(_polyFilter->users);

	g_string_free(_polyFilter->source,TRUE);
	FLPO_Destroy(_polyFilter->flowpool);
	MEPO_Destroy(_polyFilter->memorypool);
	USPO_Destroy(_polyFilter->userpool);
	COMN_Destroy(_polyFilter->conn);
	USTA_Destroy(_polyFilter->users);
	AUHT_Destroy(_polyFilter->hosts);

	// TODO: verify if the forwarder destroy the analyzers
	FORD_Destroy(_polyFilter->forwarder);
	PKCX_Destroy();
	POLG_Destroy();
	g_free(_polyFilter);
	_polyFilter = NULL;
	return;
}

/**
 * POFR_Stats - Show statistics related to the ST_PolyFilter 
 */

void POFR_Stats() {
        PKDE_PrintfStats();
        TCAZ_Stats();
        USPO_Stats(_polyFilter->userpool);
        MEPO_Stats(_polyFilter->memorypool);
        FLPO_Stats(_polyFilter->flowpool);
        COMN_Stats(_polyFilter->conn);
        USTA_Stats(_polyFilter->users);
        FORD_Stats(_polyFilter->forwarder);
	return;
}

/**
 * POFR_AddToHTTPCache - Show statistics related to the ST_PolyFilter
 *
 * @param type the cache type (NODE_TYPE_STATIC,NODE_TYPE_DYNAMIC)
 * @param value the parameter
 * 
 */
void POFR_AddToHTTPCache(int type,char *value){

	if (type == CACHE_HEADER )
		HTAZ_AddHeaderToCache(value,NODE_TYPE_STATIC);
	else if (type == CACHE_PARAMETER) 
		HTAZ_AddParameterToCache(value,NODE_TYPE_STATIC);
}

/**
 * POFR_SendSuspiciousSegmentToExecute - Sends a suspicious segment to the detection engine. 
 *
 * @param seg the ST_MemorySegment.
 * @param off the trusted offset list.
 * @param hash
 * @param seq
 * 
 */
void POFR_SendSuspiciousSegmentToExecute(ST_MemorySegment *seg,ST_TrustOffsets *t_off,unsigned long hash, uint32_t seq) {

	if(_polyFilter->bus == NULL) {
		LOG(POLYLOG_PRIORITY_ALERT,
			"Cannot send suspicious segment over dbus, no connection available");
		return;
	}
	PODS_SendSuspiciousSegment(_polyFilter->bus,
		POLYVACCINE_DETECTION_OBJECT,
		POLYVACCINE_DETECTION_INTERFACE,
		"Analyze",
		seg->mem,
		seg->virtual_size,
		TROF_GetStartOffsets(t_off),
		TROF_GetEndOffsets(t_off),
		hash,seq);
	return;
}

/**
 * POFR_SendVerifiedSegment - Sends a verified segment to the protection engine. 
 *
 * @param hash
 * @param seq
 * @param veredict 
 * 
 */
void POFR_SendVerifiedSegment(unsigned long hash, u_int32_t seq,int veredict) {
	
	if(_polyFilter->bus == NULL) {
		LOG(POLYLOG_PRIORITY_ALERT,
			"Cannot send vereridct segment over dbus, no connection available");
		return;
	}
	PODS_SendVerifiedSegment(_polyFilter->bus,
		POLYVACCINE_PROTECTOR_OBJECT,
		POLYVACCINE_PROTECTOR_INTERFACE,
		"Veredict",
		seq,hash,veredict);
	return;
}

void POFR_SetExitOnPcap(int value){
	_polyFilter->when_pcap_done_exit = value;
}

/**
 * POFR_SetLearningMode - Authorize all the host. 
 *
 */
void POFR_SetLearningMode() {
	AUTH_SetAuthorizedAll(_polyFilter->hosts);
	return;
}

void __POFR_UpdateStatus() {
        if(_polyFilter->hosts->all) {
                // All the hosts are considered as trusted
                _polyFilter->mode = POLYFILTER_MODE_FULLCACHE;
        }else{
                if(AUHT_GetNumberOfAuthorizedHosts(_polyFilter->hosts)>0)
                        _polyFilter->mode = POLYFILTER_MODE_SOMECACHE;
                else
                        _polyFilter->mode = POLYFILTER_MODE_NONCACHE;
        }
        return;
}

/**
 * POFR_AddTrustedUser - Adds a IP user so the caches will be update on real-time 
 *
 * @param ip
 */
void POFR_AddTrustedUser(char *ip) {

	AUHT_AddHost(_polyFilter->hosts,ip);
	__POFR_UpdateStatus();
	return;
}

/**
 * POFR_RemoveTrustedUser - Destroy a IP user from the authorized list 
 *
 * @param ip
 */
void POFR_RemoveTrustedUser(char *ip) {

        AUHT_RemoveHost(_polyFilter->hosts,ip);
	__POFR_UpdateStatus();
        return;
}


void POFR_SetInitialFlowsOnPool(int value){
	int pflows;
	
	if(value>0){
		pflows = FLPO_GetNumberFlows(_polyFilter->flowpool);
		if(value > pflows) { // We should increment the flow pool
			FLPO_IncrementFlowPool(_polyFilter->flowpool,value - pflows);
		}else{
			if(value < pflows) {
				FLPO_DecrementFlowPool(_polyFilter->flowpool,pflows - value);
			}
		}
	}
	return;
}

void POFR_GetTimeOfDay(struct timeval *t,struct pcap_pkthdr *hdr){

	if(_polyFilter->is_pcap_file == TRUE){
		t->tv_sec = hdr->ts.tv_sec;
		t->tv_usec = hdr->ts.tv_usec;
	}else{
                gettimeofday(t,NULL);
	}
} 

/**
 * POFR_Run - Main loop, for manage the packets and the dbus-messages. 
 *
 */
void POFR_Run() {
	ST_GenericFlow *flow = NULL;
	ST_GenericAnalyzer *ga = NULL;
	ST_MemorySegment *memseg = NULL;
	ST_TrustOffsets *trust_offsets = NULL;
	ST_User *user = NULL;
	register int i;
	int nfds,usepcap,ret,update_timers;
        DBusWatch *local_watches[MAX_WATCHES];
	struct timeval currenttime;
	struct timeval lasttimeouttime;
	struct pcap_pkthdr *header;
	unsigned char *pkt_data;
	struct pollfd local_fds[MAX_WATCHES];

        fprintf(stdout,"%s running on %s machine %s\n",POLYVACCINE_FILTER_ENGINE_NAME,
		SYIN_GetOSName(),SYIN_GetMachineName());
        fprintf(stdout,"\tversion %s\n",SYIN_GetVersionName());

	__POFR_UpdateStatus();
	
	fprintf(stdout,"\tActive mode '%s'\n",polyfilter_modes_str[_polyFilter->mode]);
	FORD_ShowAnalyzers(_polyFilter->forwarder);

        gettimeofday(&lasttimeouttime,NULL);
	update_timers = 1;
	while (TRUE) {
                nfds = 0;
                usepcap = 0;
                gettimeofday(&currenttime,NULL);

                for (i = 0; i < PODS_GetTotalActiveDescriptors(); i++) {
                        if (PODS_GetDescriptorByIndex(i) == 0 ||
                            !dbus_watch_get_enabled(PODS_GetWatchByIndex(i))) {
                                continue;
                        }

                        local_fds[nfds].fd = PODS_GetDescriptorByIndex(i); 
                        local_fds[nfds].events = PODS_GetEventsByIndex(i);
                        local_fds[nfds].revents = 0;
                        local_watches[nfds] = PODS_GetWatchByIndex(i);
                        nfds++;
                }

                if(_polyFilter->polyfilter_status == POLYFILTER_STATE_RUNNING) {
                        local_fds[nfds].fd = _polyFilter->pcapfd;
                        local_fds[nfds].events = POLLIN|POLLPRI|POLLHUP;
                        local_fds[nfds].revents = 0;
                        usepcap = 1;
                }

                ret = poll(local_fds,nfds+usepcap,-1);
                if (ret <0){
                        perror("poll");
                        break;
                }

                if((local_fds[nfds].revents & POLLIN)&&(_polyFilter->polyfilter_status == POLYFILTER_STATE_RUNNING)){
                        ret = pcap_next_ex(_polyFilter->pcap,(struct pcap_pkthdr*)&header,(unsigned char*)&pkt_data);
			if(ret < 0) {
                                POFR_Stop();
                                usepcap = 0;
                                if(_polyFilter->is_pcap_file == TRUE){
					fprintf(stdout,"Source analyze done.\n");
					if(_polyFilter->when_pcap_done_exit == TRUE)
                                        	break;
                                }
			}else {
				POFR_GetTimeOfDay(&currenttime,header);
				if(PKDE_Decode(header,pkt_data) == TRUE){
					ga = FORD_GetAnalyzer(_polyFilter->forwarder,
						PKCX_GetIPProtocol(),
						PKCX_GetSrcPort(),
						PKCX_GetDstPort());
					if(ga != NULL) { 
						int segment_size;
						int protocol = PKCX_GetIPProtocol();
						uint32_t seq = PKCX_GetSequenceNumber();
						unsigned long hash;
						/* Find a ST_GenericFlow object in order to evaluate it */
						flow = COMN_FindConnection(_polyFilter->conn,
							PKCX_GetIPSrcAddr(),
							PKCX_GetSrcPort(),
							protocol,
							PKCX_GetIPDstAddr(),
							PKCX_GetDstPort(),
							&hash);	
							
						if (flow == NULL) {
							flow = FLPO_GetFlow(_polyFilter->flowpool);
							if (flow != NULL) {
								GEFW_SetFlowId(flow,
									PKCX_GetIPSrcAddr(),
									PKCX_GetSrcPort(),
									protocol,
									PKCX_GetIPDstAddr(),
									PKCX_GetDstPort());	
										
								flow->direction = ga->direction;
								COMN_InsertConnection(_polyFilter->conn,flow,&hash);
#ifdef DEBUG
								LOG(POLYLOG_PRIORITY_DEBUG,
									"New connection on Pool [%s:%d:%d:%s:%d] flow(0x%x)",
									PKCX_GetSrcAddrDotNotation(),
									PKCX_GetSrcPort(),
									protocol, 
									PKCX_GetDstAddrDotNotation(),
									PKCX_GetDstPort(),
									flow);
#endif 
								/* Check if the flow allready have a ST_MemorySegment attached */
								memseg = MEPO_GetMemorySegment(_polyFilter->memorypool);
								GEFW_SetMemorySegment(flow,memseg);
								GEFW_SetArriveTime(flow,&currenttime);	
							}else{
								//WARNING("No flow pool allocated\n");
								continue;
							}
						}
						// Update the direction of the flow
						flow->direction = ga->direction;
				
						if(protocol == IPPROTO_TCP){
							// Update the tcp flow
							TCAZ_Analyze(flow);
							// check if the flow have end
							if(flow->tcp_state_curr == POLY_TCPS_CLOSED) {
								// The flow should be returned to the cache
#ifdef DEBUG
								LOG(POLYLOG_PRIORITY_DEBUG,
									"Release connection to Pool [%s:%d:%d:%s:%d] flow(0x%x)",
                                                                        PKCX_GetSrcAddrDotNotation(),
                                                                        PKCX_GetSrcPort(),
                                                                        protocol,
                                                                        PKCX_GetDstAddrDotNotation(),
                                                                        PKCX_GetDstPort(),
                                                                        flow);
#endif 
								COMN_ReleaseConnection(_polyFilter->conn,flow);
								continue;
							}
						}
						// TODO problem with retransmisions with post
						// check test/pcapfiles directory
						segment_size = PKCX_GetPayloadLength();
						flow->total_packets++;
						flow->total_bytes += segment_size;
						if((segment_size > 0)&&(flow->direction == FLOW_FORW)) {
							// Retrieve the corresponding user struct
							user = USTA_FindUser(_polyFilter->users,PKCX_GetIPSrcAddr());
							if(user == NULL){
								user = USPO_GetUser(_polyFilter->userpool);
								if(user != NULL){
									user->ip = PKCX_GetIPSrcAddr();
									user->arrive_time.tv_sec = currenttime.tv_sec;
									user->arrive_time.tv_usec = currenttime.tv_usec;
									USTA_InsertUser(_polyFilter->users,user);
								}else{
									WARNING("No user pool allocated\n");
									continue;
								}
							}

							user->current_time.tv_sec = currenttime.tv_sec;
							user->current_time.tv_usec = currenttime.tv_usec;

							MESG_AppendPayloadNew(flow->memory,PKCX_GetPayload(),segment_size);
							//  TODO check the upstream datagrams, we dont need to analyze donwstream
							// try to find something efficient
							if((protocol == IPPROTO_UDP)||((protocol == IPPROTO_TCP)&&(PKCX_IsTCPPush() == 1))) {
								if(AUHT_IsAuthorized(_polyFilter->hosts,PKCX_GetSrcAddrDotNotation())) {
									ga->learn(user,flow);	
								}else{
									ga->analyze(user,flow,&ret);
									if(ret) { // the segment is suspicious
										trust_offsets =  HTAZ_GetTrustOffsets();
										POFR_SendSuspiciousSegmentToExecute(flow->memory,
											trust_offsets,		
											hash,seq);
									}else{ // the segment is correct 
										POFR_SendVerifiedSegment(hash,
											seq,1);
									}
								}
								/* Reset the virtual memory of the segment */
								//MESG_Reset(flow->memory);
								flow->memory->virtual_size = 0;
							}	
						}
						GEFW_UpdateTime(flow,&currenttime);
						}	
					} // end of decode;
				}
                }
		/* updates the flow time every 180 seconds aproximately
		 * in order to avoid sorting without non-sense the flow list timer
		 * Notice that if not dbus messages available on the buss the 
		 * timers never execute.
		 */
		if(lasttimeouttime.tv_sec + timeout_checker < currenttime.tv_sec) {
			if(update_timers) {
				COMN_UpdateTimers(_polyFilter->conn,&currenttime);
				update_timers = 0;
				lasttimeouttime.tv_sec = currenttime.tv_sec;
				lasttimeouttime.tv_usec = currenttime.tv_usec;
			}
		}else 
			update_timers = 1;
               	for (i = 0; i < nfds; i++) {
                        if (local_fds[i].revents) {
                                PODS_Handler(_polyFilter->bus,local_fds[i].revents, local_watches[i]);
                        }
                }
        }
        return;
}


int32_t POFR_GetHTTPHeaderCacheHits(){

	return HTAZ_GetHeaderHits();
}
	
int32_t POFR_GetHTTPHeaderCacheFails() {
	
	return HTAZ_GetHeaderFails();
}

int32_t POFR_GetHTTPParameterCacheHits(){

        return HTAZ_GetParameterHits();
}

int32_t POFR_GetHTTPParameterCacheFails() {

        return HTAZ_GetParameterFails(); 
}


