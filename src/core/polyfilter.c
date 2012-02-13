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
#include "httpanalyzer.h"
#include "sipanalyzer.h"

static ST_PolyFilter *_polyFilter = NULL;

/**
 * POFR_Init - Initialize the main structures of the polyfilter
 */
void POFR_Init() {
	register int i,j;
	ST_Callback *current = NULL;
	ST_Interface *interface = NULL;

	_polyFilter = (ST_PolyFilter*)g_new0(ST_PolyFilter,1);

	PODS_Init();
	_polyFilter->polyfilter_status = POLYFILTER_STATE_STOP;
	_polyFilter->is_pcap_file = FALSE;
	_polyFilter->pcapfd = 0;
	_polyFilter->pcap = NULL;
	_polyFilter->defaultport = 80;
	_polyFilter->source = g_string_new("");
	_polyFilter->bus = PODS_Connect(POLYVACCINE_FILTER_INTERFACE,(void*)_polyFilter);

	/* Only load the callbacks if dbus is running */ 
	if(_polyFilter->bus != NULL) {
		i = 0;
		interface = &ST_PublicInterfaces[0];
		while(interface->name != NULL) {
			PODS_AddInterface(interface);

			/* Loads the methods first */
			current = (ST_Callback*)&(interface->methods[0]);
			j = 0;
			while((current != NULL)&&(current->name != NULL)) {
				DEBUG0("callback(0x%x)(%d) add method '%s' on interface '%s'\n",
					current,j,current->name,interface->name);
				PODS_AddPublicCallback(current);
				j++;
				current = (ST_Callback*)&(interface->methods[j]);
			}
			j = 0;
			current = (ST_Callback*)&(interface->signals[0]);
			while((current != NULL)&&(current->name != NULL)) {
				DEBUG0("callback(0x%x) add signal '%s' on interface '%s'\n",
					current,current[j].name,interface->name);
				PODS_AddPublicCallback(current);
				j++;
				current = (ST_Callback*)&(interface->signals[j]);
			} 
			j = 0;
			current = (ST_Callback*)&(interface->properties[0]);
			while((current!=NULL)&&(current->name != NULL)){
				DEBUG0("callback(0x%x)(%d) add properties '%s' on interface '%s'\n",
					current,j,current->name,interface->name);
				PODS_AddPublicCallback(current);
				j++;
				current = (ST_Callback*)&(interface->properties[j]);
			}
			i++;
			interface = &ST_PublicInterfaces[i];
		}		
	}
	
	PKCX_Init();
	SYIN_Init();
	_polyFilter->conn = COMN_Init();
	_polyFilter->flowpool = FLPO_Init();
	_polyFilter->memorypool = MEPO_Init();
	_polyFilter->httpcache = CACH_Init();
	_polyFilter->sipcache = CACH_Init();
	_polyFilter->hosts = AUHT_Init();
	_polyFilter->forwarder = FORD_Init();
	COMN_SetFlowPool(_polyFilter->conn,_polyFilter->flowpool);
	COMN_SetMemoryPool(_polyFilter->conn,_polyFilter->memorypool);
	DEBUG0("Initialized engine....\n");
	DEBUG0("connetion manager (0x%x)\n",_polyFilter->conn);
	DEBUG0("flowpool (0x%x)\n",_polyFilter->flowpool);
	DEBUG0("memorypool (0x%x)\n",_polyFilter->memorypool);
	DEBUG0("httpcache (0x%x)\n",_polyFilter->httpcache);
	DEBUG0("sipcache (0x%x)\n",_polyFilter->sipcache);

	// Plugin the analyzers
	FORD_AddAnalyzer(_polyFilter->forwarder,_polyFilter->httpcache,
		"HTTP Analyzer",IPPROTO_TCP,80,
		(void*)HTAZ_Init,
		(void*)HTAZ_Destroy,
		(void*)HTAZ_Stats,	
		(void*)HTAZ_AnalyzeHTTPRequest,
		(void*)HTAZ_AnalyzeDummyHTTPRequest);

	FORD_AddAnalyzer(_polyFilter->forwarder,_polyFilter->sipcache,
		"SIP Analyzer",IPPROTO_UDP,16402,
		(void*)SPAZ_Init,
		(void*)SPAZ_Destroy,
		(void*)SPAZ_Stats,	
		(void*)SPAZ_AnalyzeSIPRequest,
		(void*)SPAZ_AnalyzeDummySIPRequest);
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
 * POFR_SetSourcePort - Sets the source port of the webserver 
 *
 * @param port the new port to analyze 
 */
void POFR_SetSourcePort(int port){
        _polyFilter->defaultport = port;
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
	
	DEBUG0("Trying to start the engine, status=%s\n",polyfilter_states_str[_polyFilter->polyfilter_status]);
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
                DEBUG0("Starting engine\n");
	}
}

/**
 * POFR_Stop - Stops the polyfilter
 */
void POFR_Stop() {
	
	DEBUG0("Trying to stop the engine, status=%s\n",polyfilter_states_str[_polyFilter->polyfilter_status]);
	if(_polyFilter->polyfilter_status == POLYFILTER_STATE_RUNNING) {
		// printf("pcap = 0x%x\n",_polyFilter->pcap);
		//if(_polyFilter->pcap != NULL);
		//	pcap_close(_polyFilter->pcap);
		_polyFilter->pcap = NULL;
		_polyFilter->pcapfd = -1;
		_polyFilter->polyfilter_status = POLYFILTER_STATE_STOP;
                DEBUG0("Stoping engine\n");
	}
}

/**
 * POFR_StopAndExit - Stops and exit the polyfilter
 */
void POFR_StopAndExit() {
	POFR_Stop();
	COMN_ReleaseFlows(_polyFilter->conn);
	PKDE_PrintfStats();
        MEPO_Stats(_polyFilter->memorypool);
        FLPO_Stats(_polyFilter->flowpool);
        CACH_Stats(_polyFilter->httpcache);
        CACH_Stats(_polyFilter->sipcache);
	FORD_Stats(_polyFilter->forwarder);
	POFR_Destroy();
	exit(0);
}

/**
 * POFR_Destroy - Destroy the ST_PolyFilter type
 */
void POFR_Destroy() {
	PODS_Destroy();
	g_string_free(_polyFilter->source,1);
	FLPO_Destroy(_polyFilter->flowpool);
	MEPO_Destroy(_polyFilter->memorypool);
	COMN_Destroy(_polyFilter->conn);
	CACH_Destroy(_polyFilter->httpcache);
	CACH_Destroy(_polyFilter->sipcache);
	AUHT_Destroy(_polyFilter->hosts);
	FORD_Destroy(_polyFilter->forwarder);
	PKCX_Destroy();
	g_free(_polyFilter);
	return;
}

/**
 * POFR_Stats - Show statistics related to the ST_PolyFilter 
 */

void POFR_Stats() {
	
	MEPO_Stats(_polyFilter->memorypool);
	FLPO_Stats(_polyFilter->flowpool);
	CACH_Stats(_polyFilter->httpcache);
	CACH_Stats(_polyFilter->sipcache);
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
	if(_polyFilter->httpcache) {
		if (type == CACHE_HEADER )
			CACH_AddHeaderToCache(_polyFilter->httpcache,value,NODE_TYPE_STATIC);
		else if (type == CACHE_PARAMETER) 
			CACH_AddParameterToCache(_polyFilter->httpcache,value,NODE_TYPE_STATIC);
	}
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
                DEBUG0("Cannot send suspicious segment over dbus, no connection available\n");
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
                DEBUG0("Cannot send vereridct segment over dbus, no connection available\n");
		return;
	}
	PODS_SendVerifiedSegment(_polyFilter->bus,
		POLYVACCINE_PROTECTOR_OBJECT,
		POLYVACCINE_PROTECTOR_INTERFACE,
		"Veredict",
		seq,hash,veredict);
	return;
}

/**
 * POFR_SetLearningMode - Authorize all the host. 
 *
 */
void POFR_SetLearningMode() {
	AUTH_SetAuthorizedAll(_polyFilter->hosts);
	return;
}

/**
 * POFR_Run - Main loop, for manage the packets and the dbus-messages. 
 *
 */
void POFR_Run() {
	ST_GenericFlow *flow;
	ST_GenericAnalyzer *ga;
	ST_MemorySegment *memseg;
	ST_TrustOffsets *trust_offsets = NULL;
	register int i;
	int nfds,usepcap,ret,update_timers;
        DBusWatch *local_watches[MAX_WATCHES];
	struct timeval currenttime;
	struct pcap_pkthdr *header;
	unsigned char *pkt_data;
	struct pollfd local_fds[MAX_WATCHES];

        fprintf(stdout,"%s running on %s machine %s\n",POLYVACCINE_FILTER_ENGINE_NAME,
		SYIN_GetOSName(),SYIN_GetMachineName());
        fprintf(stdout,"\tversion %s\n",SYIN_GetVersionName());
	if(_polyFilter->hosts->all)
		fprintf(stdout,"\tLearning mode active\n");
	FORD_InitAnalyzers(_polyFilter->forwarder);

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
                                        break;
                                }
			}else {
				if(PKDE_Decode(header,pkt_data) == TRUE){
					ga = FORD_GetAnalyzer(_polyFilter->forwarder,
						PKCX_GetIPProtocol(),
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
										
								COMN_InsertConnection(_polyFilter->conn,flow,&hash);
								DEBUG0("New Connection on Pool [%s:%d:%d:%s:%d]\n",
									PKCX_GetSrcAddrDotNotation(),
									PKCX_GetSrcPort(),
									protocol, 
									PKCX_GetDstAddrDotNotation(),
									PKCX_GetDstPort());
								/* Check if the flow allready have a ST_MemorySegment attached */
								memseg = MEPO_GetMemorySegment(_polyFilter->memorypool);
								GEFW_SetMemorySegment(flow,memseg);
								GEFW_SetArriveTime(flow,&currenttime);	
							}else{
								//WARNING("No flow pool allocated\n");
								continue;
							}
						}
						// TODO problem with retransmisions with post
						// check test/pcapfiles directory
						segment_size = PKCX_GetPayloadLength();
						flow->total_packets++;
						flow->total_bytes += segment_size;
						if(segment_size > 0) {
							MESG_AppendPayloadNew(flow->memory,PKCX_GetPayload(),segment_size);
							//  TODO check the upstream datagrams, we dont need to analyze donwstream
							// try to find something efficient
							if((protocol == IPPROTO_UDP)||((protocol == IPPROTO_TCP)&&(PKCX_IsTCPPush() == 1))) {
								if(AUHT_IsAuthorized(_polyFilter->hosts,PKCX_GetSrcAddrDotNotation())) {
									ga->learn(ga->cache,flow);	
								}else{
									//ret = HTAZ_AnalyzeHTTPRequest(_polyFilter->httpcache,flow);
									ga->analyze(ga->cache,flow,&ret);
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
								flow->memory->virtual_size = 0;
							}	
						}
						GEFW_UpdateTime(flow,&currenttime);
						}	
					} // end of decode;
				}
                }
		/* updates the flow time every 10 seconds aproximately
		 * in order to avoid sorting without non-sense the flow list timer
		 */
		if((currenttime.tv_sec % 10) == 0){
			if(update_timers) {
				COMN_UpdateTimers(_polyFilter->conn,&currenttime);
				update_timers = 0;
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
	int32_t value = 0;

	if((_polyFilter)&&(_polyFilter->httpcache))
		value = _polyFilter->httpcache->header_hits;
	return value;
}
	
int32_t POFR_GetHTTPHeaderCacheFails() {
	int32_t value = 0;

	if((_polyFilter)&&(_polyFilter->httpcache))
		value = _polyFilter->httpcache->header_fails;
	return value;
}

int32_t POFR_GetHTTPParameterCacheHits(){
        int32_t value = 0;

        if((_polyFilter)&&(_polyFilter->httpcache))
                value = _polyFilter->httpcache->parameter_hits;
        return value;
}

int32_t POFR_GetHTTPParameterCacheFails() {
        int32_t value = 0;

        if((_polyFilter)&&(_polyFilter->httpcache))
                value = _polyFilter->httpcache->parameter_fails;
        return value;
}

