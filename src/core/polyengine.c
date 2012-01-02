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

#include "polyengine.h"
#include "polydbus.h"
#include "callbacks.h"
#include "httpflow.h"
#include "connection.h"

static ST_PolyEngine *_polyEngine = NULL;

/**
 * POEG_Init - Initialize the main structures of the polyengine
 */
void POEG_Init() {
	ST_Callback *current = NULL;
	ST_Interface *interface = NULL;
	register int i,j;

	_polyEngine = (ST_PolyEngine*)g_new0(ST_PolyEngine,1);

	PODS_Init();
	_polyEngine->polyengine_status = POLYENGINE_STATE_STOP;
	_polyEngine->is_pcap_file = FALSE;
	_polyEngine->pcapfd = 0;
	_polyEngine->pcap = NULL;
	_polyEngine->defaultport = 80;
	_polyEngine->source = g_string_new("");
	_polyEngine->bus = PODS_Connect(POLYVACCINE_AGENT_INTERFACE,(void*)_polyEngine);

        for ( i = 0; i<MAX_PUBLIC_INTERFACES;i++) {
		PODS_AddInterface(&ST_PublicInterfaces[i]);
		
                interface = &ST_PublicInterfaces[i];
		/* Loads the methods first */
		current = &interface->methods[0];
		for (j = 0;j<interface->total_methods;j++){
			current = &interface->methods[j];
			DEBUG0("add method '%s' on interface '%s'\n",current[j].name,interface->name);
			PODS_AddPublicCallback(current);
		}
		current = &interface->properties[0];
		for (j = 0;j<interface->total_properties;j++){
			current = &interface->properties[j];
			DEBUG0("add properties '%s' on interface '%s'\n",current[j].name,interface->name);
			PODS_AddPublicCallback(current);
		}
	}		

	PKCX_Init();
	HTAZ_Init();
	SYIN_Init();
	_polyEngine->conn = COMN_Init();
	_polyEngine->flowpool = FLPO_Init();
	_polyEngine->memorypool = MEPO_Init();
	_polyEngine->httpcache = HTCC_Init();
	_polyEngine->hosts = AUHT_Init();
	COMN_SetFlowPool(_polyEngine->conn,_polyEngine->flowpool);
	COMN_SetMemoryPool(_polyEngine->conn,_polyEngine->memorypool);
	DEBUG0("Initialized engine....\n");
	DEBUG0("connetion manager (0x%x)\n",_polyEngine->conn);
	DEBUG0("flowpool (0x%x)\n",_polyEngine->flowpool);
	DEBUG0("memorypool (0x%x)\n",_polyEngine->memorypool);
	DEBUG0("httpcache (0x%x)\n",_polyEngine->httpcache);
	return;
}

/**
 * POEG_SetSource - Sets the source of the network packets
 *
 * @param source a pcap file or a ethernet device
 */
void POEG_SetSource(char *source){
	g_string_printf(_polyEngine->source,"%s",source);
}

/**
 * POEG_SetSourcePort - Sets the source port of the webserver 
 *
 * @param port the new port to analyze 
 */
void POEG_SetSourcePort(int port){
        _polyEngine->defaultport = port;
}

/**
 * POEG_Start - Starts the polyengine 
 */
void POEG_Start() {
	
	DEBUG0("Trying to start the engine, status=%s\n",polyengine_states_str[_polyEngine->polyengine_status]);
	if(_polyEngine->polyengine_status == POLYENGINE_STATE_STOP) {
		char errbuf[PCAP_ERRBUF_SIZE];

		_polyEngine->is_pcap_file = FALSE;
		_polyEngine->pcap = pcap_open_live(_polyEngine->source->str, PCAP_ERRBUF_SIZE, 1, -1, errbuf);
		if(_polyEngine->pcap == NULL) {
			_polyEngine->pcap = pcap_open_offline(_polyEngine->source->str,errbuf);
			if(_polyEngine->pcap == NULL) {
				fprintf(stderr, "Could not open device/file \"%s\": %s\n", _polyEngine->source->str, errbuf);
				return;
			}
			_polyEngine->is_pcap_file = TRUE;
		}

		if(pcap_setnonblock(_polyEngine->pcap, 1, errbuf) == 1){
			fprintf(stderr, "Could not set device \"%s\" to non-blocking: %s\n", _polyEngine->source->str,errbuf);
			pcap_close(_polyEngine->pcap);
                	_polyEngine->pcap = NULL;
                	return;
        	}
		_polyEngine->pcapfd = pcap_get_selectable_fd(_polyEngine->pcap);
		_polyEngine->polyengine_status = POLYENGINE_STATE_RUNNING;
                DEBUG0("Starting engine\n");
	}
}

/**
 * POEG_Stop - Stops the polyengine
 */
void POEG_Stop() {
	
	DEBUG0("Trying to stop the engine, status=%s\n",polyengine_states_str[_polyEngine->polyengine_status]);
	if(_polyEngine->polyengine_status == POLYENGINE_STATE_RUNNING) {
		// printf("pcap = 0x%x\n",_polyEngine->pcap);
		//if(_polyEngine->pcap != NULL);
		//	pcap_close(_polyEngine->pcap);
		_polyEngine->pcap = NULL;
		_polyEngine->pcapfd = -1;
		_polyEngine->polyengine_status = POLYENGINE_STATE_STOP;
                DEBUG0("Stoping engine\n");
	}
}

/**
 * POEG_StopAndExit - Stops and exit the polyengine
 */
void POEG_StopAndExit() {
	POEG_Stop();
	POEG_Destroy();
	exit(0);
}

/**
 * POEG_Destroy - Destroy the ST_PolyEngine type
 */
void POEG_Destroy() {
	PODS_Destroy();
	g_string_free(_polyEngine->source,1);
	FLPO_Destroy(_polyEngine->flowpool);
	MEPO_Destroy(_polyEngine->memorypool);	
	COMN_Destroy(_polyEngine->conn);
	HTCC_Destroy(_polyEngine->httpcache);
	AUHT_Destroy(_polyEngine->hosts);
	PKCX_Destroy();
	g_free(_polyEngine);
	return;
}

/**
 * POEG_Stats - Show statistics related to the ST_PolyEngine 
 */

void POEG_Stats() {
	
	MEPO_Stats(_polyEngine->memorypool);
	FLPO_Stats(_polyEngine->flowpool);
	HTCC_Stats(_polyEngine->httpcache);
	HTAZ_PrintfStats();
}

/**
 * POEG_AddToHttpCache - Show statistics related to the ST_PolyEngine
 *
 * @param type the cache type (HTTP_NODE_TYPE_STATIC,HTTP_NODE_TYPE_DYNAMIC)
 * @param value the parameter
 * 
 */
void POEG_AddToHttpCache(int type,char *value){
	if(_polyEngine->httpcache) {
		if (type == HTTP_CACHE_HEADER )
			HTCC_AddHeaderToCache(_polyEngine->httpcache,value,HTTP_NODE_TYPE_STATIC);
		else if (type == HTTP_CACHE_PARAMETER) 
			HTCC_AddParameterToCache(_polyEngine->httpcache,value,HTTP_NODE_TYPE_STATIC);
	}
}

/**
 * POEG_SendSuspiciousSegmentToExecute - Sends a suspicious segment to the detection engine. 
 *
 * @param seg the ST_MemorySegment.
 * @param hash
 * @param seq
 * 
 */
void POEG_SendSuspiciousSegmentToExecute(ST_MemorySegment *seg,unsigned long hash, uint32_t seq) {

	PODS_SendSuspiciousSegment(_polyEngine->bus,"/polyvaccine/detector","polyvaccine.detector.analyze","analyze",
		seg->mem,seg->virtual_size,hash,seq);
	return;
}

void POEG_SendVerifiedSegment(u_int32_t seq,unsigned long hash,int veredict) {

	PODS_SendVerifiedSegment(_polyEngine->bus,"/polyvaccine/protector","polyvaccine.protector.veredict","veredict",
		seq,hash,veredict);
	return;
}

void POEG_SetLearningMode() {
	AUTH_SetAuthorizedAll(_polyEngine->hosts);
	return;
}

void POEG_Run() {
	ST_HttpFlow *flow;
	ST_MemorySegment *memseg;
	register int i;
	int nfds,usepcap,ret,update_timers;
        DBusWatch *local_watches[MAX_WATCHES];
	struct timeval currenttime;
	struct pcap_pkthdr *header;
	unsigned char *pkt_data;
	struct pollfd local_fds[MAX_WATCHES];

        fprintf(stdout,"%s running on %s version %s machine %s\n",POLYVACCINE_FILTER_ENGINE_NAME,
		SYIN_GetOSName(),SYIN_GetVersionName(),SYIN_GetMachineName());
	if(_polyEngine->hosts->all)
		fprintf(stdout,"\tLearning mode active\n");

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

                if(_polyEngine->polyengine_status == POLYENGINE_STATE_RUNNING) {
                        local_fds[nfds].fd = _polyEngine->pcapfd;
                        local_fds[nfds].events = POLLIN|POLLPRI|POLLHUP;
                        local_fds[nfds].revents = 0;
                        usepcap = 1;
                }

                ret = poll(local_fds,nfds+usepcap,-1);
                if (ret <0){
                        perror("poll");
                        break;
                }

                if((local_fds[nfds].revents & POLLIN)&&(_polyEngine->polyengine_status == POLYENGINE_STATE_RUNNING)){
                        ret = pcap_next_ex(_polyEngine->pcap,(struct pcap_pkthdr*)&header,(unsigned char*)&pkt_data);
			if(ret < 0) {
                                POEG_Stop();
                                usepcap = 0;
                                if(_polyEngine->is_pcap_file == TRUE){
                                        break;
                                }
			}else {
				if(PKDE_Decode(header,pkt_data) == TRUE){
					if(PKCX_GetTCPDstPort() == _polyEngine->defaultport ) {
						int tcpsegment_size;
						unsigned long hash;
						/* Find a ST_HttpFlow object in order to evaluate it */
						flow = COMN_FindConnection(_polyEngine->conn,
							PKCX_GetIPSrcAddr(),
							PKCX_GetTCPSrcPort(),
							PKCX_GetIPProtocol(),
							PKCX_GetIPDstAddr(),
							PKCX_GetTCPDstPort(),
							&hash);	
							
						if (flow == NULL) {
							flow = FLPO_GetFlow(_polyEngine->flowpool);
							if (flow != NULL) {
								HTLF_SetFlowId(flow,
									PKCX_GetIPSrcAddr(),
									PKCX_GetTCPSrcPort(),
									PKCX_GetIPDstAddr(),
									PKCX_GetTCPDstPort());	
										
								COMN_InsertConnection(_polyEngine->conn,flow,&hash);
								DEBUG0("New Connection on Pool [%s:%d:%d:%s:%d]\n",
									PKCX_GetSrcAddrDotNotation(),
									PKCX_GetTCPSrcPort(),
									PKCX_GetIPProtocol(), 
									PKCX_GetDstAddrDotNotation(),
									PKCX_GetTCPDstPort());
								/* Check if the flow allready have a ST_MemorySegment attached */
								memseg = MEPO_GetMemorySegment(_polyEngine->memorypool);
								HTFL_SetMemorySegment(flow,memseg);
								HTFL_SetArriveTime(flow,&currenttime);	
							}
						}
						// TODO problem with retransmisions with post
						// check test/pcapfiles directory	
						tcpsegment_size = PKCX_GetPayloadLength();
						flow->total_packets++;
						flow->total_bytes += tcpsegment_size;
						if(tcpsegment_size > 0) {
							MESG_AppendPayloadNew(flow->memhttp,PKCX_GetPayload(),tcpsegment_size);
							if(PKCX_IsTCPPush() == 1) {
								if(AUHT_IsAuthorized(_polyEngine->hosts,PKCX_GetSrcAddrDotNotation())) {
									HTAZ_AnalyzeDummyHttpRequest(_polyEngine->httpcache,flow);	
								}else{
									ret = HTAZ_AnalyzeHttpRequest(_polyEngine->httpcache,flow);
									if(ret) { // the segment is suspicious 
										POEG_SendSuspiciousSegmentToExecute(flow->memhttp,
											hash,PKCX_GetTCPSequenceNumber());
									}else{ // the segment is correct 
										POEG_SendVerifiedSegment(hash,
											PKCX_GetTCPSequenceNumber(),1);
									}
								}
								/* Reset the virtual memory of the segment */
								flow->memhttp->virtual_size = 0;
							}	
						}
						HTFL_UpdateTime(flow,&currenttime);
						}	
					} // end of decode;
				}
                }
		/* updates the flow time every 10 seconds aproximately
		 * in order to avoid sorting without non-sense the flow list timer
		 */
		if((currenttime.tv_sec % 10) == 0){
			if(update_timers) {
				COMN_UpdateTimers(_polyEngine->conn,&currenttime);
				update_timers = 0;
			}
		}else 
			update_timers = 1;
               	for (i = 0; i < nfds; i++) {
                        if (local_fds[i].revents) {
                                PODS_Handler(_polyEngine->bus,local_fds[i].revents, local_watches[i]);
                        }
                }
        }
        return;
}


int32_t POEG_GetHttpHeaderCacheHits(){
	int32_t value = 0;

	if((_polyEngine)&&(_polyEngine->httpcache))
		value = _polyEngine->httpcache->header_hits;
	return value;
}
	
int32_t POEG_GetHttpHeaderCacheFails() {
	int32_t value = 0;

	if((_polyEngine)&&(_polyEngine->httpcache))
		value = _polyEngine->httpcache->header_fails;
	return value;
}

int32_t POEG_GetHttpParameterCacheHits(){
        int32_t value = 0;

        if((_polyEngine)&&(_polyEngine->httpcache))
                value = _polyEngine->httpcache->parameter_hits;
        return value;
}

int32_t POEG_GetHttpParameterCacheFails() {
        int32_t value = 0;

        if((_polyEngine)&&(_polyEngine->httpcache))
                value = _polyEngine->httpcache->parameter_fails;
        return value;
}


