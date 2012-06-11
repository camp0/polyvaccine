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
#include <signal.h>
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
 * __POFR_ShowStartBanner - Shows the initial banner of the application.
 *
 */

void __POFR_ShowStartBanner(){
        fprintf(stdout,"%s running on %s machine %s\n",POLYVACCINE_FILTER_ENGINE_NAME,
                SYIN_GetOSName(),SYIN_GetMachineName());
        fprintf(stdout,"\tversion %s\n",SYIN_GetVersionName());
        fprintf(stdout,"\tActive mode '%s'\n",polyfilter_modes_str[_polyFilter->mode]);
        FORD_ShowAnalyzers(_polyFilter->forwarder);
        return;
}

/**
 * __POFR_ShowEndBanner - Shows the finnal banner of the application.
 *      
 */ 

void __POFR_ShowEndBanner() {
        int32_t fullmemory;
        char *unit = "Bytes";
	struct tm tmaux;
	struct timeval duration;
	struct timeval *usertime = NULL; 
	struct timeval *systime = NULL;
	long ressize = 0;
	long shmsize = 0;
	long datsize = 0;
	long stksize = 0;
        char asc_duration[90],asc_usertime[90],asc_systime[90];

        fullmemory = _polyFilter->flowpool->total_allocated * sizeof(ST_GenericFlow);
        fullmemory += MAX_MEMORY_SEGMENTS_PER_POOL * (sizeof(ST_MemorySegment)+MAX_SEGMENT_SIZE);
        fullmemory += _polyFilter->userpool->total_allocated * sizeof(ST_User);
	/* the caches comsumption */
	fullmemory += HTAZ_GetCacheMemorySize();
	fullmemory += DSAZ_GetCacheMemorySize();

        if((fullmemory / 1024)>0){
                unit = "KBytes";
                fullmemory = fullmemory / 1024;
        }
        if((fullmemory / 1024)>0){
                unit = "MBytes";
                fullmemory = fullmemory / 1024;
        }
        if((fullmemory / 1024)>0){
                unit = "GBytes";
                fullmemory = fullmemory / 1024;
        }

	SYIN_TimevalSub(&duration,&(_polyFilter->endtime),&(_polyFilter->starttime));
   
	SYIN_Update();
	usertime = SYIN_GetUserTimeUsed();
	systime = SYIN_GetSystemTimeUsed();
	ressize = SYIN_GetMaximumResidentSetSize();
	shmsize = SYIN_GetIntegralSharedMemorySize();
	datsize = SYIN_GetIntegralUnsharedDataSize();
	stksize = SYIN_GetIntegralUnsharedStackSize();

	/* convert it to a struct tm */
   	localtime_r(&duration.tv_sec,&tmaux);
	tmaux.tm_hour--;
	strftime(asc_duration,90,"%H:%M:%S",&tmaux);

   	localtime_r(&(usertime->tv_sec),&tmaux);
	tmaux.tm_hour--;
	strftime(asc_usertime,90,"%H:%M:%S",&tmaux);

   	localtime_r(&(systime->tv_sec),&tmaux);
	tmaux.tm_hour--;
	strftime(asc_systime,90,"%H:%M:%S",&tmaux);

        fprintf(stdout,"%s exiting, duration %s\n",POLYVACCINE_FILTER_ENGINE_NAME,asc_duration);
        fprintf(stdout,"\tProcess flows %"PRId32"\n",_polyFilter->flowpool->pool->total_acquires);
        fprintf(stdout,"\tProcess users %"PRId32"\n",_polyFilter->userpool->pool->total_acquires);
        fprintf(stdout,"\tMemory used %"PRId32" %s [",fullmemory,unit);
	fprintf(stdout,"resident %ld, shared %ld,",ressize,shmsize);
	fprintf(stdout,"data %ld, stack %ld]\n",datsize,stksize);
	fprintf(stdout,"\tUser time %s, Sys time %s\n",asc_usertime,asc_systime);
        return;
}

/**
 * __POFR_StatsFromDescriptor - Show statistics on the recieved descriptor.
 *
 * @param out 
 * 
 */
void __POFR_StatsFromDescriptor(FILE *out) {
        PKDE_Stats(out);
        TCAZ_Stats(out);
        USPO_Stats(_polyFilter->userpool,out);
        MEPO_Stats(_polyFilter->memorypool,out);
        FLPO_Stats(_polyFilter->flowpool,out);
        COMN_Stats(_polyFilter->conn,out);
        USTA_Stats(_polyFilter->users,out);
        FORD_Stats(_polyFilter->forwarder,out);
        return;
}

/**
 * __POFR_StatisticsSignalHandler - Signal handler for the SIGUSR1 signal.
 *      
 * @param signal 
 * 
 */
void __POFR_StatisticsSignalHandler(int signal) {
	FILE *out;

        out = fopen("polyfilter.stats","w");
        if(out == NULL) 
		return;
	fprintf(stdout,"Dump statistics\n");
	__POFR_StatsFromDescriptor(out);
	fsync(out);
	fclose(out);
	return;
}

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
                (void*)DSAZ_AnalyzeDummyHTTPRequest,
		(void*)NULL,
		(void*)DSAZ_NotifyWrong);

	FORD_AddAnalyzer(_polyFilter->forwarder,
		"http",IPPROTO_TCP,8080,
		(void*)HTAZ_Init,
		(void*)HTAZ_Destroy,
		(void*)HTAZ_Stats,	
		(void*)HTAZ_AnalyzeHTTPRequest,
		(void*)HTAZ_AnalyzeDummyHTTPRequest,
		(void*)HTAZ_NotifyCorrect,
		(void*)HTAZ_NotifyWrong);

	FORD_AddAnalyzer(_polyFilter->forwarder,
		"sip",IPPROTO_UDP,5060,
		(void*)SPAZ_Init,
		(void*)SPAZ_Destroy,
		(void*)SPAZ_Stats,	
		(void*)SPAZ_AnalyzeSIPRequest,
		(void*)SPAZ_AnalyzeDummySIPRequest,
		(void*)NULL,
		(void*)NULL);

	FORD_InitAnalyzers(_polyFilter->forwarder);

	// Set the signal handler for print out the statistics by using SIGUSR1
        signal(SIGUSR1,__POFR_StatisticsSignalHandler);
        sigemptyset(&(_polyFilter->sigmask));
        sigaddset(&(_polyFilter->sigmask), SIGUSR1);

	return;
}

void POFR_EnableAnalyzers(char *analyzers){

	// TODO.
	// Tells the forwarder to enable the analyzers
	FORD_EnableAnalyzerByName(_polyFilter->forwarder,analyzers);
	return;
}

void POFR_SetStatisticsLevel(int level){
	USTA_SetStatisticsLevel(_polyFilter->users,level);
	return;
}

void POFR_SetHTTPStatisticsLevel(int level){

	HTAZ_SetStatisticsLevel(level);
	return;
}

void POFR_SetDDoSStatisticsLevel(int level){

	DSAZ_SetGraphStatisticsLevel(level);
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
 * POFR_SetDDoSSourcePort - Sets the source port of the webserver 
 *
 * @param port the new port to analyze 
 */
void POFR_SetDDoSSourcePort(int port){

        FORD_ChangePortToAnalyzer(_polyFilter->forwarder,"ddos",port);
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
 * POFR_SetMode - Change the mode of operation of all the engine
 *
 * @param mode
 *
 */

void POFR_SetMode(char *mode) {
	register int i = 0;
	int hosts = AUHT_GetNumberOfAuthorizedHosts(_polyFilter->hosts);

	while(polyfilter_modes_str[i]!= NULL) {
		if(strncmp(polyfilter_modes_str[i],mode,strlen(polyfilter_modes_str[i])) == 0) {
			if((hosts == 0)&&(i != POLYFILTER_MODE_SOMECACHE)){ //We can only switch if there is no hosts
				_polyFilter->mode = i;
        			LOG(POLYLOG_PRIORITY_INFO,
                			"Changing mode=%s",polyfilter_modes_str[_polyFilter->mode]);
				return;
			}
		}
		i++;
	}
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
	gettimeofday(&(_polyFilter->endtime),NULL);
	__POFR_ShowEndBanner();
	PODS_Destroy();
	COMN_ReleaseFlows(_polyFilter->conn);
	USTA_ReleaseUsers(_polyFilter->users);
	g_string_free(_polyFilter->source,TRUE);
	FLPO_Destroy(_polyFilter->flowpool);
	MEPO_Destroy(_polyFilter->memorypool);
	USPO_Destroy(_polyFilter->userpool);
	COMN_Destroy(_polyFilter->conn);
	USTA_Destroy(_polyFilter->users);
	AUHT_Destroy(_polyFilter->hosts);
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

	__POFR_StatsFromDescriptor(stdout);
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

void POFR_SetExitOnPcap(int value){
	_polyFilter->when_pcap_done_exit = value;
}

/**
 * POFR_SetLearningMode - Authorize all the host. 
 *
 */
void POFR_SetLearningMode() {
	_polyFilter->mode = POLYFILTER_MODE_FULLCACHE;
	return;
}

void __POFR_UpdateStatus() {
        if(AUHT_GetNumberOfAuthorizedHosts(_polyFilter->hosts)>0)
        	_polyFilter->mode = POLYFILTER_MODE_SOMECACHE;
        else
        	_polyFilter->mode = POLYFILTER_MODE_NONCACHE;
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


/**
 * POFR_SetInitialFlowsOnPool - Modify the initial value of the flowpool 
 *
 * @param value 
 */

void POFR_SetInitialFlowsOnPool(int value){
	
	if(value>0){
		FLPO_ResizeFlowPool(_polyFilter->flowpool,value);
		MEPO_ResizeMemoryPool(_polyFilter->memorypool,value);
	}
	return;
}

/**
 * POFR_SetInitialUsersOnPool - Modify the initial value of the userpool 
 *
 * @param value 
 */

void POFR_SetInitialUsersOnPool(int value){

	if(value>0){
		USPO_ResizeUserPool(_polyFilter->userpool,value);
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


int __POFR_GetActiveDescriptor(){
	register int i;
	int nfds = 0;
	int ret;

	for (i = 0; i < PODS_GetTotalActiveDescriptors(); i++) {
        	if (PODS_GetDescriptorByIndex(i) == 0 ||
                !dbus_watch_get_enabled(PODS_GetWatchByIndex(i))) {
                	continue;
                }

		_polyFilter->local_fds[nfds].fd = PODS_GetDescriptorByIndex(i);
		_polyFilter->local_fds[nfds].events = PODS_GetEventsByIndex(i);
		_polyFilter->local_fds[nfds].revents = 0;
		_polyFilter->local_watches[nfds] = PODS_GetWatchByIndex(i);
		nfds++;
	}

	if(_polyFilter->polyfilter_status == POLYFILTER_STATE_RUNNING) {
		_polyFilter->local_fds[nfds].fd = _polyFilter->pcapfd;
		_polyFilter->local_fds[nfds].events = POLLIN|POLLPRI|POLLHUP;
		_polyFilter->local_fds[nfds].revents = 0;
		_polyFilter->usepcap = 1;
	}

	ret = ppoll(_polyFilter->local_fds,nfds+_polyFilter->usepcap,NULL,&(_polyFilter->sigmask));
	// TODO: detect if the syscall ppoll is available, checkout man poll
	//ret = poll(_polyFilter->local_fds,nfds+_polyFilter->usepcap,-1);
	if (ret <0){
		perror("poll");
		return -1;
	}

	return nfds;
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
	int nfds,ret,update_timers;
	struct timeval currenttime;
	struct timeval lasttimeouttime;
	struct pcap_pkthdr *header;
	unsigned char *pkt_data;
        struct sigaction sa;

        sigemptyset (&sa.sa_mask);
        sa.sa_sigaction = (void *)__POFR_StatisticsSignalHandler;
        sa.sa_flags = SA_RESTART;

	__POFR_ShowStartBanner();

        gettimeofday(&lasttimeouttime,NULL);
	_polyFilter->starttime.tv_sec = lasttimeouttime.tv_sec;
	_polyFilter->starttime.tv_usec = lasttimeouttime.tv_usec;
	update_timers = 1;
	while (TRUE) {
                nfds = 0;
                _polyFilter->usepcap = 0;
                gettimeofday(&currenttime,NULL);

		nfds = __POFR_GetActiveDescriptor();
		if(nfds < 0)
			break;

                if((_polyFilter->local_fds[nfds].revents & POLLIN)&&
		(_polyFilter->polyfilter_status == POLYFILTER_STATE_RUNNING)){
                        ret = pcap_next_ex(_polyFilter->pcap,(struct pcap_pkthdr*)&header,(unsigned char*)&pkt_data);
			if(ret < 0) {
                                POFR_Stop();
                                _polyFilter->usepcap = 0;
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
					if(ga != NULL) { // There is a generic analyzer for the flow 
						int segment_size;
						int newflow = FALSE;
						uint32_t userip;
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
								newflow = TRUE;
							}else{
								//WARNING("No flow pool allocated\n");
								continue;
							}
						}
						// Update the direction of the flow
						flow->direction = ga->direction;
						if(flow->direction == FLOW_FORW) 
							userip = PKCX_GetIPSrcAddr();
						else
							userip = PKCX_GetIPDstAddr();	
                                                // This should be optimized, only syn/ack packets could generate
                                                // a new user
                                                user = USTA_FindUser(_polyFilter->users,userip);
                                                if(user == NULL){
                                                        user = USPO_GetUser(_polyFilter->userpool);
                                                        if(user != NULL){
                                                                user->ip = PKCX_GetIPSrcAddr();
                                                                user->arrive_time.tv_sec = currenttime.tv_sec;
                                                                user->arrive_time.tv_usec = currenttime.tv_usec;
                                                                USTA_InsertUser(_polyFilter->users,user);
                                                         }else{
                                                                //WARNING("No user pool allocated\n");
                                                                continue;
                                                         }
                                                }

						if(newflow == TRUE) {
							user->total_flows++;
							user->current_flows++;
						}

                                                user->current_time.tv_sec = currenttime.tv_sec;
                                                user->current_time.tv_usec = currenttime.tv_usec;
	
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
								user->current_flows--;	
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
							MESG_AppendPayload(flow->memory,PKCX_GetPayload(),segment_size);
							//  TODO check the upstream datagrams, we dont need to analyze donwstream
							// try to find something efficient
							if((protocol == IPPROTO_UDP)||((protocol == IPPROTO_TCP)&&(PKCX_IsTCPPush() == 1))) {
									
								if(AUHT_IsAuthorized(_polyFilter->hosts,PKCX_GetSrcAddrDotNotation())||
									(_polyFilter->mode == POLYFILTER_MODE_FULLCACHE)) {
									ga->learn(user,flow);	
								}else{
									ga->analyze(user,flow,&ret);
									if((ret)&&(ga->notify_wrong!= NULL)) { 
										// the segment or the user is suspicious
										ga->notify_wrong(_polyFilter->bus,
											user,flow,hash,seq);
									}else{ // the segment or user is correct
										if(ga->notify_correct != NULL) 
											ga->notify_correct(_polyFilter->bus,
												user,flow,hash,seq); 
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
                        if (_polyFilter->local_fds[i].revents) {
                                PODS_Handler(_polyFilter->bus,_polyFilter->local_fds[i].revents, _polyFilter->local_watches[i]);
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


