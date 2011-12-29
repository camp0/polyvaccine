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

#include "polyprotector.h"

static ST_PolyProtector *_polyProtector = NULL;

/**
 * POPR_Init - Initialize the main structures of the polydetector
 */
void POPR_Init() {
        ST_Callback *current = NULL;
        ST_Interface *interface = NULL;
        register int i,j;

        _polyProtector = g_new0(ST_PolyProtector,1);
	_polyProtector->dev_index = 0;
        _polyProtector->total_tcp_segments = 0;
        _polyProtector->total_tcp_packets = 0;
        _polyProtector->total_inbound_packets = 0;
        _polyProtector->tcp_retransmition_drop_segments = 0;
	_polyProtector->table = g_hash_table_new(g_direct_hash,g_direct_equal); 
	_polyProtector->pool = NFPO_Init();

	PODS_Init();
        _polyProtector->bus = PODS_Connect(POLYVACCINE_PROTECTOR_INTERFACE,(void*)_polyProtector);
	
	PODS_AddInterface(&ST_PublicInterfaces[0]);
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
                current = &interface->signals[0];
                for (j = 0;j<interface->total_signals;j++){
                        current = &interface->signals[j];
                        DEBUG0("add signal '%s' on interface '%s'\n",current[j].name,interface->name);
                        PODS_AddPublicCallback(current);
		}
        }
        return;
}

void POPR_SetDevice(char *dev){
        struct ifreq ireq;
        int sockfd,index;
        char bufferip[16],bufferbroad[16];
        struct in_addr ip;
        struct in_addr ip_broadcast;
        register int i;

        bzero(&ireq, sizeof(ireq));
        sockfd = socket(PF_PACKET,SOCK_PACKET, htons(ETH_P_ARP));
        strcpy(ireq.ifr_name,dev);

        /* Get the interface index */
        if( (ioctl(sockfd, SIOCGIFINDEX, &ireq)) == -1) {
                fprintf(stderr,"Unkonw Network Interface %s\n",dev);
                exit(-1);
        }
        _polyProtector->dev_index = ireq.ifr_ifindex;

	close(sockfd);
	return;
}


void POPR_Run() {
        register int i;
        int nfds,ret;
	int nffd,len;
        DBusWatch *local_watches[MAX_WATCHES];
        struct pollfd local_fds[MAX_WATCHES];
	char pktbuf[2048];

	nffd = NFPK_InitNfq(_polyProtector); 
	if(nffd == -1) {
		fprintf(stderr,"Can not attach to netfilter\n");
	}

        /* Tells the kernel we only want forwarded packets */
        system("iptables -N DISTQUEUE");
        system("iptables -I OUTPUT -p all -j DISTQUEUE");
        //system("iptables -I FORWARD -p all -j DISTQUEUE");
        system("iptables -I DISTQUEUE -p all -j NFQUEUE");

	SYIN_Init();
	fprintf(stdout,"Protection engine running on %s version %s machine %s\n",
                SYIN_GetOSName(),SYIN_GetVersionName(),SYIN_GetMachineName());
	DEBUG0("netfilter descriptor %d\n",nffd);

        while (TRUE) {
                nfds = 0;
                //gettimeofday(&currenttime,NULL);

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

         	local_fds[nfds].fd = nffd;
                local_fds[nfds].events = POLLIN|POLLPRI|POLLHUP;
                local_fds[nfds].revents = 0;
                
                ret = poll(local_fds,nfds+1,-1);
                if (ret <0){
                        perror("poll");
                        break;
                }

		if(local_fds[nfds].revents){ // & POLLIN){
			len = recv(nffd,pktbuf,2048,0);
                	nfq_handle_packet(_polyProtector->h, pktbuf, len);	
		}

                for (i = 0; i < nfds; i++) {
                        if (local_fds[i].revents) {
                                PODS_Handler(_polyProtector->bus,local_fds[i].revents, local_watches[i]);
                        }
                }
        }
        return;
}

void POPR_Exit() {
	fprintf(stdout,"Protection engine statistics\n");
	fprintf(stdout,"\ttotal inbound packets %ld\n",_polyProtector->total_inbound_packets);
	fprintf(stdout,"\ttotal tcp packets %ld\n",_polyProtector->total_tcp_packets);
	fprintf(stdout,"\ttotal tcp segments %ld\n",_polyProtector->total_tcp_segments);
	fprintf(stdout,"\ttotal retransmition tcp segments droped%ld\n",_polyProtector->tcp_retransmition_drop_segments);

	NFPK_CloseNfq(_polyProtector);
	NFPO_Destroy(_polyProtector->pool);
	exit(0);
}
