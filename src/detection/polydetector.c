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

#include "polydetector.h"

static ST_PolyDetector *_polyDetector = NULL;

/**
 * PODT_SetCpu - Sets the current process of polydetector to
 *		a specific cpu(usefull for multicore systems).
 *
 * @param cpu
 *
 */

void PODT_SetCpu(int cpu){
  	cpu_set_t mask;

	CPU_ZERO(&mask);
  	CPU_SET(cpu,&mask);
  	sched_setaffinity(getpid(), sizeof(mask), &mask);
	return;
}

/**
 * PODT_Init - Initialize the main structures of the polydetector
 */
void PODT_Init(char *name) {
        ST_Callback *current = NULL;
        ST_Interface *interface = NULL;
        register int i,j;

        _polyDetector = (ST_PolyDetector*)g_new0(ST_PolyDetector,1);

	if(name == NULL) 
		snprintf(_polyDetector->interface_name,1024,"%s",POLYVACCINE_DETECTION_INTERFACE);
	else
		snprintf(_polyDetector->interface_name,1024,"%s",name);
		
	SYIN_Init();
	PODS_Init();
        _polyDetector->bus = PODS_Connect(_polyDetector->interface_name,(void*)_polyDetector);
	_polyDetector->sandbox = SABX_Init();

	if(_polyDetector->bus != NULL) {
		i=0;	
		interface = &ST_PublicInterfaces[0];
		interface->name = _polyDetector->interface_name;
		while(interface->name != NULL) {
			/* Loads the methods first */
			current = &interface->methods[0];
			j=0;
			while((current!=NULL)&&(current->name!=NULL)){
				PODS_AddPublicMethod(interface,current);
				j++;
				current = &interface->methods[j];
			}
			j=0;
			current = &interface->properties[0];
			while((current!=NULL)&&(current->name!=NULL)){
				PODS_AddPublicProperty(interface,current);
				j++;
				current = &interface->properties[j];
			} 
			j=0;
			current = &interface->signals[0];
			while((current!=NULL)&&(current->name!=NULL)){
				PODS_AddPublicMethod(interface,current);
				j++;
				current = &interface->signals[j];
			}
			i++;
                	interface = &ST_PublicInterfaces[i];
		}
        }
        return;
}

void PODT_Stats() {
	fprintf(stdout,"Statistics\n");
	SABX_Statistics(_polyDetector->sandbox);
	fprintf(stdout,"\n");
	return;
}


void PODT_Run() {
        register int i;
        int nfds,ret;
        DBusWatch *local_watches[MAX_WATCHES];
        struct pollfd local_fds[MAX_WATCHES];

        fprintf(stdout,"%s running on %s machine %s\n",POLYVACCINE_DETECTION_ENGINE_NAME,
                SYIN_GetOSName(),SYIN_GetMachineName());
	fprintf(stdout,"\tversion %s\n",SYIN_GetVersionName());

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

                ret = poll(local_fds,nfds,-1);
                if (ret <0){
//                        perror("poll");
                        break;
                }

                for (i = 0; i < nfds; i++) {
                        if (local_fds[i].revents) {
                                PODS_Handler(_polyDetector->bus,local_fds[i].revents, local_watches[i]);
                        }
                }
        }
        return;
}

void PODT_Destroy(void){
	PODS_Destroy();
	PODT_Stats();
	SABX_Destroy(_polyDetector->sandbox);
	g_free(_polyDetector);
	_polyDetector = NULL;
	return;
}

