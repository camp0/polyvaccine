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
 * PODT_Init - Initialize the main structures of the polydetector
 */
void PODT_Init() {
        ST_Callback *current = NULL;
        ST_Interface *interface = NULL;
        register int i,j;

        _polyDetector = (ST_PolyDetector*)g_new0(ST_PolyDetector,1);
	_polyDetector->executed_segments = 0;

	PODS_Init();
        _polyDetector->bus = PODS_Connect(POLYVACCINE_DETECTOR_INTERFACE,(void*)_polyDetector);
	
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
	SYSU_Init();
        return;
}



void PODT_Run() {
        register int i;
        int nfds,ret;
        DBusWatch *local_watches[MAX_WATCHES];
        //struct timeval currenttime;
        struct pollfd local_fds[MAX_WATCHES];

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
                        perror("poll");
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

