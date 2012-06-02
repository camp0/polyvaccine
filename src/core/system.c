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

#include "system.h"

void SYIN_Init(){
	uname(&system_info);
}
void SYIN_Update() {
	getrusage(RUSAGE_SELF,&usage_info);
}

char *SYIN_GetOSName(void) { return system_info.sysname;}
char *SYIN_GetNodeName(void) { return system_info.nodename;}
char *SYIN_GetReleaseName(void) { return system_info.release;}
char *SYIN_GetVersionName(void) { return system_info.version;}
char *SYIN_GetMachineName(void) { return system_info.machine;}

struct timeval *SYIN_GetUserTimeUsed() { return &usage_info.ru_utime;}
struct timeval *SYIN_GetSystemTimeUsed() { return &usage_info.ru_stime;}
long SYIN_GetMaximumResidentSetSize() { return usage_info.ru_maxrss;}
long SYIN_GetIntegralSharedMemorySize() { return usage_info.ru_ixrss;}
long SYIN_GetIntegralUnsharedDataSize() { return usage_info.ru_idrss; }
long SYIN_GetIntegralUnsharedStackSize() { return usage_info.ru_isrss; }

/**
 * SYIN_TimevalSub - make the diferente between a and b ( r = a - b)
 *
 * @param a The timeval struct
 * @param b The timeval struct
 *
 * @param r Returns the diference between a and b
 *
 */
void SYIN_TimevalSub(struct timeval *r, struct timeval *a, struct timeval *b)
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
 * SYIN_TimevalAdd - make the sum of a and b ( r = a + b)
 *
 * @param a The timeval struct
 * @param b The timeval struct
 *
 * @param r Returns the diference between a and b
 *
 */

void SYIN_TimevalAdd(struct timeval *r, struct timeval *a, struct timeval *b)
{
        r->tv_usec = a->tv_usec + b->tv_usec;
        if (r->tv_usec > 1000000) {
                r->tv_sec = a->tv_sec + b->tv_sec + 1;
                r->tv_usec -= 1000000;
        } else {
                r->tv_sec = a->tv_sec + b->tv_sec;
        }
}

