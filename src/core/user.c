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

#include "user.h"

void USER_Reset(ST_User *user){
	register int i;

	for(i=0;i<SAMPLE_TIME;i++){
		user->requests_per_minute[i] = 0;
		user->flows_per_minute[i] = 0;
	}
        user->ip = 0;
        user->total_request = 0;
        user->total_flows = 0;
        user->current_flows = 0;
        user->current_requests = 0;
        user->total_gets = 0;
        user->total_posts = 0;
	user->arrive_time.tv_sec = 0;
	user->arrive_time.tv_usec = 0;
	user->current_time.tv_sec = 0;
	user->current_time.tv_usec = 0;
	user->acumulated_cost = 0;
	user->path_hits = 0;
	user->path_fails = 0;
	user->request_hits = 0;
	user->request_fails = 0;
	user->statistics_reach = 0;
}

ST_User *USER_Init(){
	ST_User *user = g_new(ST_User,1);

	USER_Reset(user);
	return user;
}

void USER_Destroy(ST_User *user){
	g_free(user);
	user = NULL;
	return;
}
