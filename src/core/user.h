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

#ifndef _USER_H_
#define _USER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <log4c.h>
#include <sys/types.h>
#include <glib.h>
#include "debug.h"

struct ST_User{
	u_int32_t ip;

	int16_t total_request;
	int16_t total_flows;
	int16_t total_gets;
	int16_t total_posts;	

	int acumulated_cost;
	int16_t correct_paths;
	int16_t incorrect_paths;
	
	struct timeval arrive_time;
	struct timeval current_time;
};

typedef struct ST_User ST_User;

ST_User *USER_Init(void);
void USER_Destroy(ST_User *user);
void USER_Reset(ST_User *user);

#endif
