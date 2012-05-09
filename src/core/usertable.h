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

#ifndef _USERTABLE_H_
#define _USERTABLE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <log4c.h>
#include "userpool.h"
#include "debug.h"
#include "interfaces.h"
#include <netinet/in.h>

struct ST_UserTable {
	GHashTable *table;
	GList *timers;
	int inactivitytime;
	int show_current_users;
	int32_t expiretimers;
	int32_t inserts;
	int32_t releases;
	int32_t current_users;
	ST_UserPool *userpool;
};

typedef struct ST_UserTable ST_UserTable;

ST_UserTable *USTA_Init(void);
void USTA_Destroy(ST_UserTable *ut); 

ST_User *USTA_FindUser(ST_UserTable *ut,u_int32_t saddr);
void USTA_InsertUser(ST_UserTable *ut,ST_User *user);
void USTA_UpdateTimers(ST_UserTable *ut,struct timeval *currenttime);
void USTA_SetUserPool(ST_UserTable *ut,ST_UserPool *userpool);
void USTA_ReleaseUsers(ST_UserTable *ut);
void USTA_Stats(ST_UserTable *ut);
void USTA_ShowUserStatistics(ST_UserTable *ut,int value);

#endif

