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

#ifndef _AUTHORIZED_H_
#define _AUTHORIZED_H_

#include <sys/types.h>
#include <glib.h>

struct ST_AuthorizedHost {
	GHashTable *hosts;
};

typedef struct ST_AuthorizedHost ST_AuthorizedHost;

ST_AuthorizedHost *AUHT_Init(void);
void AUHT_Destroy(ST_AuthorizedHost *a);
void AUHT_AddHost(ST_AuthorizedHost *a,char *ip);
int AUHT_IsAuthorized(ST_AuthorizedHost *a, char *ip);

#endif
