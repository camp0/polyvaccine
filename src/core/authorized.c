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

#include "authorized.h"

ST_AuthorizedHost *AUHT_Init(){
	ST_AuthorizedHost *a = g_new(ST_AuthorizedHost,1);
	a->hosts = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,g_free); 
	a->all = FALSE;
	
	return a;
}

void AUHT_Destroy(ST_AuthorizedHost *a){

	g_hash_table_destroy(a->hosts);
	g_free(a);

}

void AUHT_AddHost(ST_AuthorizedHost *a,char *ip){

	g_hash_table_insert(a->hosts,g_strdup(ip),g_strdup(ip));
	return;
}

void AUHT_RemoveHost(ST_AuthorizedHost *a,char *ip){

	g_hash_table_remove(a->hosts,(gchar*)ip);
	return;
}

int AUHT_IsAuthorized(ST_AuthorizedHost *a, char *ip) {

	if(a->all == TRUE)
		return 1;

	if(g_hash_table_lookup(a->hosts,(gchar*)ip) == NULL) {
		return 0;
	}else{
		return 1;
	}
	return 0;
}

void AUTH_SetAuthorizedAll(ST_AuthorizedHost *a) { a->all = TRUE; }

int AUHT_GetNumberOfAuthorizedHosts(ST_AuthorizedHost *a) { 
	return g_hash_table_size(a->hosts);
}
