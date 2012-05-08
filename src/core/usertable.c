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

#include "usertable.h"

#define POLYLOG_CATEGORY_NAME POLYVACCINE_FILTER_CONNECTION_INTERFACE
#include "log.h"

/**
 * USTA_SetUserPool - Sets the reference of the userpool on the ST_UserTable.
 *
 * @param ut the ST_UserTable 
 * @param flowpool 
 */

void USTA_SetUserPool(ST_UserTable *ut,ST_UserPool *userpool){
	ut->userpool = userpool;
}

/**
 * USTA_Stats - Show the statistics
 *
 * @param ut the ST_UserTable 
 */

void USTA_Stats(ST_UserTable *ut) {
 
        fprintf(stdout,"User table statistics\n");
        fprintf(stdout,"\ttimeout:%d seconds\n",ut->inactivitytime);
        fprintf(stdout,"\treleases:%d\n",ut->releases);
        fprintf(stdout,"\tinserts:%d\n",ut->inserts);
        fprintf(stdout,"\texpires:%d\n",ut->expiretimers);
	return;
}


gint user_cmp(ST_User *user1, ST_User *user2) {
        if (user1->current_time.tv_sec > user2->current_time.tv_sec)
                return 1;
        else
                return 0;
}

/**
 * USTA_ReleaseUser - Release a ST_User to the ST_UserTable.
 *
 * @param ut the ST_UserTable 
 * @param userf
 */
void USTA_ReleaseUser(ST_UserTable *ut,ST_User *user) {

        g_hash_table_remove(ut->table,GINT_TO_POINTER(user->ip));

	// TODO: This should be optimized maybe by a tree.
	ut->timers = g_list_remove(ut->timers,user);

#ifdef DEBUG
	LOG(POLYLOG_PRIORITY_DEBUG,
        	"Release user(0x%x) to userpool(0x%x)",user,ut->userpool);
#endif
        USPO_AddUser(ut->userpool,user);
	ut->current_users--;
	ut->releases++;
	return;
}


/**
 * USTA_InsertUser - Adds a ST_User to the ST_UserTable.
 *
 * @param ut the ST_UserTable 
 * @param user
 */

void USTA_InsertUser(ST_UserTable *ut,ST_User *user){

	ut->current_users++;
	ut->inserts++;

        g_hash_table_insert(ut->table,GINT_TO_POINTER(user->ip),user);
	ut->timers = g_list_insert_sorted(ut->timers,user,(GCompareFunc)user_cmp);
	return;
}

/**
 * USTA_UpdateTimers - Updates the flow list in order to release the users.
 *
 * @param ut the ST_UserTable 
 * @param currenttime 
 * 
 */
void USTA_UpdateTimers(ST_UserTable *ut,struct timeval *currenttime){
        GList *f_update = NULL;
        GList *current = NULL;
        ST_User *user = NULL;

        while((current = g_list_first(ut->timers)) != NULL) {
                user =(ST_User*)current->data;
                ut->timers = g_list_remove_link(ut->timers,current);

                if(user->current_time.tv_sec + ut->inactivitytime <= user->current_time.tv_sec) {
                        /* The timer expires */
#ifdef DEBUG
			LOG(POLYLOG_PRIORITY_DEBUG,
                        	"Expire timer for user(0x%x)secs(%d)curr(%d)",user,user->current_time.tv_sec,currenttime->tv_sec);
#endif
			USTA_ReleaseUser(ut,user);

                        ut->expiretimers++; 
                        continue;
                }
                f_update = g_list_insert_sorted(f_update,user,(GCompareFunc)user_cmp);
        }
        ut->timers = g_list_concat(f_update,ut->timers);
        return;
}

/**
 * USTA_Init - Creates a ST_UserTable type.
 *
 * @return ST_UserTable 
 * 
 */

ST_UserTable *USTA_Init() {
	ST_UserTable *ut= NULL;

	ut =(ST_UserTable*)g_new(ST_UserTable,1);
	ut->table = g_hash_table_new(g_direct_hash,g_direct_equal);
	//ut->table = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,USTA_DestroyCallback);
	ut->timers = NULL;
	ut->inactivitytime = 60 * 60;
	ut->expiretimers = 0;
	ut->releases = 0;
	ut->inserts = 0;
	ut->current_users = 0;
	ut->userpool = NULL;
	return ut;
};

/**
 * USTA_ReleaseUsers - Releases all the users stored on the ST_UserTable.
 *
 * @param ut 
 * 
 */

void USTA_ReleaseUsers(ST_UserTable *ut){
        GHashTableIter iter;
	GList *l = NULL; 
	int items = 0;

	while((l = g_list_first(ut->timers)) != NULL) {
                ST_User *user =(ST_User*)l->data;
		USTA_ReleaseUser(ut,user);
		items++;
	}	
#ifdef DEBUG
	LOG(POLYLOG_PRIORITY_DEBUG,
        	"Releasing %d users to userpool(0x%x)",items,ut->userpool);
#endif
	return;
}

/**
 * USTA_Destroy - Destroy the ST_UserTable.
 *
 * @param ut 
 * 
 */

void USTA_Destroy(ST_UserTable *ut) {
       	g_hash_table_destroy(ut->table);
        g_list_free(ut->timers);
     	g_free(ut); 
	ut = NULL;
}

/**
 * USTA_FindUser - Finds a ST_User associated to a IP.
 *
 * @param ut 
 * @param saddr 
 *
 * @return ST_User
 * 
 */
ST_User *USTA_FindUser(ST_UserTable *ut,u_int32_t saddr){
        gpointer object;
	ST_User *user = NULL;

        object = g_hash_table_lookup(ut->table,GINT_TO_POINTER(saddr));
        if (object != NULL){
		user = (ST_User*)object;
                return user;
        }

        return NULL;
}

