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
#include "httpsignalbalancer.h"

/**
 * HTSB_Init - Initialize all the fields of the http signal balancer 
 */

ST_HTTPSignalBalancer *HTSB_Init(){
	ST_HTTPSignalBalancer *sb;

	sb = g_new0(ST_HTTPSignalBalancer,1);
	sb->index = 0;
	sb->total_items = 0;
	sb->detectors = g_array_new(FALSE,FALSE,sizeof(ST_HTTPDetectorNode));

	return sb;
}

/**
 * HTSB_Destroy - Initialize all the fields of the http signal balancer
 *
 * @param sb to destroy
 *
 */

void HTSB_Destroy(ST_HTTPSignalBalancer *sb){

	g_array_free(sb->detectors,TRUE);
	g_free(sb);
}


ST_HTTPDetectorNode *__HTSB_FindNode(ST_HTTPSignalBalancer *sb,char *interface, char *name) {
	ST_HTTPDetectorNode *nod = NULL;
	register int i;

	for (i = 0;i<sb->total_items;i++) {
		nod = &g_array_index(sb->detectors,ST_HTTPDetectorNode,i);
		if((strncmp(interface,nod->interface,strlen(interface)) == 0)&&
			(strncmp(name,nod->name,strlen(name))==0)) {
			break;
		}	
	}
	return nod;
}

/**
 * HTSB_AddDetectorNode - Add a pvde engine reference in order to balance the suspicious segments
 *
 * @param sb
 * @param interface
 * @param name 
 *
 */

void HTSB_AddDetectorNode(ST_HTTPSignalBalancer *sb, char *interface, char *name){
	ST_HTTPDetectorNode *nod = NULL;

	nod = g_new0(ST_HTTPDetectorNode,1);
	nod->interface = g_strdup(interface);
	nod->name = g_strdup(name);

	g_array_append_vals(sb->detectors,nod,1);
	sb->total_items++;
	return;
}

/**
 * HTSB_RemoveDetectorNode - Remove a pvde engine reference in order to balance the suspicious segments
 *      
 * @param sb 
 * @param interface
 * @param name
 *
 */

void HTSB_RemoveDetectorNode(ST_HTTPSignalBalancer *sb, char *interface, char *name){
	/// TODO: clean everything
	return;
}

/**
 * HTSB_GetNext - Retrieve a ST_HTTPDetectorNode by using a simple round robin discipline
 *      
 * @param sb 
 *
 * @return ST_HTTPDetectorNode
 */

ST_HTTPDetectorNode *HTSB_GetNext(ST_HTTPSignalBalancer *sb){
	ST_HTTPDetectorNode *nod = NULL;

	if(sb->total_items > 0) {
		if(sb->total_items == 1) {
			nod = &g_array_index(sb->detectors,ST_HTTPDetectorNode,0); 
		}else{
			/* round robin discipline */
			if(sb->index == sb->total_items) 
				sb->index = 0;
			
			nod = &g_array_index(sb->detectors,ST_HTTPDetectorNode,sb->index);
			sb->index++;
		}	
	}	
	return nod;
}
