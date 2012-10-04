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

#include "sharedcontext.h"

/**
 * COXT_GetContext - Gets the shared context between the parent and his child. 
 *
 * @return ST_SharedContext 
 */
ST_SharedContext *COXT_GetContext(){
	ST_SharedContext *c = COXT_AttachContext();

	bzero(c,sizeof(ST_SharedContext));
	return c;
}

/**
 * COXT_AttachContext - Attach to a shared context between the parent and his child. 
 *
 * @return ST_SharedContext 
 */
ST_SharedContext *COXT_AttachContext(){
        int fd;
        caddr_t result;

        fd = open("/dev/zero",O_RDWR);
        if(fd == -1){
                perror("open");
                return NULL;
        }
        result = mmap(0, sizeof(ST_SharedContext), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
        return (ST_SharedContext*)result;
}


/**
 * COXT_FreeContext - Free the shared context  
 *
 * @param ST_SharedContext c 
 */

void COXT_FreeContext(ST_SharedContext *c){
	munmap(c,sizeof(ST_SharedContext));	
}


void COXT_Printf(ST_SharedContext *c) {

	printf("Shared context\n");
	printf("\tctx(0x%x)child_pid(%d)parent_pid(%d)\n",c,c->child_pid,c->parent_pid);
	printf("\ttotal_forks(%d)total_segs_by_child(%d)\n",c->total_forks,c->total_segs_by_child);

	return;
}
