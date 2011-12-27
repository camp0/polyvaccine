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

#include "context.h"

ST_SharedContext *COXT_GetContext(){
	ST_SharedContext *c = COXT_AttachContext();

	bzero(c,sizeof(ST_SharedContext));
	return c;
}

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


void COXT_FreeContext(ST_SharedContext *c){
	munmap(c,sizeof(ST_SharedContext));	
}

void COXT_Printf(ST_SharedContext *c) {

	printf("ctx=0x%x;child_pid=%d;parent_pid=%d;virtualeip=%d;memory=%x;size=%d;",
		c,c->child_pid,c->parent_pid,
		c->virtualeip,c->memory,c->size);
}
