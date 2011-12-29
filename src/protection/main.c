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

#include <stdio.h>
#include <getopt.h>
#include "polyprotector.h"

void sigquit(int signal) {
    	POPR_Exit(); 
        return;
}

void usage(char *prog){
        fprintf(stdout,"Use %s -s <pcapfile/device> [options]\n",prog);
        fprintf(stdout,"\n");

}

void main(int argc, char **argv) {
        int c,port;
        char *source = NULL;

        port = 80;
        while ((c = getopt (argc, argv, "s:p:")) != -1){
                switch (c) {
                        case 's':
                                source = optarg;
                                break;
                        case 'p':
                                port = atoi(optarg);
                                break;
                        default:
                                abort ();
                }
        }

        if(source == NULL) {
                usage(argv[0]);
                exit(0);
        }

	POPR_Init();
	signal(SIGINT,sigquit);
	POPR_SetDevice(source);
	
	POPR_Run();

	POPR_Exit();
	return;
}
