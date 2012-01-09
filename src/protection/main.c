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

static struct option long_options[] = {
        {"interface",	required_argument,      0, 'i'},
        {"authorized",	required_argument,      0, 'a'},
        {"help",        no_argument,            0, 'h'},
        {"version",     no_argument,            0, 'V'},
        {0, 0, 0, 0}
};

static char *short_options = "i:hVa:";

void sigquit(int signal) {
    	POPR_Exit(); 
        return;
}

void usage(char *prog){
        fprintf(stdout,"%s %s\n",POLYVACCINE_PROTECTION_ENGINE_NAME,VERSION);
        fprintf(stdout,"Usage %s [option(s)]\n",prog);
        fprintf(stdout,"The options are:\n");
        fprintf(stdout,"\t-i, --interface=<device>             Device\n");
        fprintf(stdout,"\t-a, --authorized=<host>              Authorized host.\n");
	fprintf(stdout,"\n");
        fprintf(stdout,"\t-h, --help                           Display this information.\n");
        fprintf(stdout,"\t-V, --version                        Display this program's version number.\n");
        fprintf(stdout,"\n");
        fprintf(stdout,"%s",bugs_banner);
        return;
}

void main(int argc, char **argv) {
        int c,option_index;
        char *source = NULL;
	char *authorized_host = NULL;

        while((c = getopt_long(argc,argv,short_options,
                            long_options, &option_index)) != -1) {
                switch (c) {
                        case 'i':
                                source = optarg;
                                break;
                        case 'a':
                                authorized_host = optarg;
                                break;
                        case 'h':
                                usage(argv[0]);
                                exit(0);
                        case 'V':
                                fprintf(stdout,"%s %s\n",POLYVACCINE_PROTECTION_ENGINE_NAME,VERSION);
                                fprintf(stdout,"%s",version_banner);
				exit(0);
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
	if(authorized_host)
		POPR_AddAuthorizedHost(authorized_host);	
	POPR_Run();

	POPR_Exit();
	return;
}
