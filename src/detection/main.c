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
#include "polydetector.h"
#include <getopt.h>
#include <signal.h>

static struct option long_options[] = {
        {"payload",  		no_argument,      	0, 'p'},
        {"interface",  		required_argument,	0, 'i'},
        {"cpu",  		required_argument,	0, 'c'},
        {"help",        	no_argument,            0, 'h'},
        {"version",     	no_argument,            0, 'v'},
        {0, 0, 0, 0}
};

static char *short_options = "hvpi:c:";

void sigquit(int signal) {
        PODT_Destroy();
        return;
}

void usage(char *prog){
        fprintf(stdout,"%s %s\n",POLYVACCINE_DETECTION_ENGINE_NAME,VERSION);
        fprintf(stdout,"Usage %s [option(s)]\n",prog);
        fprintf(stdout,"The options are:\n");
        fprintf(stdout,"\t-i, --interface                      Sets the interface name on the dbus(%s).\n",
		POLYVACCINE_DETECTION_INTERFACE);
        fprintf(stdout,"\t-c, --cpu                            Sets the process to a specific CPU.\n");
        fprintf(stdout,"\t-p, --payload                        Shows the execution payload received by the daemon.\n");
        fprintf(stdout,"\n");
        fprintf(stdout,"\t-h, --help                           Display this information.\n");
        fprintf(stdout,"\t-V, --version                        Display this program's version number.\n");
        fprintf(stdout,"\n");
        fprintf(stdout,"%s",bugs_banner);
        return;
}


void main(int argc, char **argv) {
	int c,option_index;
	int show_syscalls = FALSE;
	int show_received_payload = FALSE;	
	char *interface = NULL;
	int cpu = -1;

        while((c = getopt_long(argc,argv,short_options,
                            long_options, &option_index)) != -1) {
                switch (c) {
                        case 'p':
                               	show_received_payload = TRUE; 
                                break;
                        case 'c':
                               	cpu = atoi(optarg); 
                                break;
                        case 'i':
                               	interface = optarg; 
                                break;
                        case 'h':
                                usage(argv[0]);
                                exit(0);
                        case 'v':
                                fprintf(stdout,"%s %s\n",POLYVACCINE_DETECTION_ENGINE_NAME,VERSION);
                                fprintf(stdout,"%s",version_banner);
                                exit(0);
                        default:
                                abort ();
                }
        }

	PODT_Init(interface);

	if(cpu>=0)
		PODT_SetCpu(cpu);

	signal(SIGINT,sigquit);

	PODT_Run();
	return;
}
