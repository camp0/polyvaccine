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
        {"execution-path",	no_argument,      	0, 'p'},
        {"syscalls",  		no_argument,      	0, 's'},
        {"payload",  		no_argument,      	0, 'x'},
        {"block",  		no_argument,      	0, 'b'},
        {"help",        	no_argument,            0, 'h'},
        {"version",     	no_argument,            0, 'V'},
        {0, 0, 0, 0}
};

static char *short_options = "shVpxb";

void sigquit(int signal) {
        PODT_Destroy();
        return;
}

void usage(char *prog){
        fprintf(stdout,"%s %s\n",POLYVACCINE_DETECTION_ENGINE_NAME,VERSION);
        fprintf(stdout,"Usage %s [option(s)]\n",prog);
        fprintf(stdout,"The options are:\n");
        fprintf(stdout,"\t-s, --syscall                        Shows the available syscalls.\n");
        fprintf(stdout,"\t-p, --execution-path                 Shows the execution syscall path of the executions.\n");
        fprintf(stdout,"\t-x, --payload                        Shows the execution payload received by the daemon.\n");
        fprintf(stdout,"\t-b, --block                          Blocks the syscall detected and continue exexution path.\n");
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
	int show_execution_path = FALSE;
	int show_received_payload = FALSE;	
	int block_syscalls  = FALSE;

        while((c = getopt_long(argc,argv,short_options,
                            long_options, &option_index)) != -1) {
                switch (c) {
                        case 'x':
                               	show_received_payload = TRUE; 
                                break;
                        case 'b':
                               	block_syscalls = TRUE; 
                                break;
                        case 's':
                               	show_syscalls = TRUE; 
                                break;
                        case 'p':
                               	show_execution_path = TRUE; 
                                break;
                        case 'h':
                                usage(argv[0]);
                                exit(0);
                        case 'V':
                                fprintf(stdout,"%s %s\n",POLYVACCINE_DETECTION_ENGINE_NAME,VERSION);
                                fprintf(stdout,"%s",version_banner);
                                exit(0);
                        default:
                                abort ();
                }
        }

	PODT_Init();

	signal(SIGINT,sigquit);

	PODT_Run();
	return;
}
