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
#include <signal.h>
#include "polyengine.h"
#include <getopt.h>

static struct option long_options[] = {
        {"learning",	no_argument,       	0, 'l'},
        {"interface",  	required_argument, 	0, 'i'},
        {"port",  	required_argument, 	0, 'p'},
        {"force-post", 	no_argument, 		0, 'f'},
        {"help",    	no_argument, 		0, 'h'},
        {"version",    	no_argument, 		0, 'V'},
        {0, 0, 0, 0}
};

static char *short_options = "li:p:hVf";

void sigquit(int signal) {
	POEG_Stop();
	POEG_Stats();
	POEG_StopAndExit();
	return;
}

void usage(char *prog){
	fprintf(stdout,"%s %s\n",POLYVACCINE_FILTER_ENGINE_NAME,VERSION);
	fprintf(stdout,"Usage: %s [option(s)]\n",prog);
        fprintf(stdout,"The options are:\n");
        fprintf(stdout,"\t-i, --interface=<device>             Device or pcapfile.\n");
        fprintf(stdout,"\t-p, --port=<port number>             Web-server port number (80 default).\n");
        fprintf(stdout,"\t-f, --force-post                     Force the Http analyzer to analyze the post data content.\n");
	fprintf(stdout,"\t-l, --learning                       Cache all the HTTP request on the HTTP cache.\n");
	fprintf(stdout,"\n");
        fprintf(stdout,"\t-h, --help                           Display this information.\n");
        fprintf(stdout,"\t-V, --version                        Display this program's version number.\n");
        fprintf(stdout,"\n");
        fprintf(stdout,"%s",bugs_banner);
        return;
}

void main(int argc, char **argv) {
	int c,port,learning,option_index;
	char *source = NULL;
	int force_post;

	force_post = FALSE;
	learning = FALSE;
	port = 80;
	while((c = getopt_long(argc,argv,short_options,
                            long_options, &option_index)) != -1) {
        	switch (c) {
           		case 'i':
             			source = optarg;
             			break;
           		case 'p':
             			port = atoi(optarg);
             			break;
           		case 'l':
             			learning = TRUE;
             			break;
           		case 'f':
             			force_post = TRUE;
             			break;
			case 'h':
				usage(argv[0]);
				exit(0);
			case 'V':
				fprintf(stdout,"%s %s\n",POLYVACCINE_FILTER_ENGINE_NAME,VERSION);
				fprintf(stdout,"%s",version_banner);
           		default:
             			abort ();
           	}
	}

	if(source == NULL) {
		usage(argv[0]);
		exit(0);
	}

	POEG_Init();

	signal(SIGINT,sigquit);

	if(learning)
		POEG_SetLearningMode();

	POEG_SetForceAnalyzeHttpPostData(force_post);
	POEG_SetSource(source);
	POEG_SetSourcePort(port);
	//POEG_AddToHttpCache(0,"GET /dashboard HTTP/1.1");
	//POEG_AddToHttpCache(1,"Host: www.tumblr.com");
	POEG_Start();
	POEG_Run();

	POEG_Stop();
	POEG_Stats();
	POEG_StopAndExit();
	return;
}
