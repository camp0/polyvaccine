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

void sigquit(int signal) {
	POEG_Stop();
	POEG_Stats();
	POEG_StopAndExit();
	return;
}

void usage(char *prog){
	fprintf(stdout,"%s\n",POLYVACCINE_FILTER_ENGINE_NAME);
	fprintf(stdout,"Usage %s -s <pcapfile/device> [OPTIONS]\n",prog);
	fprintf(stdout,"[OPTIONS]\n");
	fprintf(stdout,"\t-p --port <port>\n");
	fprintf(stdout,"\t-l --learning\n");
	fprintf(stdout,"\n");
	return;
}

void main(int argc, char **argv) {
	int c,port,learning;
	char *source = NULL;

	learning = FALSE;
	port = 80;
	while ((c = getopt (argc, argv, "s:p:l")) != -1){
        	switch (c) {
           		case 's':
             			source = optarg;
             			break;
           		case 'p':
             			port = atoi(optarg);
             			break;
           		case 'l':
             			learning = TRUE;
             			break;
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
