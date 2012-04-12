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
#include "polyfilter.h"
#include <getopt.h>
#include "callgrind.h"

static struct option long_options[] = {
        {"learning",	no_argument,       	0, 'l'},
        {"interface",  	required_argument, 	0, 'i'},
        {"hport",  	required_argument, 	0, 'p'},
        {"sport",  	required_argument, 	0, 's'},
        {"force-post", 	no_argument, 		0, 'f'},
        {"unknown", 	no_argument, 		0, 'u'},
        {"cache", 	no_argument, 		0, 'c'},
        {"stats", 	no_argument, 		0, 'S'},
        {"exit", 	no_argument, 		0, 'e'},
        {"help",    	no_argument, 		0, 'h'},
        {"version",    	no_argument, 		0, 'V'},
        {0, 0, 0, 0}
};

static char *short_options = "li:p:hVfuces:S";

static char *common_http_headers [] = {
	"GET /index.phtml HTTP/1.1",
	"GET /index.php HTTP/1.1",
	"GET /index.html HTTP/1.1",
	"GET /rss.php HTTP/1.1",
	"GET / HTTP/1.1",
	"OPTIONS / HTTP/1.1",
	"GET / HTTP/1.0",
	"POST /login.php HTTP/1.1",	
	"POST /login.php HTTP/1.0",	
	"POST /gateway.php HTTP/1.1",	
	"POST /gateway.php HTTP/1.0",	
	NULL
};

static char *common_http_parameters [] = {
	"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7",
	"Keep-Alive: 300",
	"Connection: keep-alive",
	"connection: Keep-Alive",
	"DNT: 1",
	"Accept-Language: es-ES,es;q=0.8",
	"X-Requested-With: XMLHTTPRequest",
	"Accept-Encoding: gzip, deflate",
	"Accept-Encoding: gzip,deflate,sdch",
	"User-Agent: Mozilla/5.0 (Ubuntu; X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0",
	"Accept: image/png,image/*;q=0.8,*/*;q=0.5",
	"Accept: */*",
	"Accept: text/html, */*; q=0.01",
	"Accept: text/plain, */*; q=0.01",
	"Content-Type: text/html",
	"Content-Encoding: gzip",
	NULL
};

static char *show_options = {
	"The options are:\n"
	"\t-i, --interface=<device>             Device or pcapfile.\n"
	"\t-e, --exit                           Exits when analisys is done(for pcapfiles).\n"
	"\t-S, --stats                          Show statistics.\n"
	"\n"
	"\tHTTP options\n"
	"\t-p, --hport=<port number>            Web-server port number (80 default).\n"
	"\t-f, --force-post                     Force the HTTP analyzer to analyze the post data content.\n"
	"\t-l, --learning                       Cache all the HTTP request on the HTTP cache.\n"
	"\t-u, --unknown                        Shows the unknown HTTP supported.\n"
	"\t-c, --cache                          Use common HTTP values on the cache to test cache effectivity.\n"
	"\n"
	"\tSIP options\n"
	"\t-s, --sport=<port number>            Sip-server port number (5060 default).\n"
	"\n"
	"\t-h, --help                           Display this information.\n"
	"\t-V, --version                        Display this program's version number.\n"
	"\n"
};

/* options of the daemon */
int show_statistics = FALSE;
int force_post = FALSE;
int show_unknown = FALSE;
int learning = FALSE;
int use_cache = FALSE;
int exit_on_pcap = FALSE;
int hport = 80;
int sport = 5060;

void sigquit(int signal) {

	POFR_Stop();
	if(show_statistics == TRUE) {
		POFR_Stats();
	}
	POFR_StopAndExit();
	return;
}

void usage(char *prog){
	fprintf(stdout,"%s %s\n",POLYVACCINE_FILTER_ENGINE_NAME,VERSION);
	fprintf(stdout,"Usage: %s [option(s)]\n",prog);
	fprintf(stdout,"%s",show_options);
        fprintf(stdout,"%s",bugs_banner);
        return;
}



void main(int argc, char **argv) {
	int i,c,option_index;
	char *source = NULL;
	char *value;

	while((c = getopt_long(argc,argv,short_options,
                            long_options, &option_index)) != -1) {
        	switch (c) {
           		case 'i':
             			source = optarg;
             			break;
           		case 'p':
             			hport = atoi(optarg);
             			break;
           		case 's':
             			sport = atoi(optarg);
             			break;
           		case 'c':
             			use_cache = TRUE;	
             			break;
           		case 'e':
             			exit_on_pcap = TRUE;	
             			break;
           		case 'u':
             			show_unknown = TRUE;
             			break;
           		case 'S':
             			show_statistics = TRUE;
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
				usage(argv[0]);
				exit(-1);
           	}
	}

	if(source == NULL) {
		usage(argv[0]);
		exit(0);
	}

	POFR_Init();

	signal(SIGINT,sigquit);
	//signal(SIGSEGV,sigquit);

	if(learning)
		POFR_SetLearningMode();

	/* Configuring the Http options */
	POFR_SetForceAnalyzeHTTPPostData(force_post);
	POFR_SetSource(source);
	POFR_SetHTTPSourcePort(hport);
	POFR_ShowUnknownHTTP(show_unknown);

	if(use_cache == TRUE) {
		value = common_http_parameters[0];
		i = 0;
		while(value!= NULL) {
			POFR_AddToHTTPCache(1,value);
			i ++;
			value = common_http_parameters[i];
		}	
		value = common_http_headers[0];
		i = 0;
		while(value!= NULL) {
			POFR_AddToHTTPCache(0,value);
			i ++;
			value = common_http_headers[i];
		}	
	}

	/* Configuring the SIP options */
	POFR_SetSIPSourcePort(sport);

	POFR_SetExitOnPcap(exit_on_pcap);

	POFR_Start();

	CALLGRIND_START_INSTRUMENTATION;
	POFR_Run();
  	CALLGRIND_STOP_INSTRUMENTATION;
  	CALLGRIND_DUMP_STATS;

	//POFR_Stop();
        if(show_statistics == TRUE) {
                POFR_Stats();
        }
	POFR_StopAndExit();
	return;
}
