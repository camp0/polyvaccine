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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include "polyfilter.h"
#include <getopt.h>

#ifdef USE_VALGRIND
#include <valgrind/callgrind.h>
#endif

static struct option long_options[] = {
        {"learning",	no_argument,       	0, 'L'},
        {"interface",  	required_argument, 	0, 'I'},
        {"hport",  	required_argument, 	0, 'p'},
        {"sport",  	required_argument, 	0, 's'},
        {"dport",  	required_argument, 	0, 'd'},
        {"flows",  	required_argument, 	0, 'F'},
        {"enable",  	required_argument, 	0, 'E'},
        {"force-post", 	no_argument, 		0, 'f'},
        {"unknown", 	no_argument, 		0, 'u'},
        {"cache", 	no_argument, 		0, 'c'},
        {"gstats", 	no_argument, 		0, 'g'},
        {"hstats", 	no_argument, 		0, 'a'},
        {"stats", 	no_argument, 		0, 'S'},
        {"exit", 	no_argument, 		0, 'X'},
        {"dummy", 	required_argument, 	0, 'D'},
        {"help",    	no_argument, 		0, 'h'},
        {"version",    	no_argument, 		0, 'V'},
        {0, 0, 0, 0}
};

static char *short_options = "LI:p:hVF:fucE:Xs:Sd:D:ga";

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
	"\t-I, --interface=<device>             Device or pcapfile.\n"
	"\t-E, --enable=<analyzer list>         Enables the analyzers(http,sip,ddos).\n"
	"\t-X, --exit                           Exits when analisys is done(for pcapfiles).\n"
	"\t-S, --stats                          Show statistics.\n"
	"\t-D, --dummy                          Add dummy IP for updates caches.\n"
	"\t-L, --learning                       Caches all the information (update mode).\n"
	"\t-F, --flows                          Sets the number of flows of the flowpool to process(default 262144).\n"
	"\n"
	"\tHTTP options\n"
	"\t-p, --hport=<port number>            Web-server port number (80 default).\n"
	"\t-f, --force-post                     Force the HTTP analyzer to analyze the post data content.\n"
	"\t-u, --unknown                        Shows the unknown HTTP supported.\n"
	"\t-c, --cache                          Use common HTTP values on the cache to test cache effectivity(Testing).\n"
	"\t-a, --hstats                         Shows statistics in detail.\n"
	"\n"
	"\tSIP options\n"
	"\t-s, --sport=<port number>            Sip-server port number (5060 default).\n"
	"\n"
	"\tDDoS options\n"
	"\t-d, --dport=<port number>            Web-server port number (80 default).\n"
	"\t-g, --gstats                         Shows statistics in detail.\n"
	"\n"
	"\t-h, --help                           Display this information.\n"
	"\t-V, --version                        Display this program's version number.\n"
	"\n"
};

/* options of the daemon */
char *enable_analyzers = NULL; // String with the name of the analyzers to enable
int flows_on_pool = 0; // non set
char *dummy_ip = NULL;
int show_sip_statistics_level = 0;
int show_ddos_statistics_level = 0;
int show_http_statistics_level = 0;
int show_statistics_level = 0;
int force_post = FALSE;
int show_unknown = FALSE;
int learning = FALSE;
int use_cache = FALSE;
int exit_on_pcap = FALSE;
int hport = 8080;
int dport = 80;
int sport = 5060;

void sigquit(int signal) {

	POFR_Stop();
	if(show_statistics_level > 0 ) {
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
           		case 'I':
             			source = optarg;
             			break;
           		case 'p':
             			hport = atoi(optarg);
             			break;
           		case 'd':
             			dport = atoi(optarg);
             			break;
           		case 's':
             			sport = atoi(optarg);
             			break;
           		case 'F':
             			flows_on_pool = atoi(optarg);
             			break;
           		case 'E':
             			enable_analyzers = optarg;
             			break;
           		case 'c':
             			use_cache = TRUE;	
             			break;
           		case 'X':
             			exit_on_pcap = TRUE;	
             			break;
           		case 'u':
             			show_unknown = TRUE;
             			break;
           		case 'S':
             			show_statistics_level ++;
             			break;
           		case 'g':
             			show_ddos_statistics_level ++;
             			break;
           		case 'a':
             			show_http_statistics_level ++;
             			break;
           		case 'D':
             			dummy_ip = optarg;	
             			break;
           		case 'L':
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

	if(dummy_ip!= NULL)
		POFR_AddTrustedUser(dummy_ip);

	POFR_SetStatisticsLevel(show_statistics_level);
	POFR_SetSource(source);

	/* Configuring the Http options */
	POFR_SetForceAnalyzeHTTPPostData(force_post);
	POFR_SetHTTPSourcePort(hport);
	POFR_SetHTTPStatisticsLevel(show_http_statistics_level);
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

	if(flows_on_pool>0)
		POFR_SetInitialFlowsOnPool(flows_on_pool);

	if(enable_analyzers!=NULL)
		POFR_EnableAnalyzers(enable_analyzers);

	/* Configuring the DDoS options */
	POFR_SetDDoSSourcePort(dport);
	POFR_SetDDoSStatisticsLevel(show_ddos_statistics_level);

	/* Configuring the SIP options */
	POFR_SetSIPSourcePort(sport);

	POFR_SetExitOnPcap(exit_on_pcap);

	POFR_Start();

#ifdef USE_VALGRIND
	CALLGRIND_START_INSTRUMENTATION;
	POFR_Run();
  	CALLGRIND_STOP_INSTRUMENTATION;
  	CALLGRIND_DUMP_STATS;
#else
	POFR_Run();
#endif
	//POFR_Stop();
        if(show_statistics_level > 0) {
                POFR_Stats();
        }
	POFR_StopAndExit();
	return;
}
