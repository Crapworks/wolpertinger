/*
 * This file is part of the wolpertinger project.
 *
 * Copyright (C) 2003-2009 Christian Eichelmann <ceichelmann@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <time.h>
#include <sys/types.h>
#include <ctype.h>
#include <getopt.h>

#include <fcntl.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H
#include <netinet/tcp.h>
#define NETINET_TCP_H
#endif

#include <poll.h>
#include <signal.h>

#include "shared.h"
#include "ipc.h"
#include "drone.h"
#include "main.h"
#include "database.h"

drone_list dl; /* praise the magic drone list object */

uint8_t send_child_sync = 0; /* sender process synchronized */
uint8_t recv_child_sync = 0; /* listener process synchronized */

/* scan infos for database backend */
struct info scan_info;

/* global informations */
struct global_informations global;

/* get children sync signals */
void s_child_sync(int arg) {
	send_child_sync = 1;
}

void r_child_sync(int arg) {
	recv_child_sync = 1;
}

/* Catch up SIGINT and clean up */
void sigint(int sig) {
	MSG(MSG_WARN, "caught SIGINT: cleaning up...\n");
	exit(1);
}

int main(int argc, char *argv[]) 
{
	struct timeb start_time, stop_time, est_stop_time;
	struct sigaction sa;

	uint32_t chld_timeout = 0;
	uint32_t total_ports = 0;
	uint32_t total_pps = 0;
	
	/* signal handler for SIGINT */
	signal(SIGINT, sigint);

	/* initialize global */
	bzero(&global, sizeof(struct global_informations));
	
	/* signal handler for children in single mode */
	signal(WOLPER_CHLD_SENDER_SYNC, s_child_sync);	
	signal(WOLPER_CHLD_LISTENER_SYNC, r_child_sync);	

	/* save commandline */
	dl.save_cmd_line(argc, argv);
	
	/* open database */
	db_open();

	/* parse commandline options */
	get_options(argv, argc); 

	/* clear screen */
	cls();
	gotoxy (0, 0);
	
	/* beta -- working but we need unix domain sockets first */
	if (dl.get_local()) {
		// Should be stable enough. No more warnings.
		// MSG(MSG_WARN, "WARNING: local mode is currently *BETA* It may SEGFAULT or even open the gates to hell.\n");
		MSG(MSG_DBG, "Starting wolpertinger WITHOUT drones. Forking one sender and one listener drone.\n")
		
		if (getuid()) { MSG(MSG_ERR, "you need r00t privileges to run wolpertinger (in local mode)\n"); }

		/* fork sender/listener drone */
		fork_drones ();		

		/* wait for children to sync */
		chld_timeout = tv2long(NULL) + CHLD_SYNC_TIMEOUT;
		while (send_child_sync  < 1 && recv_child_sync < 1) {
			if (tv2long(NULL) > chld_timeout) {
				MSG(MSG_ERR, "timeout while waiting for childs to SYNC with master\n");
			}
		}

		// let the drones setup the unix domain sockets
		sleep(1);
	}
	
	/* print banner */
	MSG(MSG_USR, "Starting %s %s at %s\n", MY_NAME, MY_VERSION, get_time_str());	

	/* placeholder for sender statistics */
	MSG(MSG_VBS, "\n\n\n");
	
	/* connect to all drones */
	if (!dl.connect()) {
		MSG(MSG_ERR, "can not connect to at least one sender and one listener drone\n");
	}
	
	/* challenge response authentication */
	if (!dl.authenticate()) {
		MSG(MSG_ERR, "can not authenticate with at least one sender and one listener drone\n");
	}

	/* send workunits to drones */
	dl.distribute_workunits();
	
	/*  add listener address to scan */
	db_set_listener(dl.get_listener_addr());
	
	/* fill scan_info structure */
	scan_info.num_ports = dl.get_num_ports();
	scan_info.num_hosts = dl.get_num_hosts();
	scan_info.pps = dl.get_pps();
	scan_info.source_port = dl.get_sport();
	scan_info.source_ip = dl.get_listener_addr();
	
	if (scan_info.scan_tag == NULL && global.use_database) {
		printf("[?] enter an identifier for this scan (max. %d characters): ", MAX_TAGNAME_LEN);
		scan_info.scan_tag = (char *) safe_zalloc(MAX_TAGNAME_LEN + 1);
		fgets(scan_info.scan_tag, MAX_TAGNAME_LEN, stdin);

		/* remove newline */
		if(scan_info.scan_tag[strlen(scan_info.scan_tag) - 1] == '\n')
			scan_info.scan_tag[strlen(scan_info.scan_tag) - 1] = 0;			

		MSG(MSG_VBS, "\n");
		
	}

	/* set savepoint for database rollback when -q flag is used */
	if (!global.use_database) {
		MSG(MSG_DBG, "scan will be removed from database after completion.\n");
		db_set_savepoint();
	}
	
	/* start-time of scan */
	ftime(&start_time); 

	/* create scan in database */
	db_create_scan(&start_time, &scan_info);

	/* calculate scan time */
	total_ports = ((dl.get_num_hosts() * dl.get_num_ports()) * dl.get_retry());
	total_pps = (dl.get_num_sender_drones () * dl.get_pps());
		
	est_stop_time.time = start_time.time + ( total_ports / total_pps ) + dl.get_timeout();
	est_stop_time.millitm = start_time.millitm + (((double)(total_ports % total_pps ) / (double)total_pps) * 1000);
		
	MSG(MSG_USR, " * estimated time for portscan: %s\n", get_scan_duration (&start_time, &est_stop_time));
	
	/* start the scan */
	dl.start_scan();	
						
	/* poll drones for events */
	dl.poll_drones();
	
	MSG(MSG_USR, "\nScan results:\n");
	
	/* print results */
	db_create_report(0);
	
	ftime(&stop_time); /* end-time of scan */
	
	/* close portscan in database */
	db_finish_scan(&stop_time);
	
	/* print footer */
	MSG(MSG_USR, "\nScan of %d %s on %d %s complete. Scan time: %s\n", dl.get_num_ports(), dl.get_num_ports() > 1 ? "ports" : "port", dl.get_num_hosts(), dl.get_num_hosts() > 1 ? "hosts" : "host", get_scan_duration(&start_time, &stop_time));


	/* remove scan from database if -q flag is used */
	if (!global.use_database) 
		db_rollback ();
	
	/* close database */
	db_close();
	
	return 0;		   
}

/*
 * parse commandline options
 */
int get_options(char *argv[], int argc) { 
	char arg;
	int option_index=0;
	bool drone_def = false;
	
	FILE *hostlist = NULL;
	FILE *dronelist = NULL;
	
	struct option long_options[] = {
		{"iL", required_argument, 0, 0},
		{"with-tcpops", no_argument, 0, 0},
		{"drone-list", required_argument, 0, 0},
		{"retry", required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	opterr=1;
	optind=1;

	scan_info.scan_tag = NULL;
	global.use_database = 1;

	while((arg = getopt_long_only(argc,argv,"L:s:p:g:D:t:hVvdq",long_options,&option_index)) != EOF) {
		switch(arg) {
		case 0:
			if(strcmp(long_options[option_index].name,"iL")==0) {
				if ( !(hostlist=fopen(optarg, "rb"))  ) {
					perror("open hostlist");
					exit(1);
				}
			}
			if(strcmp(long_options[option_index].name,"drone-list")==0) {
				if ( !(dronelist=fopen(optarg, "rb"))  ) {
					perror("open dronelist");
					exit(1);
				}
			}				
			if(strcmp(long_options[option_index].name,"with-tcpops")==0) {
				dl.set_tcpops(1);
			}		
			if(strcmp(long_options[option_index].name,"retry")==0) {
				dl.set_retry(atoi(optarg));
			}						
			break;
		case 'D':
			dl.add_dronestr (optarg);
			drone_def = true;
			break;
		case 'V': 
			printf("\n *** %s V. %s *** \n\n",MY_NAME,MY_VERSION); 
			exit(0);
			break;
		case 't':
			scan_info.scan_tag = strdup(optarg);
			break;
		case 'q':
			global.use_database = 0;
			break;
		case 'g':
			if (!isdigit((int)*optarg)) { MSG(MSG_ERR, "invalid sourceport given.\n"); }
			dl.set_sport(atoi(optarg));
			break;
		case 'p': 				
			if (*optarg == 'a')
				dl.add_portstr(strdup("1-65535"));
			else
				if (! dl.add_portstr(optarg)) {
					MSG(MSG_ERR, "inavlid port string: %s\n", optarg);
				}
			break;
		case 'v':
			dl.set_verb();
			global.verbose++;
			break;
		case 'L':
			if (!isdigit((int)*optarg)) { MSG(MSG_ERR, "invalid timeout given.\n"); }
			dl.set_timeout(atoi(optarg));
			break;
		case 'd':
			dl.set_debug();
			global.debug++;
			break;
		case 's':
			dl.set_pps(atoi(optarg));
			break;
		case 'h':
		case '?':
			help(argv[0]);
			break;
		}
	}
	
	/* get targets into the drones target array */
	if (hostlist || optind < argc) {
		/* read targets from file */
		if (hostlist) {
			get_hosts_from_file(hostlist);
		} 
		/* get hosts from commandline */
		while (optind < argc) {				
			//printf("num_host: %d [%s]\n", dl.add_hostexp (argv[optind]), argv[optind]);
			dl.add_hostexp(argv[optind++]);
		}
	} else {
		fprintf(stderr, "Nothing to scan? Fine... Goodby\n");
		exit(0);
	}

	/* read dronelist from file */
	if (dronelist) {
		get_drones_from_file(dronelist);
	}
	
	/* check for default values */
	if (!dl.get_num_ports()) {
		MSG(MSG_DBG, "using default ports from database\n");
		dl.add_portstr(db_get_default_ports());		
	}
	
	if (!dl.get_num_hosts ()) {
		MSG(MSG_ERR, "no valid targets found. exiting.\n"); /* Sollte nie passieren, da das ein paar Zeilen höher abgefangen wird */
	}

	if (!dl.get_sport()) {
		dl.set_sport ((rand () % 2600) + 2000);
		MSG(MSG_DBG, "setting sourceport: %d\n", dl.get_sport());
	}
	
	if (!dl.get_timeout()) {
		MSG(MSG_DBG, "using default timeout: 5 seconds\n");
		dl.set_timeout(5);
	}
	
	if (!dl.get_pps()) {
		MSG(MSG_DBG, "using default packet rate: 300pps\n");
		dl.set_pps(300);
	}	
	
	/* check for local use */
	if (!drone_def && !dronelist) {
		MSG(MSG_DBG, "no drones specified. using localmode and fork drone processes\n");
		dl.set_local();
		/* add listener drone */
		dl.add_drone(IDENT_LISTENER, 0, strdup(DEFAULT_PASS));
		/* add sender_drone */
		dl.add_drone(IDENT_SENDER, 0, strdup(DEFAULT_PASS));
	}
	
	return 0;
}

/*
 * HELP !!1
 */
void help(char *me) {
	printf("usage : %s [options] <targets>\n\n"
		"options:\n"
	    "  -D <drones>       : list of drones like ip:port,ip:port,...\n"
		"  -iL <filename>    : load hosts from file\n"
		"  -s <pps>          : packets per seconds\n"
		"  -p <port str>     : ports to scan (1-1000,2000, etc. a = all ports)\n"
		"  -g <source port>  : set source port for scan\n"
	    "  -L <seconds>      : time to wait after packet are sent\n"
	    "  -t <tagname>      : tag of the scan (identifier)\n"
		"  -d                : debug output\n"
		"  -q                : dont save scan in database\n"
	    "  -v                : verbose output\n"
		"  -V                : show version number ang exit\n"
		"  -h                : this help\n\n"
	    " --drone-list  <filename> : read drones from file\n"
	    " --retry <num>            : repeat packet scan <num> times\n"
	    " --with-tcpops            : Send packets with some TCP Options set\n\n"   
		"targets:\n"
		"  hostnames\n"
		"  ipadresses\n"
		"  cidr-notation\n"
	    "  ranges\n"
		"  example: 192.168.2.0/24 www.yahoo.com 192.168.10.222 127.0.0-1.10-20,30-40\n\n", me);
	exit(0);
}

void get_hosts_from_file(FILE *fd)
{
	char hostexp[MAX_HOSTNAME_LEN];
	
	int32_t hostexp_index = 0;
	int32_t ch;
	
	while((ch = getc(fd)) != EOF) {
		if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t' || ch == '\0') {
			if (hostexp_index == 0) continue;
			hostexp[hostexp_index] = '\0';
			dl.add_hostexp(hostexp);
			hostexp_index = 0;
		} else if (hostexp_index < sizeof(hostexp) / sizeof(char) -1) {
			hostexp[hostexp_index++] = (char) ch;
		} else {
			MSG(MSG_ERR, "One of the host_specifications from your input file is too long (> %d chars)\n", (int) sizeof(hostexp));	
		}
	}
	
	fclose(fd); 	
	
	return;
}


void get_drones_from_file(FILE *fd)
{
	char drone_entry[MAX_HOSTNAME_LEN];
	
	int32_t drone_index = 0;
	int32_t ch;
	
	while((ch = getc(fd)) != EOF) {
		if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t' || ch == '\0') {
			if (drone_index == 0) continue;
			drone_entry[drone_index] = '\0';
			dl.add_dronestr(drone_entry);
			drone_index = 0;
		} else if (drone_index < sizeof(drone_entry) / sizeof(char) -1) {
			drone_entry[drone_index++] = (char) ch;
		} else {
			MSG(MSG_ERR, "One of the drone specifications from your input file is too long (> %d chars)\n", (int) sizeof(drone_entry));
		}
	}
	
	fclose(fd); 	
	
	return;
}

void fork_drones(void) {
	bool f_listener = false;
	bool f_sender = false;

	pid_t p_listener;
	pid_t p_sender;

	char *newargv[10];
	uint8_t argc = 0;

	newargv[argc++] = strdup(PATH_DRONE);
	newargv[argc++] = strdup("-s");
	newargv[argc++] = strdup("-i");
	newargv[argc++] = dl.get_device();
	if (global.debug) newargv[argc++] = strdup("-d");
	
	if (!f_listener) {
		p_listener = fork();
		if (p_listener == 0) { /* i am the listener */
			newargv[argc++] = strdup("-L");
			newargv[argc] = NULL;
			char *newenviron[] = { NULL };
			execve(PATH_DRONE, newargv, newenviron);
		}
		f_listener = true;
	}

	if (!f_sender) {
		p_sender = fork();
		if (p_sender == 0) { /* i am the sender */
			newargv[argc++] = strdup("-S");
			newargv[argc] = NULL;
			char *newenviron[] = { '\0' };
			execve(PATH_DRONE, newargv, newenviron);
		}
		f_sender = true;
	}
}
