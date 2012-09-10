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
#include <time.h>
#include <sys/types.h>
#include <ctype.h>
#include <getopt.h>

#include <fcntl.h>
#include <poll.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "shared.h"
#include "ipc.h"
#include "drone.h"
#include "database.h"
#include "main.h"

extern struct global_informations global;

/*****************************************************
 *
 * drone object. beta testing
 *
 *****************************************************/

/* constructor(s) */
void drone::initialize(void)
{
	this->socket = 0;
	bzero(&this->my_addr, sizeof(struct in_addr));
	bzero(&this->my_stats, sizeof(struct ipc_sender_stats));
	bzero(this->my_addr_str, MAX_DIRNAME_LEN);
	bzero(this->drone_id, UUID_LEN);
	this->my_port = 0;
	this->my_type = 0;
	this->my_pass = NULL;
	this->debug = false;
	this->local = false;
	
	this->scan_pps = 0;
	this->scan_sport = 0;
	this->scan_secret = 0;
	this->scan_timeout = 0;
	this->scan_retry = 1;
	this->scan_tcpops = 0;
	
	this->port_workunit.clear();
	this->target_workunit.clear();
}

drone::drone()
{
	this->initialize();
	
	return;
}

drone::drone(uint32_t addr)
{
	this->initialize();
	
	this->my_addr.s_addr = addr;
	
	return;
}

drone::drone(uint32_t addr, uint16_t port)
{
	this->initialize();
	
	this->my_addr.s_addr = addr;
	this->my_port = port;
	if (!port) {
		this->local = true;
		snprintf(this->my_addr_str, MAX_DIRNAME_LEN - 1, "%s", addr == IDENT_LISTENER ? SOCKET_PATH_LISTENER : SOCKET_PATH_SENDER);
	} else {
		snprintf(this->my_addr_str, MAX_DIRNAME_LEN - 1, "%s", inet_ntoa(this->my_addr));
	}
	
	return;
}

drone::drone(uint32_t addr, uint16_t port, char *pass)
{
	this->initialize();
	
	this->my_addr.s_addr = addr;
	this->my_port = port;
	if (!port) {
		this->local = true;
		snprintf(this->my_addr_str, MAX_DIRNAME_LEN - 1, "%s", addr == IDENT_LISTENER ? SOCKET_PATH_LISTENER : SOCKET_PATH_SENDER);
	} else {
		snprintf(this->my_addr_str, MAX_DIRNAME_LEN - 1, "%s", inet_ntoa(this->my_addr));
	}
	this->my_pass = strdup(pass);
	
	return;
}

/* destructor */
drone::~drone()
{
	return;
}

/* add a new host workunit to the drone (struct targets) */
void drone::add_host_workunit(struct targets *tt)
{
	this->target_workunit.push_back(*tt);
	
	return;
}

/* add a new port workunit to the drone (struct ports) */
void drone::add_port_workunit(struct ports *pp)
{
	this->port_workunit.push_back(*pp);
	
	return;
}

/* 
 * add a new host workunit to the redistribution vector 
 * (only hosts are redistributed, ports are equal for all drones)
 */ 
void drone::add_redist_workunit(struct targets *tt)
{
	this->redist_workunit.push_back(*tt);
	
	return;
}

/* ipc connect to drone */
uint32_t drone::connect(void)
{
	if (this->local) this->socket = connect_ipc_socket(this->my_addr.s_addr == IDENT_LISTENER ? strdup(SOCKET_PATH_LISTENER) : strdup(SOCKET_PATH_SENDER), this->my_port);
	else this->socket = connect_ipc_socket(inet_ntoa(this->my_addr), this->my_port);
	
	if (this->socket == 0) {
		return 0;
	} else {
		/* nonblocking sockets are used */
		unblock_socket(this->socket);
	}	
	
	return this->socket;
}

/* CRAM-MD5 authentication */
uint32_t drone::authenticate(void)
{	
	char *digest;
	char *msg;
	char *challenge;	
	char *auth_str;
	struct ipc_message *ipc_m;
	bool save_cred = false;
	
	ipc_send_helo(this->socket);
	if (get_ipc_message(this->socket, &msg) == 0) {
		return 0;
	}
	
	ipc_m = (struct ipc_message *) msg;
	if (ipc_m->msg_type != MSG_CHALLENGE) {
		return 0;
	}

	/* get uuid */
	memcpy(this->drone_id, msg + sizeof(struct ipc_message), UUID_LEN);

	char uuid_str[UUID_STR_LEN], *p;
	int i;

	for (i=0, p = uuid_str; i < UUID_LEN; i++, p += 2) {
		sprintf(p, "%02x", this->drone_id[i]);
	}
	MSG(MSG_DBG, "[uuid] %s\n", uuid_str);
	
	/* get drone challenge */
	challenge = strndup(msg + sizeof(struct ipc_message) + UUID_LEN, ipc_m->msg_len - (sizeof(struct ipc_message) + UUID_LEN));
	MSG(MSG_DBG, "[auth] got challenge: %s\n", challenge);

	if (!this->local) {		
		/* check for drone credentials in database */
		char **drone_credentials;
		if (drone_credentials = db_get_drone_credentials(this->drone_id)) {
			this->my_user = drone_credentials[0];
			this->my_pass = drone_credentials[1];
		} else {				
			/* get username and password from stdin */
			this->my_user = (char *) safe_zalloc (MAX_USERNAME_LEN + 1);
			this->my_pass = (char *) safe_zalloc (MAX_PASSWORD_LEN + 1);
			
			fprintf(stderr, "[*] Username for drone %s:%d (max. %d characters) : ", this->my_addr_str, this->my_port, MAX_USERNAME_LEN);
			fgets(this->my_user, MAX_USERNAME_LEN, stdin);				

			/* remove newline */
			if(this->my_user[strlen(this->my_user) - 1] == '\n')
				this->my_user[strlen(this->my_user) - 1] = 0;	

			fprintf(stderr, "[*] Password for drone %s:%d (max. %d characters) :", this->my_addr_str, this->my_port, MAX_PASSWORD_LEN);
			strncpy(this->my_pass, getpass(" "), MAX_PASSWORD_LEN);	

			save_cred = true;
		}
		/* generate HMAC-MD5 digest */
		digest = generate_digest(challenge, strlen(challenge), this->my_pass, strlen(this->my_pass));		
		auth_str = (char *)safe_zalloc (strlen(digest) + strlen(this->my_user) + 2);		
		sprintf(auth_str, "%s %s", this->my_user, digest);	
	} else {
		/* generate HMAC-MD5 digest */
		digest = generate_digest(challenge, strlen(challenge), this->my_pass, strlen(this->my_pass));		
		auth_str = (char *)safe_zalloc(strlen(digest) + strlen(DEFAULT_USER) + 2);		
		sprintf(auth_str, "%s %s", DEFAULT_USER, digest);
	}
	
	ipc_send_auth(this->socket, auth_str);
	if (get_ipc_message(this->socket, &msg) == 0) {
		return 0;
	}

	ipc_m = (struct ipc_message *) msg;	
	if (ipc_m->msg_type != MSG_READY) {
		return 0;
	}		

	/* write informations into database */
	if (save_cred)
		db_add_drone_credentials (this->drone_id, this->my_user, this->my_pass);
	
	return 1;
}

/* initialise drone and check drone type */
uint32_t drone::init(void)
{
	char *msg;
	struct ipc_message *ipc_m;
	
	ipc_send_ident_request(this->socket);
	if (get_ipc_message(this->socket, &msg) == 0) {
		return 0;
	}
	
	ipc_m = (struct ipc_message *) msg;
	if (ipc_m->msg_type != MSG_IDENT_REPLY) {
		return 0;
	}

	this->my_type = (uint8_t) *(msg + sizeof(struct ipc_message));
	MSG(MSG_DBG, "drone type: %d\n", this->my_type);
	if (this->my_type == IDENT_LISTENER) {
		msg += + sizeof(struct ipc_message) + 1;
		this->listener_addr = *((uint32_t *)msg);
		return IDENT_LISTENER;
	} else if (this->my_type == IDENT_SENDER) {
		return IDENT_SENDER;
	} else { /* WTF? */
		return 0;
	}
	return 0;
}

/* start drone */
uint32_t drone::start(void)
{
	char *msg;
	struct ipc_message *ipc_m;

	ipc_send_start(this->socket);
		
	if (get_ipc_message(this->socket, &msg) == 0) {
		return 0;
	}
	
	ipc_m = (struct ipc_message *) msg;
	switch(ipc_m->msg_type) {
		case MSG_BUSY:
			/* store drone in database */
			db_add_drone(this->my_addr.s_addr, this->my_port, this->my_type);	

			MSG(MSG_DBG, "[ipc in] BUSY (drone is working)\n");			
			break;
		case MSG_ERROR:
			this->print_error(msg);
			return 0;
			break;
		default:
			return 0;
			break;
	}

	return 1;
}

/* stop drone */
uint32_t drone::stop(void)
{
	/* FIXME */
	return 0;
}

/* print IPC error message */
void drone::print_error(char *msg)
{
	printf("*** [drone error: '%s' from %s:%d ] ***\n", (msg + sizeof(struct ipc_message)),this->my_addr_str, this->my_port);

	return;
}

uint32_t drone::send_workload(void)
{
	char *payload;
	char *p;
	char *msg = NULL; /* IPC Response Message */

	struct ipc_message *ipc_m;
	struct ipc_sendunit *ipc_s;
	struct ipc_listenunit *ipc_l;
	
	struct ports *pp;
	struct targets *tt;
	
	uint32_t port_data_len=0;
	uint32_t ip_data_len=0;
	uint32_t payload_size=0;
	uint32_t r_msg_len=0;
	
	/*** create workunit (LISTENER) ***/
	if (this->my_type == IDENT_LISTENER)  {
		payload_size=sizeof(struct ipc_message) + sizeof(struct ipc_listenunit);
		payload = (char *)malloc(payload_size);
		p = payload;

		/* Message Header */
		ipc_m = (struct ipc_message *) p;
		ipc_m->msg_type = MSG_WORKUNIT;
		ipc_m->msg_len = payload_size;
		p += sizeof(struct ipc_message);

		/* Listenunit Header */
		ipc_l = (struct ipc_listenunit *) p;
		ipc_l->sport=this->scan_sport;
		ipc_l->secret = this->scan_secret;
		ipc_l->timeout=this->scan_timeout;

	/*** create workunit (SENDER) ***/	
	} else if (this->my_type == IDENT_SENDER) {
		ip_data_len = this->target_workunit.size();
		port_data_len = this->port_workunit.size();
		
		payload_size=sizeof(struct ipc_message) + sizeof(struct ipc_sendunit) + (sizeof(struct ports) * port_data_len) + (sizeof(struct targets) * ip_data_len);
		
		payload = (char *)malloc(payload_size);
		p = payload;

		/* Message Header */
		ipc_m = (struct ipc_message *) p;
		ipc_m->msg_type = MSG_WORKUNIT;
		ipc_m->msg_len = payload_size;
		p += sizeof(struct ipc_message);

		/* Sendunit Header */
		ipc_s = (struct ipc_sendunit *) p;
		ipc_s->pps = this->scan_pps;
		ipc_s->secret = this->scan_secret;
		ipc_s->listener_addr = this->listener_addr;
		ipc_s->port_data_len = port_data_len;
		ipc_s->ip_data_len = ip_data_len;
		ipc_s->sport = this->scan_sport;
		ipc_s->retry = this->scan_retry;
		ipc_s->tcpops = this->scan_tcpops;		
		p += sizeof(struct ipc_sendunit);	

		/* Get Targets for this drone */			
		p += this->create_target_payload(p);
		
		/* Get Ports for this drone */
		p += this->create_port_payload(p);			
		
	} else {
		return 0; /* Failed */
	}

	/* send workunit to drone */
	MSG(MSG_DBG, "[ipc out] WORKUNIT\n");
	send_ipc_msg(this->socket, payload, ipc_m->msg_len);
	
	free(payload);
	
	/* check ipc response  */
	r_msg_len = get_ipc_message(this->socket, &msg);

	if (r_msg_len > 0) {

		ipc_m = (struct ipc_message *) msg;

		switch(ipc_m->msg_type) {
			case MSG_READY:
				MSG(MSG_DBG, "[ipc in] READY\n");
				return r_msg_len;
				break;
			case MSG_ERROR:
				this->print_error(msg);
				return 0;
				break;
			default:
				MSG(MSG_DBG, "[drone] invalid response\n");
				return 0;
				break;
		}
	} else {
		MSG(MSG_DBG, "[drone] can not read response from drone\n");
		return 0; /* Failed */
	}
	
	return 0;
}

/*
 * used for re-distributing targets to drones during scan
 */
uint32_t drone::send_new_workload(void)
{
	char *payload;
	char *p;
	char *msg = NULL; /* IPC Response Message */

	struct ipc_message *ipc_m;
	struct ipc_sendunit *ipc_s;
	
	struct targets *tt;
	
	uint32_t port_data_len=0;
	uint32_t ip_data_len=0;
	uint32_t payload_size=0;
	uint32_t r_msg_len=0;
	uint32_t target_num = 0;
	
	if (this->my_type == IDENT_SENDER) {
		ip_data_len = this->redist_workunit.size();
		/* port_data_len = this->port_workunit.size(); -- no new ports needed for redistribution */
		port_data_len = 0;
		
		payload_size=sizeof(struct ipc_message) + sizeof(struct ipc_sendunit) + (sizeof(struct ports) * port_data_len) + (sizeof(struct targets) * ip_data_len);
		
		payload = (char *)malloc(payload_size);
		p = payload;

		/* Message Header */
		ipc_m = (struct ipc_message *) p;
		ipc_m->msg_type = MSG_WORKUNIT;
		ipc_m->msg_len = payload_size;
		p += sizeof(struct ipc_message);

		/* Sendunit Header */
		ipc_s = (struct ipc_sendunit *) p;
		ipc_s->pps = this->scan_pps;
		ipc_s->secret = this->scan_secret;
		ipc_s->listener_addr = this->listener_addr;
		ipc_s->port_data_len = port_data_len;
		ipc_s->ip_data_len = ip_data_len;
		ipc_s->sport = this->scan_sport;
		ipc_s->retry = this->scan_retry;
		ipc_s->tcpops = this->scan_tcpops;
		p += sizeof(struct ipc_sendunit);	

		/* Get Targets for this drone */			
		for (target_num=0; target_num < this->redist_workunit.size(); target_num++) {									
			tt = (struct targets *)p;
			tt->ipaddr = this->redist_workunit[target_num].ipaddr;
			tt->range = this->redist_workunit[target_num].range;		
			p += sizeof(struct targets);
		}
		
		/* no new ports required for redistribution --
		p += this->create_port_payload(p); */
		
	} else {
		return 0; /* Failed */
	}

	/* 
	 * send new workunits to sender drones. they will add them to their existing
	 * workunits on the fly (realy cool, isn't it?)
	 */
	MSG(MSG_DBG, "[ipc out] WORKUNIT\n");
	send_ipc_msg(this->socket, payload, ipc_m->msg_len);
	
	free(payload);
	
	/* check ipc response  */
	r_msg_len = get_ipc_message(this->socket, &msg);

	if (r_msg_len > 0) {

		ipc_m = (struct ipc_message *) msg;

		switch(ipc_m->msg_type) {
			case MSG_READY:
				MSG(MSG_DBG, "[ipc in] READY\n");
				return r_msg_len;
				break;
			case MSG_ERROR:
				this->print_error(msg);
				return 0;
				break;
			default:
				MSG(MSG_DBG, "[drone] invalid response\n");
				return 0;
				break;
		}
	} else {
		MSG(MSG_DBG, "[drone] can not read response from drone\n");
		return 0; /* Failed */
	}
	
	return 0;
}

/*
 * create a target payload for the sender workunit
 * the data is put to the *payload address
 * the bytes added to the workunit are returned
 */
uint32_t drone::create_target_payload(char *payload)
{
	uint32_t i, ret_bytes = 0;
	char *p = payload;
	struct targets *tt;

	struct in_addr start_addr, end_addr;
	char ipaddr_start[16];
	char ipaddr_end[16];	
	for (i=0; i<this->target_workunit.size(); i++) {
		start_addr.s_addr = this->target_workunit[i].ipaddr;
		end_addr.s_addr = htonl(ntohl(this->target_workunit[i].ipaddr) + this->target_workunit[i].range - 1);

		/* convert IP addresses to strings */
		inet_ntop(AF_INET, &start_addr, ipaddr_start, 16);	
		inet_ntop(AF_INET, &end_addr, ipaddr_end, 16);	
		MSG(MSG_DBG, "[workload] [hosts] (drone: %s:%d) [%d] -> from: %s to: %s\n", this->my_addr_str, this->my_port, i+1, ipaddr_start, ipaddr_end);
		
		tt = (struct targets *)p;
		tt->ipaddr = this->target_workunit[i].ipaddr;
		tt->range = this->target_workunit[i].range;
		
		p += sizeof(struct targets);
		ret_bytes += sizeof(struct targets);		
	}
	
	return ret_bytes;
}

/*
 * create a port payload for the sender workunit
 * the data is put to the *payload address
 * the bytes added to the workunit are returned
 */
uint32_t drone::create_port_payload(char *payload)
{
	uint32_t i, ret_bytes = 0;

	char *p;
	struct ports *pp;	
	
	p = payload;
		
	for (i=0; i<this->port_workunit.size(); i++) {
		
		pp = (struct ports *)p;
		pp->port = this->port_workunit[i].port;
		pp->range = this->port_workunit[i].range;		

		MSG(MSG_DBG, "[workload] [ports] (drone: %s:%d) [%d] -> from: %d to %d\n",this->my_addr_str, this->my_port, i + 1, pp->port, pp->port + (pp->range));
		
		p += sizeof(struct ports);
		ret_bytes += sizeof(struct ports);
		
	}	
	
	return ret_bytes;	
}

/********************************************************
 * 
 * drone list object: beta testing
 *
 ********************************************************/

/* constructor */
drone_list::drone_list()
{
	this->dl.clear();
	this->num_listen_drones = 0;
	this->num_send_drones = 0;
	this->debug = false;
	this->verb = false;
	this->local = false;
	
	this->scan_pps = 0;
	this->scan_sport = 0;
	this->scan_timeout = 0;			
	this->scan_retry = 1;
	this->scan_tcpops = 0;	

	this->scan_cmd_line = NULL;
	
	/* Zufallsgenerator initialisieren */
	srand(time(NULL));

	this->scan_secret = get_rnd_uint32();
	
	return;
}

/* destructor */
drone_list::~drone_list()
{
	return;
}

/* add drone to list */
uint32_t drone_list::add_drone(uint32_t addr, uint16_t port, char *pass) 
{
	drone tmpdrone(addr, port, pass);
	
	dl.push_back(tmpdrone);
	
	return 0;
}

/* add host expresseion to target list */
uint32_t drone_list::add_hostexp (char *hostexp)
{
	char *target_net = NULL;
	char addr_buff[16];	
	char *buffer = strdup(hostexp);
	char *s = NULL;
	char *endptr;
	char *p;
	
	static struct targets *target = this->target_buffer;	
	struct in_addr startaddr, endaddr, tmpaddr;
	struct hostent *t;
	
	uint32_t i, x, y, z;
	uint32_t suffix = 0;
	uint32_t netmask = 0;	
	uint32_t dots = 0;
	uint32_t range_start = 0;
	uint32_t range_end = 0;
	uint32_t ip_count = 0;
	in_addr_t ip_address;
	
	target_buffer_count = 0;									// set target buffer count to zero 

	vector <struct s_range> range[4];
	struct s_range tmprange;
	
	p = buffer;
	
	if(is_ip(hostexp)) { /* ist es eine einzelne ip? */
		if(!(inet_aton(hostexp, &tmpaddr))) {
			MSG(MSG_ERR, "invalid target ip: %s\n", hostexp);
			return 0;
		} else {
			target->ipaddr = tmpaddr.s_addr;
			target->range = 1;
			target++;
			this->target_buffer_count++;
			this->total_ip_count++;
		}	
	} else if (is_ip_cidr (hostexp)) { /* ist es eine CIDR notation? */
		target_net = strtok(buffer, "/");
		s = strtok(NULL, "");    /* find the end of the token from hostexp */
		suffix  = ( s ) ? atoi(s) : 32;
		
		if (suffix < 0 || suffix > 32) {
			MSG(MSG_ERR, "Illegal netmask value (%d), must be /0 - /32 .  Assuming /32 (one host)", suffix);
			suffix = 32;
		}

		if (suffix) {
			ip_address = inet_addr(target_net);

			// check for invalid IP addresses due to invalid input
			if ((ip_address == 0x0) || (ip_address == 0xffffffff)) {
				MSG(MSG_ERR, "invalid ip addr: %s\n", target_net);
				return 0;
			}
		
			ip_count = (1 << (32 - suffix)) - 2;							

			netmask = ((1 << suffix) - 1) << (32 - suffix);	
			ip_address = htonl(ntohl(ip_address) & netmask);

			target->ipaddr = htonl(ntohl(ip_address) + 1);
			target->range = ip_count;
			target++;

			this->target_buffer_count++;
			this->total_ip_count += ip_count;			
		} else {
			fatal("error while processing target expression: %s", hostexp);
		}
	} else if (is_ip_range (hostexp)) { /* ist es ein ip-range? */
		do {
			if (*p == '.') {
				if (dots > 3) { MSG(MSG_ERR, "Invalid Target expression: %s\n", hostexp); }
				tmprange.start = range_start;
				tmprange.end = range_end ? range_end : range_start;
				range[dots].push_back(tmprange);

				range_end = 0;
				range_start = 0;
				dots++;
				p++;
			}
			if (*p == '-') {
				if (!range_start) { MSG(MSG_ERR, "Invalid IP Range: %s\n", hostexp); }
				p++;
			}
			if (*p == ',') {
				tmprange.start = range_start;
				tmprange.end = range_end ? range_end : range_start;
				range[dots].push_back(tmprange);				
				
				range_end = 0;
				range_start = 0;
				p++;
			}
			if (isdigit((int) *p)) {
				if (!range_start) range_start = strtol(p, &endptr, 10);
				else if (!range_end) range_end = strtol(p, &endptr, 10);
				else { MSG(MSG_ERR, "Invalid Range Spec\n"); }
				
				p=endptr;
			}
			if (*p == '\0') {
				if (dots==3) {
					tmprange.start = range_start;
					tmprange.end = range_end ? range_end : range_start;
					range[dots].push_back(tmprange);
				} else { 
					MSG(MSG_ERR, "Invalid IP Range: %s\n", hostexp);
				}
			}		
		} while (*p);
		int a,b,c,d;

		for (i=0; i < range[0].size(); i++) {
			for (x=0; x < range[1].size(); x++) {
				for (y=0; y < range[2].size(); y++) {
					for (z=0; z < range[3].size(); z++) {
						for (a=range[0][i].start; a <= range[0][i].end; a++) {
							for (b=range[1][x].start; b <= range[1][x].end; b++) {
								for (c=range[2][y].start; c <= range[2][y].end; c++) {							
									/* create ip range for workunit */
									snprintf(addr_buff, sizeof(addr_buff), "%d.%d.%d.%d\n",a, b, c, range[3][z].start);
									
									target->ipaddr = (uint32_t) inet_addr(addr_buff);
									target->range = (uint32_t) (range[3][z].end - range[3][z].start) + 1;																		
									
									this->target_buffer_count++;
									this->total_ip_count += target->range;

									target++;
								}
							}
						}
					}
				}
			}
		}		
	} else { /* dann muss es wohl ein hostname sein */
		if ((t = gethostbyname(hostexp))) {
			uint16_t count=0;
			memcpy(&(tmpaddr), t->h_addr_list[0], sizeof(struct in_addr));
			while (t->h_addr_list[count]) count++;
			if (count > 1) {
				MSG(MSG_WARN, "Warning: Hostname %s resolves to %d IPs. Using %s.\n", hostexp, count, inet_ntoa(*((struct in_addr *)t->h_addr_list[0])));
			}
			
			target->ipaddr = tmpaddr.s_addr;
			target->range = 1;
			target++;
			this->total_ip_count += target->range;target_buffer_count++;
			this->total_ip_count += target->range;total_ip_count++;
		} else {
			MSG(MSG_ERR, "can't resolve hostname: %s\n", hostexp);
			return 0;
		}
	}		

	return this->total_ip_count;
}

/* add portstring to portlist */
uint32_t drone_list::add_portstr(char *portstr)
{
	char *s = strdup(portstr);								// work string
	char *p;													// general purpose pointer
	char *token;												// token
	struct ports *port;											// pointer to port buffer
	uint16_t port_number, port_number2;							// IP ports
	uint16_t range;												// port range
	uint32_t i, pass;							// various counters

	port = this->port_buffer;											// set port pointer to global port buffer
	this->port_buffer_count = 0;										// set port buffer count to zero 
	this->total_port_count = 0;										// set IP port counter to zero
		
	// tokenize the target string
	i = 0; 
	pass = 0; 
	while (i < MAX_PORTS) { // parse until port max. is reached or nothing more to parse
		pass++;													// increment pass counter
		
		// split target string in comma-separated tokens
		if (1 == pass) 
			token = strtok(s, ",");								// call this on first pass 
		else 
			token = strtok(NULL, ",");							// call this on all other passes
			
		if (token == NULL)										// no more tokens?  
			break;												// so we are done
	
		// is the port input a range?
		p = strchr(token, '-'); 
		if (p != NULL) { 
			*p = '\0';											// set terminating zero

			// convert strings to integers
			port_number = atoi(token); 
			port_number2 = atoi(p + 1);
	
			// check for invalid IP ports due to invalid input
			if ((port_number == 0) || (port_number2 == 0)) 
				return 0;
		
			// if the range is not well-formatted, return
			if (port_number > port_number2) 
				return 0;										// return zero IP ports

			range = port_number2 - port_number;					// calculate port range
			this->total_port_count += port_number2 - port_number + 1;	// increment total IP port counter
	
			// save target information in global target buffer
			port->port = port_number;			    		    // save start IP port in host byte order 
			port->range = range;								// set port range
			port++;												// point to next element in port buffer 
			this->port_buffer_count++;								// increment port buffer count 
		} else {
			// convert token to IP port
			port_number = atoi(token);							// convert token to IP port

			// check for invalid IP port due to invalid input
			if (port_number == 0)
				return 0;			
			
			this->total_port_count++;									// increment total IP port counter
	
			// save target information in global target buffer
			port->port = port_number;					        // save startIP port in host byte order 
			port->range = 0;									// set count to 1 for a single port 
			port++;												// point to next element in port buffer 
			this->port_buffer_count++;								// increment port buffer count 
		}
		
		i++;
	} 
	
	free(s);
	
	return this->total_port_count;
}

/* connect to all drones */
uint32_t drone_list::connect(void)
{
	uint32_t i = 0;	
	
	for (i=0; i < this->dl.size(); i++) {
		if (this->debug) dl[i].set_debug();
		/* try to connect to drone */
		if(!this->dl[i].connect()) this->remove_drone (i--, "connection refused");
	}

	/* drone check */
	if (this->dl.size() >= 2) return this->dl.size();
	else return 0;
}

/* authenticate with all drones */
uint32_t drone_list::authenticate(void)
{
	uint32_t i = 0;
	uint32_t drone_type = 0;
	struct in_addr addr;
	
	for (i=0; i < this->dl.size(); i++) {
		/* try to authenticate with drones*/
		if (!this->dl[i].authenticate()) { 
			this->remove_drone (i--, "authentication failed"); 
			continue; 
		}

		/* try to get drone type */
		drone_type = this->dl[i].init();

		/* we got a sender drone here */
		if (drone_type == IDENT_SENDER) {
			this->num_send_drones++;
			
			/* informationen über den scan an die drone übergeben */
			dl[i].set_pps(this->scan_pps);
			dl[i].set_secret(this->scan_secret);
			dl[i].set_sport(this->scan_sport);
			dl[i].set_retry(this->scan_retry);
			dl[i].set_tcpops(this->scan_tcpops);
		}

		/* this one is a listener drone */
		else if (drone_type == IDENT_LISTENER) { 
			this->num_listen_drones++;
			
			/* informationen über den scan an die drone übergeben */		
			dl[i].set_timeout(this->scan_timeout);
			dl[i].set_secret(this->scan_secret);
			dl[i].set_sport(this->scan_sport);					
			
			this->listener_sock = dl[i].get_socket();
			this->listener_addr = dl[i].get_listener_addr();
			
			if (this->debug) {
				addr.s_addr = this->listener_addr;
				MSG(MSG_DBG, "got listener address: %s\n", inet_ntoa(addr));
			}
			    
		}

		/* öhm... what? hey, cool. a new drone type Oo */
		else {
			this->remove_drone(i--, "unknown drone type returned");
		}
	}

	/* set listener_addr for all sender drones */
	for (i=0; i < this->dl.size(); i++) {
		if (dl[i].get_type() == IDENT_SENDER) dl[i].set_listener_addr(this->listener_addr);
	}
	
	/* drone check */
	if (this->num_send_drones && this->num_listen_drones) return this->dl.size();
	else return 0;
}

/* distrubite workunits to all drones */
uint32_t drone_list::distribute_workunits(void)
{
	uint32_t i = 0;
	uint32_t target_num = 0;
	uint32_t port_num = 0;
	uint32_t sender_idx = 0;
	
	struct targets tt;
	struct ports pp;	

	/* loadbalancing */ 
	this->balance_workunit();
	
	for (i=0; i < dl.size(); i++) {		
		if (dl[i].get_type() == IDENT_LISTENER) {
			dl[i].send_workload();
			continue; /* skip listener drones, they need no host based workunits */
		}
		
		for (target_num=0; target_num < this->drone_distribution_idx[sender_idx]; target_num++) {						
			tt.ipaddr = target_buffer[this->drone_distribution[sender_idx][target_num]].ipaddr;
			tt.range = target_buffer[this->drone_distribution[sender_idx][target_num]].range;		

			/* add host workload to drone */
			dl[i].add_host_workunit (&tt);
		}	
		
		for (port_num=0; port_num < this->port_buffer_count; port_num++) {			
			pp.port = port_buffer[port_num].port;
			pp.range = port_buffer[port_num].range;			
			
			/* add port workload to drone */
			dl[i].add_port_workunit (&pp);			
		}	
		
		/* send workload to sender drones */				
		dl[i].send_workload();
		sender_idx++;
	}
		
	return 0;
}

/* start all drones (listener first) */
uint32_t drone_list::start_scan(void)
{
	uint32_t i = 0;

	/* start listener drones first */
	for (i=0; i < dl.size(); i++) {
		if (dl[i].get_type() == IDENT_LISTENER) dl[i].start();
	}

	/* then start sender drones */
	for (i=0; i < dl.size(); i++) {
		if (dl[i].get_type() == IDENT_SENDER) dl[i].start();
	}
	
	return 0;
}

/* stop scan for all drones */
uint32_t drone_list::stop_scan(void)
{
	uint32_t i = 0;

	/* Noooooooooooo!! */
	for (i=0; i < dl.size(); i++) {
		dl[i].stop();
	}
	
	return 0;
}

/*
 * the drones are working, so now we check for incoming messages from them until they finish.
 * or get killed by a segmentation fault... *douh*
 */
uint32_t drone_list::poll_drones(void)
{
	uint32_t bytes;
	uint32_t i;
	uint32_t msg_len = 0;
	
	struct ipc_message *ipc_m;
	struct pollfd *pfd;
	
	char buff[MAX_MSG_LEN];
	char *msg = NULL;	
	
	pfd = (struct pollfd *) safe_zalloc(this->dl.size() * sizeof(struct pollfd));
	
	while(true) {
		for (i=0; i < this->dl.size(); i++) {
			pfd[i].fd=this->dl[i].get_socket();
			pfd[i].events=POLLIN|POLLPRI;	
		}
		
		if (poll(pfd, this->dl.size(), 10) < 0) {
			printf("[warn] poll fails: %s", strerror(errno));
		}
				
		for (i=0; i < this->dl.size(); i++) {
			if (pfd[i].revents & POLLIN) { /* received something */
				msg_len = get_ipc_message(this->dl[i].get_socket(), &msg);
				if (msg_len > 0) {
					ipc_m = (struct ipc_message *) msg;
						
					switch (ipc_m->msg_type) {
						case MSG_ERROR: /* Oh no, something went wrong. blame someone! */
							this->dl[i].print_error(msg);
							this->handle_dead_drone(i);
							break;
						case MSG_WORKDONE: /* drone finished the work. well done, get a cookie */
							MSG(MSG_DBG, "[ipc in] workdone from: %s:%d\n", this->dl[i].get_addr_str(), this->dl[i].get_port());
						
							if (this->dl[i].get_type() == IDENT_SENDER) {
								/* Close socket and remove drone */
								this->remove_drone (i, NULL);								
								
								MSG(MSG_DBG, "[drone] sender drone finished [%d drones left]\n", this->num_send_drones);
								
								if(this->num_send_drones == 0) {
									MSG(MSG_DBG, "all senders finished. telling listener to stop (%d seconds timeout) \n", this->scan_timeout);
									ipc_send_quit(this->get_listener_sock());
								}
							} else if (this->dl[i].get_type() == IDENT_LISTENER) {
								MSG(MSG_DBG, "listener finished. Print results\n");																
								/* return to main() */
								return 0;
							} else {
								printf("[wtf] holy shit! Error in MSG_WORKDONE processing\n");
							}

							break;
						case MSG_PORTSTATE: /* open port found */
							this->set_portstate((char *)ipc_m);
							break;
						case MSG_SENDER_STATS: /* sender statistics */
							this->statistics((char *)ipc_m, i);
							break;						
						default:
							printf("[wtf] what the... invalid ipc message recveived. ignoring.\n");
							break;
					}
				} else if (msg_len == 0) {
					/* connection lost */
					MSG(MSG_WARN, "connection lost to drone %s:%d\n", this->dl[i].get_addr_str(), this->dl[i].get_port());
					this->handle_dead_drone(i);
				} else {
					MSG(MSG_WARN, "invalid message from drone, ignoring\n");
				}
			}
		}
	}
}

/*
 * remove drone form list and set some counters
 */
void drone_list::remove_drone(uint32_t index, const char *msg)
{	
	if (msg) {
		MSG(MSG_WARN, "%s - removing drone from list (%s:%d).\n", msg, this->dl[index].get_addr_str(), this->dl[index].get_port ());
	}
	
	if (this->dl[index].get_type() == IDENT_LISTENER) {
		if (msg) MSG(MSG_ERR, "listener drone had an error. Aborting.");
	} else if (this->dl[index].get_type() == IDENT_SENDER) {
		this->num_send_drones--;
	}
	
	/* close socket */
	if (this->dl[index].get_socket()) close(this->dl[index].get_socket());
	
	this->dl.erase(this->dl.begin() + index);	
	
	return;
}

/*
 * parse drone string and add drones to drone() vector
 */
void drone_list::add_dronestr(char *drone_str)
{
	char *p = strdup(drone_str);
	char *q = p;
	
	char ip_buff[MAX_IP_STR_LEN + 1];
	char port_buff[MAX_PORT_STR_LEN + 1];
	
	
	bool is_ip=false, is_port=false;
	
	this->num_listen_drones = 0;
	this->num_send_drones = 0;
	
	is_ip=true;
	
	do {
		if (*p == ':') {
			if (is_ip) {
				bzero(ip_buff, MAX_IP_STR_LEN + 1);
				strncpy(ip_buff, q, (((p-q) > MAX_IP_STR_LEN) ? MAX_IP_STR_LEN : p-q)); 
				q = p + 1;
				is_port = true;
				is_ip = false;
			} else {
				MSG(MSG_ERR, "invalid drone string: %s\n", drone_str);
				exit(0);
			}
		} else if (*p == ',' || *p == '\0') {
			if (is_port) {
				bzero(port_buff, MAX_PORT_STR_LEN + 1);
				strncpy(port_buff, q, (((p-q) > MAX_PORT_STR_LEN) ? MAX_PORT_STR_LEN : p-q)); 
				is_port = false;
				is_ip = true;				
				q = p + 1;
				
				this->add_drone(host2long(ip_buff), atoi(port_buff), strdup(DEFAULT_PASS));
			} else {
				MSG(MSG_ERR, "invalid drone string: %s\n", drone_str);
				exit(0);
			}
		}
	} while(*(p++) != '\0');
	
	return;
}

/*
 * round-robin loadbalancing. distributes the targets to the sender drones (very cool)
 */
void drone_list::balance_workunit(void)
{
	char *payload;
	char *p;

	struct ports *pp;
	struct targets *tt;
	
	uint32_t i=0;
	uint32_t port_data_len=0;
	uint32_t ip_data_len=0;
	uint32_t payload_size=0;
	uint32_t r_msg_len=0;
	uint32_t current_drone=0;
	
	/* Target distribution */
	uint16_t sender_count = 0;
	uint32_t ipaddr_per_sender = 0;
	uint32_t target_number = 0;
	uint32_t ipaddr_sender_count = 0;
	uint32_t remaining = 0;	

	/* number of available drones */
	sender_count = this->num_send_drones;

	/* no targets? not good... */
	if (!this->total_ip_count) { MSG(MSG_ERR, "error in target string\n"); }
	
	/* more drones than targets ? */
	if (this->total_ip_count < sender_count) {
		MSG(MSG_WARN, "got %d targets for %d sender drones. Removing %d sender drones from list.\n", this->total_ip_count, sender_count, sender_count - this->total_ip_count);
		/* remove unused drones from drone list */
		i = 0;
		do {				
			if (this->dl[i].get_type() == IDENT_SENDER) {
				this->remove_drone (i, "more drones than targets");
				i--;
			}
			i++;
		} while (this->num_send_drones > this->total_ip_count || i > this->dl.size());

		sender_count = this->num_send_drones;
	}

	rearrange_targets(this->total_ip_count, sender_count);
	
	/* Generate Load-Balancing Array */
	ipaddr_per_sender = this->total_ip_count / sender_count;
	//fprintf(stderr, "ipaddr_per_sender (%d) = total_target_count(%d) / sender_count(%d)\n", ipaddr_per_sender, total_ip_count, sender_count);
	tt = this->target_buffer;
	target_number = 0;
	for (i = 0; i < sender_count; i++) {
		ipaddr_sender_count = 0;

		this->drone_distribution_idx[i] = 0;
		while (ipaddr_sender_count < ipaddr_per_sender) {
			//fprintf(stderr, "debug: drone_distribution[%d][(drone_distribution_idx[%d]) = %d] = %d\n",i,i,drone_distribution_idx[i],target_number);
			this->drone_distribution[i][this->drone_distribution_idx[i]] = target_number;
			this->drone_distribution_idx[i]++;
			ipaddr_sender_count += tt->range;
			//fprintf(stderr, "ipaddr_sender_count (%d) += tt->range(%d)(@%p)\n", ipaddr_sender_count, tt->range, tt);
			tt++;
			target_number++;
		}
	}

	/* distribute remaining targets round-robin */
	while (target_number < target_buffer_count) {
		remaining = (i + 1) % sender_count;
		this->drone_distribution[remaining][this->drone_distribution_idx[remaining]]=target_number;
	
		this->drone_distribution_idx[remaining]++;
		target_number++;
		i++;
	}		
}

/*
 * rearrange_targets
 */
void drone_list::rearrange_targets(uint32_t ipaddr_count, uint32_t sender_count) { 
	struct targets local_target_buffer[MAX_TARGETS];			// local target buffer
	uint32_t target_count;										// counter for local target buffer
	struct targets *t_global, *t_local;							// pointers to target buffers
	struct targets target;										// target
	uint32_t ipaddr_per_sender, ipaddr_remainder, delta;		// calculation stuff
	uint32_t i,ip_count_sender;									// various counters

	// calculate number of IP addresses per sender
	ipaddr_per_sender = ipaddr_count / sender_count;
	ipaddr_remainder = ipaddr_count % sender_count;

	t_global = target_buffer;									// set pointer to global target buffer
	t_local = local_target_buffer;								// set pointer to local target buffer
	target_count = 0;											// set local target buffer count to zero
	i = 0;														// index for global target buffer

	// process all targets in global target buffer
	while (i < sender_count) {
		ip_count_sender = 0;									// set IP address count for sender to zero
		while (ip_count_sender < ipaddr_per_sender) {
			// is target a single host or an IP address range?	
			
			if (t_global->range == 1) {
				// single host

				// add single host to local target buffer
				t_local->ipaddr = t_global->ipaddr;				// save IP address
				t_local->range = t_global->range;				// save range (in this case 0)
				t_local++;										// point to next element in local target buffer
				ip_count_sender++;								// increment IP address count of sender
				target_count++;									// increment target counter
			} else {
				// IP address range

				// calculate number of IP addresses to complete a sender
				delta = ipaddr_per_sender - ip_count_sender;

				if (t_global->range <= delta) {				
					// number of targets fits in current sender
					// so add IP address range to local target buffer
					t_local->ipaddr = t_global->ipaddr;			// save IP address
					t_local->range = t_global->range;			// save range (in this case 0)
					t_local++;									// point to next element in local target buffer
					ip_count_sender += t_global->range;			// increment IP address count of sender
					target_count++;								// increment target counter
				} else {
					// IP address range has to be splitted
					// so split it in two ranges
					target.ipaddr = t_global->ipaddr;			// save global target IP address
					target.range = t_global->range;				// save global target range
			
					// add first IP address range to local target buffer
					t_local->ipaddr = t_global->ipaddr;			// save IP address
					t_local->range = delta;						// save range (in this case the calculated delta)
					t_local++;									// point to next element in local target buffer
					ip_count_sender += delta;					// increment IP address count of sender
					target_count++;								// increment target counter
	
					// in-memory replacement of target in global memory buffer with second range
					t_global->ipaddr = htonl(ntohl(target.ipaddr) + delta);
					t_global->range = target.range - delta;
					
					continue;
				}	
			}
			t_global++;	
		}
		i++;
	}

	// add remaining IP address to local target buffer
	while (ipaddr_remainder > 0) {
		if (t_global->range == 1) {
			// single host
			// add single host to local target buffer
			t_local->ipaddr = t_global->ipaddr;					// save IP address
			t_local->range = t_global->range;					// save range (in this case 0)
			t_local++;											// point to next element in local target buffer
			ipaddr_remainder--;									// decrement remainder counter
			target_count++;										// increment target counter
		} else {
			// IP address range

			t_local->ipaddr = t_global->ipaddr;					// save IP address
			t_local->range = t_global->range;					// save range (in this case 0)
			t_local++;											// point to next element in local target buffer
			ipaddr_remainder -= t_global->range;				// decrement remainder counter
			target_count++;										// increment target counter
		}
		//t_global += sizeof(struct targets);	
		t_global++;
	}

	// copy local target buffer to global target buffer
	memcpy(target_buffer, local_target_buffer, sizeof(struct targets) * target_count);
	target_buffer_count = target_count;
}

/*
 * a drone has died during the scan (you will always be in our hearts) save this drones workunit
 * and balance it to the remaining sender drones (if any)
 */
void drone_list::handle_dead_drone(uint32_t index) 
{
	uint32_t target_num = 0;
	uint32_t i = 0;	
	uint32_t sender_idx=0;

	struct targets tt;
	
	if (this->num_send_drones < 2) {
		MSG(MSG_ERR, "to many drones died through the scan. Aborting.\n");
		exit(0);
	}
	
	if (this->dl[index].get_type() == IDENT_LISTENER) { /* OMG, they killed kenny! */
		MSG(MSG_ERR, "listener drone died. Aborting.\n");
		exit(0);		
	}
	
	MSG(MSG_USR,  "[info] re-distributing workload of drone %s:%d to the remaining %d sender drones\n", this->dl[index].get_addr_str(), this->dl[index].get_port(), this->num_send_drones -1);
	
	/* step 1: get workload for this drone and overwrite global target array */		
	this->total_ip_count = 0;
	for (target_num=0; target_num < this->dl[index].target_workunit.size(); target_num++) {		
		this->target_buffer[target_num] = this->dl[index].target_workunit[target_num];
		this->total_ip_count += this->dl[index].target_workunit[target_num].range;
	}	

	this->target_buffer_count = this->dl[index].target_workunit.size();	
	
	/* step 2: close connection and remove drone from list */
	this->remove_drone (index, NULL);	
	
	/* step 3: balance the new global target array to the remaining drones */
	this->balance_workunit();

	/* step 4: add the new workunits to the redistribution array of the remaining drones */			
	for (i=0; i<this->dl.size(); i++) {
		if (this->dl[i].get_type() == IDENT_SENDER) {
			/* clear existing redistribution array */
			this->dl[i].redist_workunit.clear();
			for (target_num=0; target_num < this->drone_distribution_idx[sender_idx]; target_num++) {						
				tt.ipaddr = target_buffer[this->drone_distribution[sender_idx][target_num]].ipaddr;
				tt.range = target_buffer[this->drone_distribution[sender_idx][target_num]].range;		
				/* add range to redistribution array */
				this->dl[i].add_redist_workunit(&tt);

				/* add range to the host array as well (if this drones workunit must be redistributed too) */
				this->dl[i].add_host_workunit (&tt);
			}
			this->dl[i].send_new_workload();
			sender_idx++;	
		}
	}	
}

/*
 * save commandline arguments (for database entries) 
 */
void drone_list::save_cmd_line(int argc, char *argv[])
{	
	uint32_t i = 0;
	uint32_t cmd_line_len = 0;
	char *cmd_line, *p;
	
	for (i=0; i<argc; i++) 
		cmd_line_len += strlen(argv[i]); /* get cmdline length */
	
 	/* allocate memory for cmd_line incl. spaces and NULL bytes */
	cmd_line = (char *) safe_zalloc(cmd_line_len + (argc * 2));
	p = cmd_line;
	
	for (i=0; i<argc; i++) {
		p += snprintf(p, strlen(argv[i]) + 2, "%s ", argv[i]);
	}
	
	this->scan_cmd_line = cmd_line;
	
	return;
}

/*
 * save state of port in database (only open ports are saved. any other state is ignored)
 */
void drone_list::set_portstate (char *msg)
{
	struct ipc_message *ipc_m;
	struct ipc_portstate *ipc_p;
	struct in_addr addr;
	
	ipc_m = (struct ipc_message *) msg;
	ipc_p = (struct ipc_portstate *) (msg + sizeof(struct ipc_message));
	
	addr.s_addr = ipc_p->target_addr;
	MSG(MSG_VBS, " * found open port %s:%d\n", inet_ntoa(addr), ipc_p->port);

	db_store_result(ipc_p->target_addr, ipc_p->port);

	return;
}

/*
 * this function receives statistic messages from the sender drones and correlate them
 */
void drone_list::statistics (char *msg, uint32_t drone_index)
{
	uint16_t i, stats_index;
	struct ipc_message *ipc_m;
	struct ipc_sender_stats *ipc_s;
	struct ipc_sender_stats tmp, sum;
	
	ipc_m = (struct ipc_message *) msg;
	ipc_s = (struct ipc_sender_stats *) (msg + sizeof(struct ipc_message));

	float timediff = (float)(ipc_s->packets_current_time - ipc_s->packets_send_time);
	float pps = (float)(ipc_s->packets_send / timediff) * 1000000;
	uint16_t prozent = ((float)ipc_s->packets_send / ipc_s->packets_total) * 100;	
	
	this->dl[drone_index].set_stats(ipc_s);
	MSG(MSG_DBG, "statistics from sender drone %s: send %d packets (%d%%) in %.2f seconds (%.2fpps)\n", this->dl[drone_index].get_addr_str(), ipc_s->packets_send, prozent, (timediff/1000000), pps);

	/* initiallisere statistic structs */
	bzero(&sum, sizeof(struct ipc_sender_stats));
	bzero(&tmp, sizeof(struct ipc_sender_stats));
	
	// check if we have statistics from all working drones
	for (i=0, stats_index=0; i < this->dl.size(); i++) {
		if (dl[i].get_type() == IDENT_SENDER) {
			tmp = this->dl[i].get_stats();

			// is this a valid statistic received from a sender drone
			if (tmp.packets_send) {
				stats_index++;

				// add statistics to summary struct
				sum.packets_send += tmp.packets_send;
				sum.packets_send_time += tmp.packets_send_time;
				sum.packets_current_time += tmp.packets_current_time;
				sum.packets_total += tmp.packets_total;				
			} else {
				// not enough statistics received
				break;
			}
		}
	}
	
	if (stats_index == this->num_send_drones) {
		// calculate summary statistics
		float timediff = (float)((sum.packets_current_time / stats_index)- (sum.packets_send_time / stats_index));
		float pps = (float)(sum.packets_send / timediff) * 1000000;
		uint16_t prozent = ((float)(sum.packets_send / stats_index) / (sum.packets_total / stats_index)) * 100;	

		gotoxy(0, 3);
		MSG(MSG_VBS, "[statistics from %d sender drones]: send %d packets (%d%%) in %.2f seconds (%.2fpps)\n", stats_index, sum.packets_send, prozent, (timediff/1000000), pps);
		reset_cursor();
		
		// reset statistics
		bzero(&tmp, sizeof(struct ipc_sender_stats));
		for (i=0, stats_index=0; i < this->dl.size(); i++) {
			if (dl[i].get_type() == IDENT_SENDER)
				dl[i].set_stats(&tmp);
		}
	}		

	return;
}

void drone_list::init_routing_table(void)
{
	struct routing_entry rtentry;
	FILE *routefp;
	char buf[1024];
	char *p, *endptr, *ret;
	int i;  

	routefp = fopen("/proc/net/route", "r");
	if (routefp) {
		ret = fgets(buf, sizeof(buf), routefp); /* Kill the first line (column headers) */
		while(fgets(buf,sizeof(buf), routefp)) {
			bzero(&rtentry, sizeof(rtentry));
			p = strtok(buf, " \t\n");
			if (!p) {
				fprintf(stderr, "Could not find interface in /proc/net/route line");
				continue;
			}
			if (*p == '*')
				continue; /* Deleted route -- any other valid reason for a route to start with an asterict? */

			strncpy(rtentry.dev, p, sizeof(rtentry.dev));
			p = strtok(NULL, " \t\n");
			endptr = NULL;
	
			rtentry.dst = strtoul(p, &endptr, 16);               
       
			if (!endptr || *endptr) {
				fprintf(stderr, "Failed to determine Destination from /proc/net/route");
				continue;
			}

			p = strtok(NULL, " \t\n");
			if (!p) break;
			endptr = NULL;
			
			rtentry.gw = strtoul(p, &endptr, 16);
			if (!endptr || *endptr) {
				fprintf(stderr, "Failed to determine gw for %s from /proc/net/route", rtentry.dev);
			}
			for(i=0; i < 5; i++) {
				p = strtok(NULL, " \t\n");
				if (!p) break;
			}

			if (!p) {
			  fprintf(stderr, "Failed to find field %d in /proc/net/route", i + 2);
			  continue;
			}
			endptr = NULL;
			rtentry.mask = strtoul(p, &endptr, 16);
			if (!endptr || *endptr) {
				fprintf(stderr, "Failed to determine mask from /proc/net/route");
			  	continue;
			}

			this->rtbl.push_back(rtentry);
		}
	} 
	
	return;
}

char *drone_list::get_device (void)
{
	int i=0;
	
	if (!this->rtbl.size())
		this->init_routing_table();
	
	for (i=0; i < rtbl.size(); i++) {		
		if ( (rtbl[i].dst & rtbl[i].mask) == (this->target_buffer[0].ipaddr & rtbl[i].mask) ) { /* uuaaaaarrrggghh */
			return strdup(rtbl[i].dev);
		}
	}
	return NULL;
}
