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
#include <stdint.h>
#include <ctype.h>

#include <poll.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dnet.h>

#include "shared.h"
#include "ipc.h"
#include "drone.h"
#include "wolperdrone.h"

/* fixme */
uint8_t debug;

uint32_t master_socket;
char my_challenge[MAX_CHALLENGE_LEN];
extern struct global_informations global;

uint32_t reset_ipc_socket(uint32_t sock)
{
	uint32_t cli_sock, cli_size;
	struct sockaddr_in cli_addr;
	
	close(sock); /* Client Socket schließen */
	
	cli_size = sizeof(cli_addr);
	if ((cli_sock = accept(master_socket, (struct sockaddr *) &cli_addr, &cli_size)) < 0) {
		perror("accept");
		exit(-1);
	}	
	
	return cli_size;
}

/*
 * creates a listening socket fpr the drones. normaly uses TCP sockets. if no drones are specified
 * unix domain sockets are used and the drones are spawned by the master process (TODO)
 */
uint32_t open_ipc_socket(uint16_t port, uint8_t type, char *lhost) 
{
	uint32_t sock, cli_sock, cli_size, bytes;
	
	struct sockaddr_in serv_addr, cli_addr;
	struct sockaddr_un local_addr;
	
	/* create socket */
	if (port==0) sock = create_domain_socket (0);
	else sock = create_stream_socket(IPPROTO_TCP);

	/* Socket Setup */
	if (port == 0) {
		bzero((char *) &local_addr, sizeof(local_addr));
		
		local_addr.sun_family=AF_UNIX;
		if (type == IDENT_SENDER) {			
			unlink (SOCKET_PATH_SENDER);
			snprintf(local_addr.sun_path, sizeof(local_addr.sun_path), "%s", SOCKET_PATH_SENDER);
		}
		if (type == IDENT_LISTENER) {
			unlink (SOCKET_PATH_LISTENER);
			snprintf(local_addr.sun_path, sizeof(local_addr.sun_path), "%s", SOCKET_PATH_LISTENER);
		}
		
		MSG(MSG_DBG, "unix domain socket path -> unix:/%s\n", local_addr.sun_path);
	} else {
		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = lhost ? inet_addr(lhost) : INADDR_ANY;
		serv_addr.sin_port = htons(port);
	}
	
	/* Socket Bind */
	if (port == 0) {
		if (bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0) {
			perror("bind");	
			exit(-1);
		}
	} else {
		if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
			perror("bind");	
			exit(-1);
		}
	}
		
	/* Listen... */
	if (listen(sock,1) < 0) {
		perror("listen");
		exit(-1);
	}
	
	if (port == 0) {
		cli_size = sizeof(local_addr);
		if((cli_sock = accept(sock, (struct sockaddr*) &local_addr, &cli_size)) < 0) {
			perror("accept");
			exit(-1);
		}
	} else {
		cli_size = sizeof(cli_addr);
		if ((cli_sock = accept(sock, (struct sockaddr *) &cli_addr, &cli_size)) < 0) {
			perror("accept");
			exit(-1);
		}
	}

	master_socket = sock;
	
	return cli_sock;
}

uint32_t send_ipc_msg(uint32_t sock, char *msg, uint32_t len)
{
	int32_t bytes;
	struct pollfd pfd;
	struct ipc_message *ipc_m;
	
	/* Wait for Socket to get ready to write */
	pfd.fd=sock;
	pfd.events=POLLOUT|POLLERR;	
	pfd.revents=0;

	if (poll(&pfd, 1, -1) < 0) {
		MSG(MSG_WARN, "poll fails: %s", strerror(errno));
	}		
				
	if (pfd.revents & POLLOUT) {	
		bytes = send(sock, msg, len, 0);
		if (bytes < 0) {
		        perror("write");
		        exit(-1);
		}
		ipc_m = (struct ipc_message *) msg;
		MSG(MSG_TRC, "[ipc out] %d bytes (should be: %d bytes) [type: %d]\n", bytes, len, ipc_m->msg_type);
	}
	
	return bytes;
}

uint32_t get_ipc_message(uint32_t sock, char **msg)
{
	int32_t bytes;
	fd_set fd_read;
	uint16_t err;
	
	struct timeval waitd;
	struct ipc_message *ipc_m;
	
	char buff[MAX_MSG_LEN];
	char *msg_buffer = NULL;
	uint32_t msg_buffer_ptr=0;
	uint32_t msg_body_len=0;
	
	struct pollfd pfd;
	
	while(1) {
		waitd.tv_sec = 1;
		waitd.tv_usec = 0;

		pfd.fd=sock;
		pfd.events=POLLIN|POLLPRI;	
		pfd.revents=0;

		if (poll(&pfd, 1, -1) < 0) {
			MSG(MSG_WARN, "poll fails: %s", strerror(errno));
		}		
		
		if (pfd.revents & POLLIN) {
			bzero(buff, MAX_MSG_LEN);

			// get message header
			bytes = recv(sock, buff, sizeof(struct ipc_message), 0);
			if(bytes < 0) {	perror("read"); return 0; } 
			if (bytes == 0) { /* EOF */
				MSG(MSG_WARN, "[drone] connection closed by foreign host\n");
				return 0;
			}			
			ipc_m = (struct ipc_message *) buff;

			if (ipc_m->msg_len > MAX_MSG_LEN) {
				MSG(MSG_WARN, "ipc message to big ( bytes: %d max: %d)\n", ipc_m->msg_len, MAX_MSG_LEN);
				return 0;
			}
			
			// fprintf(stderr, "****** message length: %d message type: %d ********\n", ipc_m->msg_len, ipc_m->msg_type);
			msg_buffer = (char *) safe_zalloc(ipc_m->msg_len);			
			msg_body_len = ipc_m->msg_len - sizeof(struct ipc_message);
			msg_buffer_ptr = sizeof(struct ipc_message);
			memcpy(msg_buffer, buff, sizeof(struct ipc_message));
			ipc_m = (struct ipc_message *) msg_buffer;
			
			bzero(buff, MAX_MSG_LEN);
			while (msg_body_len && msg_buffer_ptr < ipc_m->msg_len) {
				// get message body
				bytes = recv(sock, buff, msg_body_len, 0);
				if(bytes < 0) {	perror("read"); return 0; } 
				if (bytes == 0) { /* EOF */
					MSG(MSG_WARN, "[drone] connection closed by foreign host\n");
					return 0;
				}					
				// fprintf(stderr, "****** got %d more bytes! ********\n", bytes);
				memcpy(msg_buffer + msg_buffer_ptr, buff, bytes);
				msg_buffer_ptr = msg_buffer_ptr + bytes;				
			}
			*msg = msg_buffer;			    
			MSG(MSG_DBG, "[ipc in] %d bytes [type: %d]\n", ipc_m->msg_len, ipc_m->msg_type);
			return ipc_m->msg_len;
		}
	}
}

uint32_t ipc_send_busy(uint32_t sock) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_BUSY;
	ipc_m->msg_len = sizeof(struct ipc_message);

	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_listener_ident(uint32_t sock, uint32_t myaddr) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message) + 5);
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_IDENT_REPLY;
	ipc_m->msg_len = sizeof(struct ipc_message) + 5;
	
	*(msg + sizeof(struct ipc_message)) = IDENT_LISTENER;
	
	*((uint32_t *) (msg + sizeof(struct ipc_message) + 1)) = myaddr;
	
	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_sender_ident(uint32_t sock) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message) + 1);
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_IDENT_REPLY;
	ipc_m->msg_len = sizeof(struct ipc_message) + 1;
	
	*(msg + sizeof(struct ipc_message)) = IDENT_SENDER;
	
	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_ident_request(uint32_t sock) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_IDENT;
	ipc_m->msg_len = sizeof(struct ipc_message);

	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_portstate(uint32_t sock, uint16_t port, uint32_t from) {
	char *msg;
	struct ipc_message *ipc_m;
	struct ipc_portstate *ipc_p;
	
	msg = (char *)malloc(sizeof(struct ipc_message) + sizeof(struct ipc_portstate));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_PORTSTATE;
	ipc_m->msg_len = sizeof(struct ipc_message) + sizeof(struct ipc_portstate);

	ipc_p = (struct ipc_portstate *) (msg + sizeof(struct ipc_message));
	ipc_p->port = port;
	ipc_p->target_addr = from;
	
	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	free(msg);
	
	return 0;
}

/*
 * connect to an ipc socket (drone socket)
 * 
 * drone_addr = ip/hostname of drone OR path to unix domain socket
 * port = tcp port to connect to OR 0 for unix domain socket
 */
uint32_t connect_ipc_socket(char *drone_addr, uint16_t port) {
	uint32_t sock;
	struct sockaddr_in drone;
	struct sockaddr_un local_drone;

	if(port==0) {
		sock = create_domain_socket (0);

		bzero((char *) &local_drone, sizeof(struct sockaddr_un));

		local_drone.sun_family=AF_UNIX;
		snprintf(local_drone.sun_path, sizeof(local_drone.sun_path), "%s", drone_addr);

		MSG(MSG_DBG, "connecting to local socket -> %s\n", local_drone.sun_path);
		
		if((connect(sock, (struct sockaddr *)&local_drone, sizeof(struct sockaddr_un))) < 0) {
			perror("connect");
			return 0;
		}		
	} else {
		sock = create_stream_socket(IPPROTO_TCP);

		bzero((char *) &drone, sizeof(struct sockaddr_in));
		
		if((drone.sin_addr.s_addr = host2long(drone_addr)) == 0) {
			MSG(MSG_WARN, "invalid hostname for drone: %s\n", drone_addr);
			return 0;
		}
		
		drone.sin_port = htons(port);
		drone.sin_family = AF_INET;
		
		if((connect(sock, (struct sockaddr *)&drone, sizeof(struct sockaddr_in))) < 0) {
			return 0;
		}
	}
		
	return sock;
}

uint32_t ipc_send_ready(uint32_t sock) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_READY;
	ipc_m->msg_len = sizeof(struct ipc_message);

	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_start(uint32_t sock) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_START;
	ipc_m->msg_len = sizeof(struct ipc_message);

	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_error(uint32_t sock, const char *err) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message) + strlen(err));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_ERROR;
	ipc_m->msg_len = sizeof(struct ipc_message) + strlen(err);
	
	memcpy((msg + sizeof(struct ipc_message)), err, strlen(err));

	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_workdone(uint32_t sock) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_WORKDONE;
	ipc_m->msg_len = sizeof(struct ipc_message);

	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_sender_stats(uint32_t sock, struct ipc_sender_stats *stats) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message) + sizeof(struct ipc_sender_stats));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_SENDER_STATS;
	ipc_m->msg_len = sizeof(struct ipc_message) + sizeof(struct ipc_sender_stats);

	memcpy((msg + sizeof(struct ipc_message)), stats, sizeof(struct ipc_sender_stats));
	
	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_helo(uint32_t sock) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_HELO;
	ipc_m->msg_len = sizeof(struct ipc_message);

	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;	
}

uint32_t ipc_send_quit(uint32_t sock) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)malloc(sizeof(struct ipc_message));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_QUIT;
	ipc_m->msg_len = sizeof(struct ipc_message);

	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}

uint32_t ipc_send_auth(uint32_t sock, char *auth_str) {
	char *msg;
	struct ipc_message *ipc_m;
	
	msg = (char *)safe_zalloc(sizeof(struct ipc_message) + strlen(auth_str));
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_AUTH;
	ipc_m->msg_len = sizeof(struct ipc_message) + strlen(auth_str);
	
	memcpy(msg + sizeof(struct ipc_message), auth_str, strlen(auth_str));
	
	send_ipc_msg(sock, msg, ipc_m->msg_len);

	free(msg);
	
	return 0;
}

uint32_t ipc_send_challenge(uint32_t sock, uint32_t addr, uint8_t *drone_id) {
	uint32_t rnd;
	struct in_addr myaddr;
	struct ipc_message *ipc_m;
	char challenge[MAX_CHALLENGE_LEN+1];
	char *msg;
	uint16_t challenge_len;
	
	bzero(challenge, MAX_CHALLENGE_LEN);
	rnd = get_rnd_uint32();
	myaddr.s_addr = addr;
	
	snprintf(challenge, MAX_CHALLENGE_LEN, "<%d.%d@%s>", rnd, (uint32_t) time(NULL), inet_ntoa(myaddr));
	strncpy(my_challenge, challenge, MAX_CHALLENGE_LEN);
	challenge_len = strlen(challenge);

	msg = (char *)malloc(sizeof(struct ipc_message) + UUID_LEN + challenge_len);
	ipc_m = (struct ipc_message *) msg;
	
	ipc_m->msg_type = MSG_CHALLENGE;
	ipc_m->msg_len = sizeof(struct ipc_message) + UUID_LEN + challenge_len;

	memcpy(msg + sizeof(struct ipc_message), drone_id, UUID_LEN);
	
	memcpy(msg + sizeof(struct ipc_message) + UUID_LEN, challenge, challenge_len);
	
	send_ipc_msg(sock, msg, ipc_m->msg_len);
	
	return 0;
}


bool check_auth(char *msg, char *username, char *password) {
	struct ipc_message *ipc_m;
	char *client_auth;
	char *my_auth;
	char *digest;
	
	ipc_m = (struct ipc_message *) msg;

	client_auth = (char *) safe_zalloc(ipc_m->msg_len - sizeof(struct ipc_message) + 1);
	memcpy(client_auth, (msg + sizeof(struct ipc_message)), ipc_m->msg_len - sizeof(struct ipc_message));
		
	digest = generate_digest(my_challenge, strlen(my_challenge), password, strlen(password));
	my_auth = (char *)malloc(strlen(digest) + strlen(username) + 1);

	sprintf(my_auth, "%s %s", username, digest);

	MSG(MSG_DBG, "[auth] myauth: \"%s\" clientauth: \"%s\"\n", my_auth, client_auth);

	if (strcmp(my_auth, client_auth) == 0) return true;
	else return false;

}

void ipc_close_socket() {
	if (master_socket) close(master_socket);
}
