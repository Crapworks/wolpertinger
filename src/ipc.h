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

#ifndef IPC_H
#define IPC_H

#define MSG_ERROR 0
#define MSG_IDENT 1
#define MSG_IDENT_REPLY 2
#define MSG_WORKDONE 3
#define MSG_QUIT 4
#define MSG_WORKUNIT 5
#define MSG_READY 6
#define MSG_START 7
#define MSG_PORTSTATE 8
#define MSG_BUSY 9
#define MSG_AUTH 10
#define MSG_CHALLENGE 11
#define MSG_HELO 12
#define MSG_SENDER_STATS 13

#define IDENT_SENDER 1
#define IDENT_LISTENER 2

#define MAX_CHALLENGE_LEN 128
#define MAX_DIRNAME_LEN 256

#define MAX_MSG_LEN 8192
#define MAX_BUFFER_LEN 1048576 		// 1 MB

#define STATE_WAIT_FOR_WORK 1
#define STATE_IDENT_SENT 2
#define STATE_READY_TO_GO 3
#define STATE_BUSY 4
#define STATE_WORKDONE 5
#define STATE_CHALLENGE_SENT 6
#define STATE_AUTHENTICATED 7

#define SOCKET_PATH_SENDER LOCALSTATEDIR "/" MY_NAME "/sender" 
#define SOCKET_PATH_LISTENER LOCALSTATEDIR "/" MY_NAME "/listener" 

#define WOLPER_CHLD_SENDER_SYNC SIGUSR1
#define WOLPER_CHLD_LISTENER_SYNC SIGUSR2

struct ipc_message {
        uint32_t msg_type;
        uint32_t msg_len;
};

struct ipc_sendunit {
        uint32_t magic;
        uint32_t pps;
		uint32_t listener_addr;
		uint32_t secret;
		uint32_t retry;
		uint32_t tcpops;
        uint16_t port_data_len;
        uint16_t ip_data_len;
        uint16_t sport;
		uint16_t send_stats;
};

struct targets {
        uint32_t ipaddr;
        uint32_t range;
};

struct ports {
        uint16_t port;
        uint16_t range;
};

struct ipc_listenunit {
        uint32_t timeout;
        uint32_t magic;
		uint32_t secret;
        uint16_t sport;
};

struct ipc_portstate {
        uint16_t port;
        uint16_t sport;
        uint32_t target_addr;

};

struct ipc_sender_stats {
		uint32_t packets_total;
		uint32_t packets_send;
		uint32_t packets_send_time;
		uint32_t packets_current_time;
};

class ipc {
	private:
		/* private variables */
		uint8_t debug;
		uint32_t socket;

		/* send ipc messages */
		uint32_t send_sender_ident(uint32_t sock);
		uint32_t send_listener_ident(uint32_t sock, uint32_t myaddr);
		uint32_t send_ident_request(uint32_t sock);
		uint32_t send_start(uint32_t sock);
		uint32_t send_ready(uint32_t sock);
		uint32_t send_workdone(uint32_t sock);
		uint32_t send_busy(uint32_t sock);
		uint32_t send_error(uint32_t sock, const char *err);
		uint32_t send_quit(uint32_t sock);
		uint32_t send_portstate(uint32_t sock, uint16_t port, uint32_t from);
		uint32_t send_challenge(uint32_t sock, uint32_t addr);
		uint32_t send_helo(uint32_t sock);
		uint32_t send_auth(uint32_t sock, char *auth_str);		

		/* generic send/receive functions */
		uint32_t get_ipc_message(uint32_t sock, char **msg);
		uint32_t send_ipc_msg(uint32_t sock, char *msg, uint32_t len);
		
	public:
		ipc();
		~ipc();

		uint32_t send_msg(uint8_t msg_type);
		uint32_t send_msg(uint8_t msg_type, uint32_t addr); /* listener_ident, challenge */
		uint32_t send_msg(uint8_t msg_type, const char *str); /* error, auth */
		uint32_t send_msg(uint8_t msg_type, uint16_t port, uint32_t from); /* portstate */
		
		uint32_t get_msg(char **msg);	

		void close_client_sock(void);
		void close_server_sock(void);
		void reset_socket(void);
		
		uint32_t open_socket(uint16_t port, uint8_t type);
		uint32_t connect_socket(char *drone_addr, uint16_t port);		

		void set_debug(uint8_t debug_lvl) { debug = debug_lvl; }
};

uint32_t reset_ipc_socket(uint32_t sock);
uint32_t open_ipc_socket(uint16_t port, uint8_t type, char *lhost);
uint32_t connect_ipc_socket(char *drone_addr, uint16_t port);
bool check_auth(char *msg, char *username, char *password);

uint32_t get_ipc_message(uint32_t sock, char **msg);
uint32_t send_ipc_msg(uint32_t sock, char *msg, uint32_t len);

uint32_t ipc_send_sender_ident(uint32_t sock);
uint32_t ipc_send_listener_ident(uint32_t sock, uint32_t myaddr);
uint32_t ipc_send_ident_request(uint32_t sock);
uint32_t ipc_send_start(uint32_t sock);
uint32_t ipc_send_ready(uint32_t sock);
uint32_t ipc_send_workdone(uint32_t sock);
uint32_t ipc_send_busy(uint32_t sock);
uint32_t ipc_send_error(uint32_t sock, const char *err);
uint32_t ipc_send_quit(uint32_t sock);
uint32_t ipc_send_portstate(uint32_t sock, uint16_t port, uint32_t from);
uint32_t ipc_send_challenge(uint32_t sock, uint32_t addr, uint8_t *drone_id);
uint32_t ipc_send_helo(uint32_t sock);
uint32_t ipc_send_auth(uint32_t sock, char *auth_str);
uint32_t ipc_send_sender_stats(uint32_t sock, struct ipc_sender_stats *stats);

void ipc_close_socket();

#endif
