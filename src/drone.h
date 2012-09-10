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

#ifndef DRONE_H
#define DRONE_H

#define MAX_PORT_STR_LEN 5

#define MAX_TARGETS			1024								// maximum number of targets in target string
#define MAX_PORTS			1024								// maximum number of ports in port string
#define MAX_DRONES			32									// maximum number of drones

#define ERR_CONNECTION_CLOSED 1
#define ERR_WRONG_TYPE 2
#define ERR_AUTH_FAILED 3
#define ERR_LISTENER_COUNT 4
#define ERR_INVALID_TYPE 5
#define ERR_CONNECTION_FAILED 6
#define ERR_INVALID_RESPONSE 7
#define ERR_NO_TARGETLIST 8

#include <vector>

using namespace std;

struct s_range {
	uint8_t start;
	uint8_t end;
};

struct routing_entry
{
        long dst;       // Destination Adress
        long mask;      // Netmask
        long gw;        // Gateway
        char dev[16]; // Device Name
};

class drone {
	private:				
		uint32_t socket;
		uint32_t total_hosts;
		uint32_t total_ports;
		uint32_t listener_addr;

		uint8_t drone_id[UUID_LEN];
		
		struct in_addr my_addr;
		char my_addr_str[MAX_DIRNAME_LEN];
		uint16_t my_port;
		uint8_t my_type;
		char *my_pass;
		char *my_user;

		/* sender statistics */
		struct ipc_sender_stats my_stats;
		
		/* scan options */
		uint32_t scan_pps;
		uint32_t scan_sport;
		uint32_t scan_secret;
		uint32_t scan_timeout;
		uint32_t scan_retry;
		uint32_t scan_tcpops;
		
		bool debug;
		bool local;
		
		/* ipc messages */
		char *recv_ipc_msg (void);		
		uint32_t create_target_payload(char *payload);
		uint32_t create_port_payload(char *payload);
		
	public:
		/* port workunit */
		vector<struct ports> port_workunit;

		/* target workunit */
		vector<struct targets> target_workunit;

		/* redistribution workunit */
		vector<struct targets> redist_workunit;		
		
		/* constructor / destructor */
		void initialize(void);
		drone(); 
		drone(uint32_t addr);
		drone(uint32_t addr, uint16_t port);
		drone(uint32_t addr, uint16_t port, char *pass);
		~drone(); // fehlermeldung, free()

		/* set properties */
		void add_host_workunit(struct targets *tt);
		void add_port_workunit(struct ports *pp);
		void add_redist_workunit(struct targets *tt);
		void set_addr(uint32_t addr) { my_addr.s_addr = addr; }
		void set_listener_addr(uint32_t addr) { listener_addr = addr; }
		void set_port(uint16_t port) { my_port = port; }
		void set_type(uint8_t type) { my_type = type; }
		void set_pass(char *pass) { my_pass = pass; }
		void set_debug(void) { debug = true; }
		void set_tcpops(uint32_t tcpops) { scan_tcpops = tcpops; }
		void set_retry(uint32_t retry_num) { scan_retry = retry_num; }
		void set_stats(struct ipc_sender_stats *stats) { memcpy(&my_stats, stats, sizeof(struct ipc_sender_stats)); }

		uint32_t set_timeout(uint32_t seconds) { scan_timeout = seconds; }
		uint32_t set_pps(uint32_t pps) { scan_pps = pps; }
		uint32_t set_sport(uint16_t sport) { scan_sport = sport; }
		uint32_t set_secret(uint32_t secret) { scan_secret = secret; }
		
		
		/* get properties */
		bool is_connected(void);		
		uint32_t get_total_hosts(void) { return total_hosts; }
		uint32_t get_total_ports(void) { return total_ports; }
		uint32_t get_listener_addr() { return listener_addr; }
		uint32_t get_addr_u32(void) { return my_addr.s_addr; }
		struct in_addr get_addr(void) { return my_addr; }
		struct ipc_sender_stats get_stats(void) { return my_stats; }
		char *get_addr_str(void) { return my_addr_str; }
		uint32_t get_socket(void) { return socket; }
		uint16_t get_port(void) { return my_port; }
		uint8_t get_type(void) { return my_type; }	
		
		/* methods */
		uint32_t connect(void);
		uint32_t send_workload(void);
		uint32_t send_new_workload(void); /* target re-distribution */
		uint32_t authenticate(void);
		uint32_t init(void);
		uint32_t start(void);
		uint32_t stop(void);
		
		void sock_close(void);
		void print_error(char *msg);
};

class drone_list {
	private:
		vector<drone> dl;
		vector<struct routing_entry> rtbl;
		
		uint32_t num_listen_drones;
		uint32_t num_send_drones;
		uint32_t total_ip_count;
		uint32_t total_port_count;
		uint32_t listener_addr;
		uint32_t listener_sock;

		/* scan options */
		uint32_t scan_pps;
		uint32_t scan_sport;
		uint32_t scan_secret;
		uint32_t scan_timeout;
		uint32_t scan_retry;
		uint32_t scan_tcpops;
		
		bool debug;
		bool verb;
		bool local;

		/* saved commandline string (for database entry) */
		char *scan_cmd_line;
		
		/* Target Array */
		struct targets target_buffer[MAX_TARGETS];
		uint32_t target_buffer_count;

		/* Port Array */
		struct ports port_buffer[MAX_PORTS];
		uint32_t port_buffer_count;

		/* Target Distribution Array */
		uint16_t drone_distribution[MAX_DRONES][MAX_TARGETS];
		uint16_t drone_distribution_idx[MAX_TARGETS];
		
		void create_send_workunit(void);
		void create_listen_workunit(void);
		void init_routing_table(void);
		void rearrange_targets(uint32_t ipaddr_count, uint32_t sender_count);
		void handle_dead_drone(uint32_t index);		
	public:
		/* constructor / destructor */
		drone_list();
		~drone_list();
		
		/* set properties */
		void add_dronestr(char *dronestr);
		uint32_t add_drone(uint32_t addr, uint16_t port, char *pass);
		uint32_t add_hostexp (char *hostexp);
		uint32_t add_portstr(char *portstr);

		void set_portstate (char *msg);
		void statistics(char *msg, uint32_t drone_index);
		void set_tcpops(uint32_t tcpops) { scan_tcpops = tcpops; }
		void set_retry(uint32_t retry_num) { scan_retry = retry_num; }
		uint32_t set_timeout(uint32_t seconds) { scan_timeout = seconds; }
		uint32_t set_pps(uint32_t pps) { scan_pps = pps; }
		uint32_t set_sport(uint16_t sport) { scan_sport = sport; }		

		void set_debug(void) { debug = true; }
		void set_verb(void) { verb = true; }
		void set_local(void) { local = true; }
		void save_cmd_line(int argc, char *argv[]);
		
		/* get properties */
		uint32_t get_num_listener_drones(void) { return num_listen_drones; }
		uint32_t get_num_sender_drones(void) { return num_send_drones; }
		uint32_t get_num_hosts(void) { return total_ip_count; }
		uint32_t get_num_ports(void) { return total_port_count; }
		uint32_t get_listener_addr(void) { return listener_addr; }
		uint32_t get_listener_sock(void) { return listener_sock; }
		uint32_t get_pps(void) { return scan_pps; }
		uint32_t get_sport(void) { return scan_sport; }
		uint32_t get_timeout(void) { return scan_timeout; }
		uint32_t get_retry(void) { return scan_retry; }
		uint8_t get_debug(void) { return debug; }
		char *get_device (void);
		char *get_cmd_line(void) { return scan_cmd_line; }
		bool get_local(void) { return local; }

		/* methods */
		uint32_t connect(void);
		uint32_t authenticate(void);
		void balance_workunit(void);
		uint32_t distribute_workunits(void);
		uint32_t start_scan(void);
		uint32_t stop_scan(void);
		void remove_drone(uint32_t index, const char *msg);
		
		uint32_t poll_drones(void);		
};

#endif
