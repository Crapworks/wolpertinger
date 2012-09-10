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

#ifndef SEND_H
#define SEND_H

#include <vector>

using namespace std;

struct target_info {
	uint32_t addr;
	uint16_t port_index;
};

class wolperdrone {
	private:				
		uint32_t listener_addr;
		uint32_t myaddr;
		uint32_t pps;
		uint32_t tcpops;
		uint32_t retry;
		uint32_t secret;
		uint32_t timeout;	
			
		uint16_t port;
		uint16_t client_sock;
		uint16_t sock;
		uint16_t sport;
		uint16_t datalink_offset;

		vector<uint16_t> ports;
		vector<struct target_info> targets;

		char *iface;
		char *lhost;
		char *username;
		char *password;

		uint8_t single; /* single/local scan only */
		uint8_t proto;
		uint8_t type;
		uint8_t debug;
		uint8_t drone_state;

		uint8_t drone_id[UUID_LEN]; /* uuid */
		
		pcap_t *pcap; /* pcap handle */			
		ip_t *ip_handle; /* ip handle (libdnet) */
		uint32_t hpet_handle; /* hpet file handle */

		/* privat methods */
		uint32_t get_device_addr(void);
		uint32_t get_workunit(char *msg);
		uint32_t packet_loop(pcap_t *handle);

		int16_t send_tcp_packet(ip_t *s, struct in_addr dst_addr, uint16_t dst_port, struct in_addr src_addr, uint16_t src_port, uint16_t tcp_flags, uint32_t seq, uint16_t ack, uint16_t window, uint8_t *options, uint32_t optlen);
		pcap_t *init_pcap(char *dev);
		
		void randomize_portlist(void);
		void randomize_hostlist(void);
		void send_packets(ip_t *ip_handle);
	public:
		/* constructor / destructor */
		wolperdrone();
		~wolperdrone();		
		
		void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
		void init_options(int argc, char *argv[]);
		void listen(void);
		void ipc_loop(void);
		void cleanup(void);
		void reset(void);
};

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
	
// Pseudo Header fuer Checksummenberechnung
struct pseudo_header { 
	struct in_addr s_addr;
	struct in_addr d_addr;
	unsigned char zero;
	unsigned char protocol;
	uint16_t length;
};

void help(char *me);
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
