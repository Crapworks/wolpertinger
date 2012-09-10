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

#ifndef SHARED_H
#define SHARED_H

#define MAX_IP_STR_LEN 16
#define MD5_ASCII_SIZE 33 /* 32bit + \0 */
#define SHA512_ASCII_SIZE 129

#define MAX_USERNAME_LEN 128
#define MAX_PASSWORD_LEN 128
#define MAX_TAGNAME_LEN 32

#define DEFAULT_USER "wolpertinger"
#define DEFAULT_PASS "kladderadatsch"

#define MAX_HOSTNAME_LEN	256
#define MAX_LOG_TYPE_NUM 	2
#define UUID_LEN 16
#define UUID_STR_LEN 33

#define PATH_DRONE PREFIX_DIR "/bin/wolperdrone"

#define MY_NAME "wolpertinger"
#define MY_VERSION "0.6"

#define CHLD_SYNC_TIMEOUT 5000000 /* 5 seconds */

#define TEXTCOLOR(farbe,text,format) printf("\033[%im"format"\033[m\017",farbe,text)
#define GET16(p) ((unsigned short int) *((unsigned char*)(p)+0) << 8 | (unsigned short int) *((unsigned char*)(p)+1) )

/* secret is choosen randomly by master */
#define TCPHASHTRACK(output, srcip, srcport, dstport, secret) \
    output=(secret) ^ ( (srcip) ^ ( ( (srcport) << 16) + (dstport) ) )

#define tsc_t uint64_t

#include <pcap.h>

/* buffer für ausgaben  */
#define MAX_OUTPUT_LEN 1024

/* output types */
#define MSG_ERR 1
#define MSG_VBS 2
#define MSG_DBG 4
#define MSG_TRC 8
#define MSG_USR 16
#define MSG_WARN 32

/* output makro */
#define MSG(level, fmt, args...) \
		/* debug and trace output */ \
        if ( ( (level & MSG_DBG) && global.debug ) || ( (level & MSG_TRC) && global.debug > 1 ) ) { \
                _display(level, __FILE__, __LINE__, (fmt), ## args); \
        } \
		/* verbose output */ \
        if ( (level & MSG_VBS) && global.verbose ) { \
                _display(level, __FILE__, __LINE__, (fmt), ## args); \
        } \
		/* normal / error */ \
        if ( (level & MSG_USR) || (level & MSG_ERR) || (level & MSG_WARN) ) { \
                _display(level, __FILE__, __LINE__, (fmt), ## args); \
        }


/* global infos */
struct global_informations {
	uint8_t debug;
	uint8_t verbose;
	uint8_t syslog;
	uint8_t use_database;
};

/* scan infos for database backend */
struct info {	
	uint32_t num_ports;
	uint32_t num_hosts;
	uint32_t pps;
	uint32_t source_port;
	uint32_t source_ip;	
	
	char *scan_tag;
};

static uint64_t get_tod(void) {
    struct timeval tv;
    uint64_t tt=0;

    gettimeofday(&tv, NULL);

    tt=tv.tv_sec;
    /* some 64 bit platforms have massive tv_usecs, truncate them */
    tt=tt << (4 * 8);
    tt += (uint32_t)(tv.tv_usec & 0xffffffff);

    return tt;
}

void fatal(const char *format, ...);
const char *get_time_str(void);
int unblock_socket(int s);
int block_socket(int s);
int create_stream_socket(int proto) ;
int create_raw_socket(int proto);
int create_domain_socket(int proto);
uint16_t in_cksum(uint16_t *ptr, uint32_t nbytes);
uint32_t host2long(char *host);
bool is_ip(char *host);
bool is_ip_cidr(char *host);
bool is_ip_range(char *host);
void *safe_zalloc(int size);

uint16_t get_rnd_uint16(void); 
uint32_t get_rnd_uint32(void);
unsigned int get_rnd_uint(void);

void sleep_init_tslot(uint32_t pps);
void sleep_start_tslot(void);
void sleep_end_tslot(void);

static void hpet_event(int val);
void hpet_start_tslot(void);
void hpet_end_tslot(void);
uint32_t hpet_init_tslot(uint32_t pps, uint32_t fd);
uint32_t init_hpet_handle(void);

const char *getflags(uint8_t flags);
char *md5(char *plaintext, uint16_t len);
char *sha512(char *plaintext, uint16_t len);
char *generate_digest(char *text, uint32_t text_len, char *key, uint32_t key_len);

char *get_scan_duration(struct timeb *start, struct timeb *stop);
uint8_t file_copy(char *src, char *dst);
unsigned long int tv2long(struct timeval *tv);

void _display(int type, const char *file, int lineno, const char *fmt, ...);
int drop_priv(void);

void gotoxy(int x, int y);
void reset_cursor(void);
void cls(void);

#endif
