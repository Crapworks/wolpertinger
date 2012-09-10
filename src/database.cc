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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/timeb.h>

#include "shared.h"
#include "ipc.h"
#include "drone.h"
#include "database.h"

extern struct global_informations global;

// callback for retreiving an integer
static int get_int_cb(void *param, int argc, char **argv, char **azColName){	
	int *i = (int *)param;					// create integer pointer
	
	if (argc > 0)							// if there is a value
		*i = atoi(argv[0]);					// save it as integer
		
	return 0;
}


// callback for retreiving a string
static int get_string_cb(void *param, int argc, char **argv, char **azColName){		
	if (argc > 0)											// if there is a value
		strncpy((char *)param, argv[0], MAX_STRING_LEN);	// copy it as string
		
	return 0;
}

static int get_drone_credentials_cb(void *param, int argc, char **argv, char **azColName){
	uint32_t i;
	uint32_t len = 0;

	if (argc != 2) {
		credentials = NULL;
		return 0;
	}

	/* allocate memory */
	credentials = (char **) safe_zalloc(sizeof(char *) * 2);
	credentials[0] = (char *) safe_zalloc(MAX_USERNAME_LEN);
	credentials[1] = (char *) safe_zalloc(MAX_PASSWORD_LEN);

	/* get username and password */
	snprintf(credentials[0], MAX_USERNAME_LEN, "%s", argv[0]);
	snprintf(credentials[1], MAX_PASSWORD_LEN, "%s", argv[1]);
	
	return 0;
}

// callback for retreiving the default port list
static int get_portlist_cb(void *param, int argc, char **argv, char **azColName){		
	uint32_t i;
	uint32_t len = 0;
	char buffer[MAX_STRING_LEN];
	char *p = (char *)param;
	
	for (i = 0; i < argc; i++) {		
		snprintf(buffer, MAX_STRING_LEN, "%s,", argv[i]);
		len = strlen(buffer);

		if ((pport_string + len) < buffer + MAX_DEFAULT_PORTSTR_LEN)
			strcpy(pport_string, buffer);
		
		pport_string += len;
	}
		
	return 0;
}


// callback for creating a scan report
static int create_report_cb(void *param, int argc, char **argv, char **azColName){		
	uint32_t i;
	uint32_t port;
	char *service;
	struct in_addr addr;
			
	for (i = 0; i < argc; i++) {		
		service = NULL;
		if (strcmp(azColName[i], "ip") == 0) {
			addr.s_addr = strtoul(argv[i], NULL, 10);			
		} else if (strcmp(azColName[i], "port") == 0) {
			port = atoi(argv[i]);
		} else if (strcmp(azColName[i], "name") == 0) {
			service = strdup(argv[i]);
		}		
	}	

	if (service) {
		printf("OPEN %-16s%-6d[%s]\n", inet_ntoa(addr), port, service);		
		free(service);
	} else {
		printf("OPEN %-16s%-6d\n", inet_ntoa(addr), port);				
	}	
	
	return 0;
}


/* open database */
int db_open(void) {
	int rc, path_len;
	char *path;
	char *homepath;
	char *homepathdir;

	/* get home dir database location */
	path_len = strlen(getenv("HOME")) + strlen(DATABASE_HOME) + strlen(DATABASE) + 3;
	homepath = (char *) safe_zalloc (path_len);
	snprintf(homepath, path_len, "%s%s%s", getenv("HOME"), DATABASE_HOME, DATABASE);
	
	/* check if database exists in home dir (~/.wolpertinger/wolpertinger.db) */
    if (FILE * file = fopen(homepath, "r")) {
		/* file exists, open database */
		fclose(file);
		rc = sqlite3_open(homepath, &db);
		if (rc) {
			fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			exit(1);
		}

		return rc;        
    } else {
		/* file doesn't exist. copy it from PKGDATADIR */
		printf("wolpertinger.db does not exist. creating a new one in homedir.\n");

		/* try to create wolpertinger directory */
		path_len = strlen(getenv("HOME")) + strlen(DATABASE_HOME) + 3;
		homepathdir = (char *) safe_zalloc (path_len);
		snprintf(homepathdir, path_len, "%s%s", getenv("HOME"), DATABASE_HOME);
		mkdir(homepathdir, 0700);

		/* copy file from PKGDATADIR */
		path_len = strlen(PACKAGE_DATA_DIR) + strlen(DATABASE) + 3;
		path = (char *)safe_zalloc(path_len);
		snprintf(path, path_len, "%s/%s", PACKAGE_DATA_DIR, DATABASE);
		file_copy(path, homepath);	
		chmod(homepath, 0700);

		/* open database in homedir */
		rc = sqlite3_open(homepath, &db);
		if (rc) {
			fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			exit(1);
		}

		return rc;
	}
}


/* write database */
int db_write(char *sql_stmt) {
	int rc;
	char *zErrMsg = 0;
	rc = sqlite3_exec(db, sql_stmt, 0, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		// ignore uniqueness error messages, because the database handles this
		if (strstr(zErrMsg, "unique") != NULL) {
			return rc;
		}
		
		// print SQL error message
		MSG(MSG_WARN, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	
	return rc;
}


/* read database */
int db_read(char *sql_stmt, void *var, int (*callback)(void*, int, char**, char**)) {
	int rc;
	char *zErrMsg = 0;
		
	rc = sqlite3_exec(db, sql_stmt, callback, var, &zErrMsg);
	if (rc != SQLITE_OK) {
		MSG(MSG_WARN, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	
	return rc;
}


/* close database */
void db_close(void) {
	sqlite3_close(db);
}


/* create scan */
int db_create_scan(struct timeb *time, struct info *scan_info) {
	char sql_stmt[MAX_STMT_LEN];
		
	// better SQL input validation needed!
	//if (strchr(dl->get_cmd_line(), 0x27) != NULL)
	//	return 0;
	
	// insert new scan (with source IP 0.0.0.0)
	snprintf(sql_stmt, MAX_STMT_LEN, "insert into scan (tag, pps, hosts, ports, source_ip, source_port, start_time, end_time) "
	                                 "values ('%s', %u, %u, %u, %u, %u, %jd, %jd)", 
	         						  scan_info->scan_tag, scan_info->pps, scan_info->num_hosts, scan_info->num_ports, scan_info->source_ip, scan_info->source_port, (intmax_t)time->time, (intmax_t)time->time);
	db_write(sql_stmt);
			
	// get ID of new scan
	snprintf(sql_stmt, MAX_STMT_LEN, "select id from scan where start_time=%jd", (intmax_t)time->time);
	db_read(sql_stmt, &scan_id, &get_int_cb);
		
	return scan_id;
}

/* set listener */
int db_set_listener(uint32_t ip) {
	char sql_stmt[MAX_STMT_LEN];

	// add listener address (scan address) to scan
	snprintf(sql_stmt, MAX_STMT_LEN, "update scan set source_ip=%u where id=%u", ip, scan_id);
	db_write(sql_stmt);

	return 0;
}


/* add drone */
int db_add_drone(uint32_t ip, uint16_t port, uint32_t type) {
	char sql_stmt[MAX_STMT_LEN];
	uint32_t drone_id = 0;
	
	// add drone
	snprintf(sql_stmt, MAX_STMT_LEN, "insert into drone (ip) values (%u)", ip);
	db_write(sql_stmt);	

	// get ID of new drone
	snprintf(sql_stmt, MAX_STMT_LEN, "select id from drone where ip=%u", ip);
	db_read(sql_stmt, &drone_id, &get_int_cb);

	// drone usage
	snprintf(sql_stmt, MAX_STMT_LEN, "insert into drone_usage (drone_id, port, type, scan_id) values (%u, %u, %u, %u)", drone_id, port, type, scan_id);			
	db_write(sql_stmt);

	return 0;
}

/* add drone credentials */
int db_add_drone_credentials(uint8_t *uuid, char *username, char *password) {
	char sql_stmt[MAX_STMT_LEN];
	char uuid_str[UUID_STR_LEN], *p;
	int i;
	
	for (i=0, p = uuid_str; i <  UUID_LEN; i++, p += 2)
		sprintf(p, "%02x", uuid[i]);
	
	snprintf(sql_stmt, MAX_STMT_LEN, "insert into drone_credentials (uuid, username, password) values ('%s', '%s', '%s')", uuid_str, username, password);

	db_write(sql_stmt);

	return 0;
}

/* store result */
int db_store_result(uint32_t ip, uint16_t port) {
	char sql_stmt[MAX_STMT_LEN];
	uint32_t host_id = 0;
	
	// add host
	snprintf(sql_stmt, MAX_STMT_LEN, "insert into host (ip) values (%u)", ip);
	db_write(sql_stmt);	
	
	// get ID of new host
	snprintf(sql_stmt, MAX_STMT_LEN, "select id from host where ip=%u", ip);
	db_read(sql_stmt, &host_id, &get_int_cb);
	
	// add result
	snprintf(sql_stmt, MAX_STMT_LEN, "insert into result (port, host_id, scan_id) values (%u, %u, %u)", port, host_id, scan_id);
	db_write(sql_stmt);	

	return 0;
}


/* finish scan */
int db_finish_scan(struct timeb *time) {
	char sql_stmt[MAX_STMT_LEN];
	
	// update end time
	snprintf(sql_stmt, MAX_STMT_LEN, "update scan set end_time=%jd where id=%u", (intmax_t) time->time, scan_id);
	db_write(sql_stmt);
	
	return 0;
}


/* get default ports */
char *db_get_default_ports(void) {
	char sql_stmt[MAX_STMT_LEN];
		
	// get all default ports
	snprintf(sql_stmt, MAX_STMT_LEN, "select port_string from default_ports");
	db_read(sql_stmt, default_port_string, &get_portlist_cb);

	// delete last comma
	default_port_string[strlen(default_port_string) - 1] = '\0';
			
	return default_port_string;
}

/* get drone credentials */
char **db_get_drone_credentials(uint8_t *uuid) {
	char sql_stmt[MAX_STMT_LEN];
	char uuid_str[UUID_STR_LEN], *p;
	int i;
	
	for (i=0, p = uuid_str; i <  UUID_LEN; i++, p += 2)
		sprintf(p, "%02x", uuid[i]);

	credentials = NULL;
	
	// get credentials for uuid
	snprintf(sql_stmt, MAX_STMT_LEN, "select username, password from drone_credentials where uuid=\"%s\"", uuid_str);
	db_read(sql_stmt, credentials, &get_drone_credentials_cb);

	//fprintf(stderr, "credentials[0] = %s\n", credentials[0]);
	//fprintf(stderr, "credentials[1] = %s\n", credentials[1]);
	
	return credentials;
}

/* create report */
char *db_create_report(uint32_t id) {
	char sql_stmt[MAX_STMT_LEN];

	if (id == 0)
		id = scan_id;
	
	// get scan results
	snprintf(sql_stmt, MAX_STMT_LEN, "select r.port as port,h.ip as ip,s.name as name from result as r, host as h, services as s where scan_id=%u and r.host_id=h.id and r.port=s.port order by h.ip asc, r.port asc", id);
	db_read(sql_stmt, 0, &create_report_cb);

	return 0;
}

/* set savepoint for temporary scans */
char *db_set_savepoint(void) {
	char sql_stmt[MAX_STMT_LEN];
	
	// add savepoint
	snprintf(sql_stmt, MAX_STMT_LEN, "begin transaction");
	db_write(sql_stmt);	

	return 0;
}

/* rollback to savepoint state */
char *db_rollback(void) {
	char sql_stmt[MAX_STMT_LEN];
	
	// rollback
	snprintf(sql_stmt, MAX_STMT_LEN, "rollback transaction");
	db_write(sql_stmt);	

	return 0;
}
