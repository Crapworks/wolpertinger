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
 
#ifndef MAIN_H
#define MAIN_H

#include <vector>
#include <algorithm>

using namespace std;

struct portinfo {
	uint16_t port;
	uint32_t target;
};

struct portdesc {
	uint16_t port;
	char *desc;
};

void fork_drones(void);
int get_options(char *argv[], int argc);
void help(char *me);
void get_hosts_from_file(FILE *fd);
void get_drones_from_file(FILE *fd);
void signal_handler(int sig);

#endif
