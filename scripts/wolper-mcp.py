#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""Master Control Program for the wolpertinger portscanner"""

import getopt
import os
import socket
import sqlite3
import sys
import warnings

from datetime import datetime
from socket import gethostbyname, htonl, ntohl, inet_aton, inet_ntoa
from struct import pack, unpack

# disable warnings
warnings.filterwarnings("ignore")

# VARIABLES & CONSTANTS
USER_HOME = os.path.expanduser("~")                             # get home directory of user
DATABASE = USER_HOME + "/.wolpertinger/wolpertinger.db"         # default database file
IDENT_SENDER = 1                                                # sender identifier
IDENT_LISTENER = 2                                              # listener identifier
MAX_TARGETS = 1024                                              # maximum number of targets in target string
TIME_FMT = "%H:%M:%S"                                           # time format
DATE_FMT = "%Y-%m-%d"                                           # date format
DATETIME_FMT = "%H:%M:%S %Y-%m-%d"                              # datetime format
IP_LUT = {}                                                     # IP lookup table

SUMMARY_LAYOUT="%-05s %-020s %-06s %-07s %-07s %-012s %-012s %-012s %-07s"
SUMMARY_HEADER=("Id", "Tag", "Hosts", "Ports", "pps", "Start", "End", "Total", "Open")

class wolper_mcp():
    """Wolpertinger Master Control Program"""
    
    def __init__(self, db_file = DATABASE):
        try:
            self.db_conn = sqlite3.connect(db_file)                 # open database connection  
        except sqlite3.OperationalError:
            print "Couldn't open wolpertinger database!"
            sys.exit(1)

        self.db_conn.row_factory = sqlite3.Row
        self.db_cursor = self.db_conn.cursor()                  # get database cursor

        self.line_by_line = False


    def show_default_ports(self):
        """Show default ports"""
        self.db_cursor.execute(r"select * from default_ports")

        print "=== Default Ports ==="

        for row in self.db_cursor:      
            print str(row[0])

    def get_portscan_count(self):
        """Retreive number of portscans in database"""
        count = 0

        self.db_cursor.execute(r"select count(*) from scan")
        
        for row in self.db_cursor:      
            count = int(row[0])
        
        return count

    def set_line_by_line(self):
        """Set line_by_line flag"""
        self.line_by_line = True

    def generate_nmap(self, ref_id):
        """Generate NMAP Output"""

        scan_id = []                                            # list of scan IDs
        hosts = []                                              # host list
        rid = int(ref_id) - 1
        port_str = ""

        # get list of portscans
        self.db_cursor.execute(r"select id from scan where id =?",  (ref_id, ))
        for row in self.db_cursor:
            success = True
        
        if not success:
            print "Invalid portscan number!"
            return

        # get hosts with open ports
        self.db_cursor.execute(r"select distinct h.ip from result as r, host as h where scan_id=? and r.host_id=h.id order by h.ip asc", (ref_id,))

        print "=== NMAP Hostlist ==="

        for row in self.db_cursor:
            ip = pack("I", row[0])
            hosts.append(inet_ntoa(ip))
            print inet_ntoa(ip)

        # show uniq open ports
        self.db_cursor.execute(r"SELECT DISTINCT r.port from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port order by h.ip asc, r.port asc", (ref_id,))

        print "\n=== NMAP Portstring ==="

        for r in self.db_cursor:
            if port_str == "":
                port_str = str(r[0])
            else:
                port_str = port_str+","+str(r[0])

        print port_str

    def delete_scan(self, ref_id):
        """ Delete scan """

        success = False

        # get list of portscans
        self.db_cursor.execute(r"select id from scan where id =?",  (ref_id, ))
        for row in self.db_cursor:
            success = True
        
        if not success:
            print "Invalid portscan number!"
            return

        # delete scan
        print "[+] deleting scan..."
        if not self.db_cursor.execute(r"delete from scan where id=?", (ref_id,)).rowcount:
            print "[+] Error deleting scan"
            return 

        # get host references
        print "[+] deleting host references..."
        self.db_cursor.execute(r"select host_id from result where scan_id=?", (ref_id,))
        
        # decrement host reference count (sqlite trigger)
        host_id = []
        for row in self.db_cursor:
            host_id.append(row['host_id'])

        if not len(host_id):
            print "[+] Error retrieving host references"

        for id in host_id:
            self.db_cursor.execute(r"delete from host where id=?", (id,))
                
        # delete port entries
        print "[+] deleting port references..."
        if not self.db_cursor.execute(r"delete from result where scan_id=?", (ref_id,)).rowcount:
            print "[+] Error deleting port references"
            return

        # delete drone information
        print "[+] deleting drone informations..."
        if not self.db_cursor.execute(r"delete from drone_usage where scan_id=?", (ref_id,)).rowcount:
            print "[+] Error deleting drone informations"
            return
            
        print "[+] finished"
        self.db_conn.commit()
    
    def list_portscans(self, searchstr=""):
        """List portscans"""
        if searchstr == "":
            self.db_cursor.execute(r"SELECT *,(SELECT COUNT(scan_id) FROM result WHERE scan_id = id)  FROM scan;")
            print "\n[+] Scans found in wolpertinger-database:"
        else:
            self.db_cursor.execute(r"SELECT *,(SELECT COUNT(scan_id) FROM result WHERE scan_id = id)  FROM scan WHERE tag LIKE '%"+searchstr+"%';")
            print "\n[+] Scans found with string '"+searchstr+"' in wolpertinger-database:"

        print "--------------------------------------------------------------------------------------------------"
        print SUMMARY_LAYOUT % SUMMARY_HEADER
        print "--------------------------------------------------------------------------------------------------"

        for row in self.db_cursor:
            start_time = datetime.fromtimestamp(row['start_time']).strftime(DATE_FMT)
            end_time = datetime.fromtimestamp(row['end_time']).strftime(DATE_FMT)
            time_delta = datetime.fromtimestamp(row['end_time']) - datetime.fromtimestamp(row['start_time'])
            print SUMMARY_LAYOUT % (row['id'], row['tag'], row['hosts'], row['ports'], row['pps'], start_time, end_time, time_delta, row[9])
            
        return

    def get_portscan_results(self, scan_id):
        """Retrieve results for portscan"""

        hosts = []                                              # host list
        results = []                                            # result list

        # get scanned hosts
        self.db_cursor.execute(r"select distinct h.ip from result as r, host as h where scan_id=? and r.host_id=h.id order by h.ip asc", (int(scan_id),))
        
        for row in self.db_cursor:
            ip = pack("I", row[0])  
            hosts.append(inet_ntoa(ip))
        
        # get open ports
        self.db_cursor.execute(r"select r.port, h.ip, s.name from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port order by h.ip asc, r.port asc", (int(scan_id),))
        
        for row in self.db_cursor:
            port = int(row[0])
            ip = pack("I", row[1])  
            service = row[2]
    
            # store result in results list
            results.append((port, inet_ntoa(ip), service))

        return results
        

    def get_host_results(self, scan_id, ip):
        """Get portscan results of specified host"""
                
        results = []                                            # result list
                
        # convert IP address
        ip = unpack("I", inet_aton(ip))[0]
                
        # get open ports
        self.db_cursor.execute(r"select r.port, s.name from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port and h.ip=? order by h.ip asc, r.port asc", (int(scan_id), ip))
        
        for row in self.db_cursor:
            port = row[0]
            service = row[1]            
        
            # store result in results list
            results.append((port, service))
        
        return results
        
    
    def get_portscan_info(self, scan_id):
        """Get portscan information"""
                
        # get and show some portscan statistics
        self.db_cursor.execute(r"select * from scan where id=? order by id asc", (int(scan_id),))
        
        for row in self.db_cursor:
            hosts = row['hosts']                            # number of scanned hosts
            ports = row['ports']                            # number of scanned ports
            pps = int(row['pps'])                           # packets per second
            source_ip = pack("I", row['source_ip'])                 # source IP address
            source_port = row['source_port']                # source port
            start_time = datetime.fromtimestamp(row['start_time'])      # start time
            end_time = datetime.fromtimestamp(row['end_time'])      # end time
            
            # calculate scan time
            scan_time = end_time - start_time
        
        return (hosts, ports, pps, source_ip, source_port, start_time, end_time, scan_time)

        
    def get_drones(self, scan_id):
        """Get drones used for portscan"""
    
        drones = []                                             # drone list

        # get list of portscans
        self.db_cursor.execute(r"select d.ip, du.port, du.type from drone as d, drone_usage as du where du.scan_id=? and d.id=du.drone_id order by type", (int(scan_id),))
        
        for row in self.db_cursor:
            ip = pack("I", row['ip'])                              # drone IP address
            port = int(row['port'])                                  # drone port
            typ = int(row['type'])                                   # drone type
        
            # local mode
            if row[0] == 1 or row[0] == 2:
                drones.append(("local drone", 0, typ))
            else:
                drones.append((inet_ntoa(ip), port, typ))
    
        return drones
        
        
    def show_portscan(self, ref_id):
        """Show portscan information"""
        
        hosts = []                                              # host list
        success = False
        
        # get list of portscans
        self.db_cursor.execute(r"select id from scan where id=?",  (int(ref_id), ))
        for row in self.db_cursor:
            success = True
        
        if not success:
            print "Invalid portscan number!"
            return
        
        # get scanned hosts
        self.db_cursor.execute(r"select distinct h.ip from result as r, host as h where scan_id=? and r.host_id=h.id order by h.ip asc", (int(ref_id),))
        
        for row in self.db_cursor:
            ip = pack("I", row[0])      
            hosts.append(inet_ntoa(ip))
        
        # get and show some portscan statistics
        info = self.get_portscan_info(ref_id)
                                    
        num_hosts = info[0]                             # number of scanned hosts
        num_ports = info[1]                             # number of scanned ports
        pps = info[2]                                       # packets per second
        source_ip = info[3]                                 # source IP address
        source_port = info[4]                               # source port
        start_time = info[5]                                # start time
        end_time = info[6]                                  # end time      
                    
        # calculate scan time
        scan_time = end_time - start_time
        
        # get total portscan results
        total_results = self.get_portscan_results(ref_id)

        # get used drones
        drones = self.get_drones(ref_id)
        
        if self.line_by_line:
            print "line-by-line"
        else:
            # show default portscan output
            print "wolpertinger results"
            print "--------------------"
            print "Start time:\t\t", start_time.strftime(DATETIME_FMT)
            print "End time:\t\t", end_time.strftime(DATETIME_FMT)
            print "Scan time:\t\t", self.get_scan_time(scan_time)
            print "Scanned hosts:\t\t", num_hosts
            print "Scanned ports:\t\t", num_ports 
            print "Open ports:\t\t", len(total_results)
            print "Source IP:\t\t", inet_ntoa(source_ip)
            print "Packets per second:\t", pps
        
            print "Listener drone:\t\t%s (%d/tcp)" % (drones[-1][0], drones[-1][1])
            print "Sender drone(s):\t",

            for s in drones[:-1]:
                print "%s (%d/tcp)" % (s[0], s[1]),
            print "\n"  
        
            # show results for each host
            for h in hosts:
                results = self.get_host_results(ref_id, h)
    
                print "Open ports on %s:" % (h)
    
                # print table header
                print "PORT\tSERVICE"
                for r in results:
                    print "%d\t%s" % (r[0], r[1])
    
                print
    
    
    def get_scan_time(self, time):
        """Format scan time"""
                
        # calculate the rest
        hours = time.seconds / 3600
        minutes = (time.seconds - hours * 3600) / 60
        seconds = time.seconds - hours * 3600 - minutes * 60
        
        if hours > 0:
            return "%d:%d:%d" % (hours, minutes, seconds)
        elif minutes > 0:
            return "%dm%ds   " % (minutes, seconds)
        elif seconds > 1:
            return "%d seconds" % (seconds)
        else:
            return "%d second" % (seconds)


def usage():
    """Show Wolpertinger MCP usage"""
    print "Wolpertinger Master Control Program v0.1\n" + \
            "Usage: wolper-mcp [OPTIONS]\n" + \
            "MISC:\n" + \
            "  -l, --list\t\tShow list of portscans\n" + \
            "  -f, --find <STRING>\tFind a specific portscan\n" + \
            "  -s, --show <SCAN#>\tShow detailed information about specified portscan\n" + \
            "  -n, --nmap <SCAN#>\tGenerate hostlist and  portstring for nmap\n" + \
            "  -i, --info\t\tShow list of default ports\n" + \
            "  -d, --delete <SCAN#>\tDelete scan from database\n" + \
            "  -h\t\t\tPrint this help summary page\n" + \
            "SHOW (use with -s|--show):\n" + \
            "  --line-by-line\tshow one host and the open ports per line\n" + \
            "EXAMPLES:\n" + \
            "  wolper-mcp --show 1"


def usage_exit(exit_code):
    """Print help information and exit program"""
    usage()
    sys.exit(exit_code)


# main
def main():
    # parse command line argument list
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ihls:f:n:d:", ["info", "help", "list", "show=", "find=", "nmap=", "delete=", "line-by-line"])
    except getopt.GetoptError:
        # print help information and exit
        usage_exit(2)
    except IndexError:
        # print help information and exit
        usage_exit(2)
            
    # if no arguments are given, show usage and exit
    if len(opts) == 0:
        usage_exit(1)
    
    # create master control program
    mcp = wolper_mcp()

    # check program arguments
    for o, a in opts:
        if o in ("-h", "--help"):
            # show help screen
            usage_exit(0)

        if o in ("-i", "--info"):
            # show default ports
            mcp.show_default_ports()
            
        if o in ("-l", "--list"):
            # list portscans
            mcp.list_portscans()

        if o in ("--line-by-line"):
            # set line-by-line-flag
            mcp.set_line_by_line();
            
        if o in ("-s", "--show"):
            # show portscan results
            try:
                scan_id = int(a)                                    
                mcp.show_portscan(a)
            except ValueError:
                usage_exit(1)

        if o in ("-f", "--find"):
            # search portscans
            searchstr = str(a)                                  
            mcp.list_portscans(searchstr)
    
        if o in ("-n", "--nmap"):
            # generate nmap output
            try:
                scan_id = int(a)        
                mcp.generate_nmap(scan_id)
            except ValueError:
                usage_exit(1)
                
        if o in ("-d", "--delete"):
            # delete scan
            try:
                scan_id = int(a)        
                mcp.delete_scan(scan_id)
            except ValueError:
                usage_exit(1)

    # quit PNmap
    sys.exit(0)


# main
if __name__ == "__main__":
    main()
