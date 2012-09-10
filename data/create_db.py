#!/usr/bin/python
"""Create Wolpertinger Database"""

import sqlite3
import sys

# default ports
ports = "7,9,11,13,18,19,21-23,25,37,39,42,49,50,53,65,67-70,79-81,88,98,100,105-107,109-111,113,118,119,123,129,135,137-139,143,150,161-164,174,177-179,191,199-202,204,206,209,210,213,220,259-265,345,346,347,369-372,389,406,407,422,427,443-445,487,500,512-515,517,518,520,525,533,538,548,554,563,587,610-612,631-634,636,642,646,653,655,657,666,706,750-752,765,779,808,873,901,923,941,946,992-995,1001,1023-1030,1080,1210,1214,1234,1241,1334,1349,1352,1423-1425,1433,1434,1494,1524,1525,1527,1645,1646,1649,1701,1718,1719,1720,1723,1755,1812,1813,2048-2050,2101-2104,2140,2150,2222,2233,2323,2345,2401,2430,2431,2432,2433,2583,2628,2776,2777,2988,2989,3050,3130,3150,3200,3201,3232,3298-3299,3306,3300,3301,3389,3456,3493,3542-3545,3600,3632,3690,3801,4000,4400,4321,4567,4800,4899,5002,5060,5136-5139,5150,5151,5222,5269,5308,5354,5355,5422-5425,5432,5503,5555,5556,5678,6000-6007,6346,6347,6543,6544,6552,6789,6838,6666-6670,7000-7009,7028,7100,7983,8000,8010,8079-8082,8088,8100,8787,8879,9090,9101-9103,9325,9359,10000,10026,10027,10067,10080,10081,10167,10498,11201,12000,15345,17001-17003,18261-18265,18753,20011,20012,21554,22273,26274,27374,27444,27573,31335-31338,31787,31789,31790,31791,32668,32767-32780,33390,47262,49301,50000-50010,50020,50021,50116,54320,54321,57341,58008,58009,58666,59211,60000,60006,61000,61348,61466,61603,63485,63808,63809,64429,65000,65506,65530-65535"

# create default port list
portlist = ports.split(',')

# cmd line: $0 [working directory]
if len(sys.argv) < 2:
	working_dir = "."
else:
	working_dir = sys.argv[1]

database = working_dir + "/wolpertinger.db"
service_file = working_dir + "/wolper-services"
sql_file = working_dir + "/wolpertinger.sql"

# connect to database
conn = sqlite3.connect(database)

# get cursor
c = conn.cursor()

print "[*] Create wolpertinger database ...",
sys.stdout.flush()

try:
	# drop tables
	c.execute(r"drop table default_ports");
	c.execute(r"drop table drone");
	c.execute(r"drop table drone_usage");
	c.execute(r"drop table host");
	c.execute(r"drop table result");
	c.execute(r"drop table scan");
	c.execute(r"drop table services");
except sqlite3.OperationalError:
	pass

# create tables
wolpertables = open(sql_file, 'r').read()
c.executescript(wolpertables)

for p in portlist:
	c.execute(r"insert into default_ports (port_string) values ('%s')" % p)

# create services list
f = open(service_file, "rb")

service_ports = []									# list of service ports in service list file

for l in f:
	s = l.split()
	
	if s[1].find("tcp") != -1:
	
		service_name = s[0]
		service_port = int(s[1].split("/")[0])
		service_description = " ".join(s[3:]).replace("'", "`")

		service_ports.append(service_port)

		stmt = r"insert into services (name, port, description) values ('%s', %d, '%s')" % (service_name, service_port, service_description)
		
		c.execute(stmt)

f.close()

# add ports to services tables which are not in the service list file
service_name = ""
service_description = ""

for service_port in range(1,65536):
	if service_port not in service_ports:
		stmt = r"insert into services (name, port, description) values ('%s', %d, '%s')" % (service_name, service_port, service_description)
		
		c.execute(stmt)


# Save (commit) the changes
conn.commit()

# We can also close the cursor if we are done with it
c.close()

print "done"
