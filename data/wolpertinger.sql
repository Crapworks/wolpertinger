CREATE TABLE default_ports (
	port_string varchar(32)
);

CREATE TABLE drone (
	id integer primary key autoincrement, 
	ip integer unique
);

CREATE TABLE drone_usage (
	drone_id integer references drone(id), 
	port integer, 
	type integer, 
	scan_id references scan(id), 
	primary key(drone_id, type, scan_id)
);

CREATE TABLE host_table (
	id integer primary key autoincrement, 
	ip integer unique, 
	hostname varchar(255),
	ref_count integer default 1
);

CREATE TABLE result (
	port integer, 
	host_id references host(id), 
	scan_id references scan(id), 
	primary key(port, host_id, scan_id)
);

CREATE TABLE scan (
	id integer primary key autoincrement, 
	tag varchar(64), 
	hosts integer, 
	ports integer, 
	pps integer, 
	source_ip integer, 
	source_port integer, 
	start_time date, 
	end_time date
);

CREATE TABLE drone_credentials (
	id integer primary key autoincrement, 
	uuid varchar(64) unique, 
	username varchar(128), 
	password varchar(128)
);

CREATE TABLE services (
	name varchar(64), 
	port integer primary key, 
	description varchar(128)
);

CREATE VIEW host as select * from host_table;

CREATE TRIGGER delete_name_if_zero AFTER UPDATE ON host_table
BEGIN
	delete from host_table where ref_count <= 0;
END;

CREATE TRIGGER safe_delete INSTEAD OF DELETE ON host
BEGIN
	UPDATE host_table SET ref_count = ref_count - 1 where ip = old.ip;
END;

CREATE TRIGGER safe_insert INSTEAD OF INSERT ON host
BEGIN
	UPDATE host_table SET ref_count = ref_count + 1 where ip = new.ip;
	INSERT OR FAIL INTO host_table (ip,hostname) VALUES(new.ip, new.hostname);
END;


