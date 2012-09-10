## Process this file with automake to produce Makefile.in

## Created by Anjuta

AM_CPPFLAGS = 

AM_CFLAGS =\
	 -Wall\
	 -g

bin_PROGRAMS = \
	wolpertinger\
	wolperdrone

wolperdrone_SOURCES = \
	ipc.cc       \
	ipc.h       \
	shared.cc       \
	shared.h       \
	wolperdrone.cc       \
	wolperdrone.h

wolperdrone_LDADD = \
	-lcrypto \
	-ldnet \
	-lpcap \
	-luuid

wolperdrone_CXXFLAGS = \
	-DPREFIX_DIR=\"$(prefix)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\"

wolpertinger_SOURCES = \
	ipc.h \
	shared.cc \
	ipc.cc \
	shared.h \
	main.cc \
	main.h \
	drone.cc \
	drone.h \
	database.h \
	database.cc

wolpertinger_LDADD = \
	-lcrypto        \
	-lsqlite3

wolpertinger_CXXFLAGS = \
	-DPACKAGE_DATA_DIR=\"$(pkgdatadir)\" \
	-DPREFIX_DIR=\"$(prefix)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\"

