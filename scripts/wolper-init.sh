#!/bin/bash

#
# init script for wolpertinger drones
# 04-08-2009 Christian Eichelmann
#
# /etc/init.d/wolpertinger <start|stop|status|restart>
#


WOLPER_LISTEN=`which wolper-listen`
WOLPER_SEND=`which wolper-send`

GREEN="[32m"
RED="[31m"
RETURN="[0m"

PID_DIR="/var/run/wolpertinger"
NAME_SENDER="wolper-send"
NAME_LISTENER="wolper-listen"
PID_SEND=""
PID_LISTEN=""

DEFAULT_LISTENER_PORT="7777"
DEFAULT_SENDER_PORT="6666"

# r00t p0w3r r3qu1r3d!!1
if [ "${UID}" -gt "0" ]; then
    echo "only root can run this script"
    exit 1
fi

mkdir -p "${PID_DIR}"

usage()
{
    echo "usage: $0 <start|stop|restart|status>"
    exit 1
}

start_drones()
{
	# get interface from user
	echo -n "interface used for portscanning: "
	read INTERFACE
	
	### SENDER DRONE ###

	# Check for process already running
	if [ "`pgrep ${NAME_SENDER} | wc -l`" -gt "0" ]; then
		echo "[ ${NAME_SENDER} already running ]"
		exit 1
	fi

	# Check for pid file
	if [ -f "${PID_DIR}/${NAME_SENDER}" ]; then	

		# check for pid. if not exist, delete pid file
       	if [ -z "$(ps -p `cat ${PID_DIR}/${NAME_SENDER} 2> /dev/null` | awk '/'${NAME_SENDER}'/ {print $4}')" ]; then
           	# no process with this pid -> delete
			rm -f "${PID_DIR}/${NAME_SENDER}"
        else
   	        echo "[ ${NAME_SENDER} already running ]"
			exit 1
        fi
	fi

	# Starting
	echo -n "[ starting ${NAME_SENDER} : "
	nohup ${NAME_SENDER} -i ${INTERFACE} -p ${DEFAULT_SENDER_PORT} &> /dev/null &
	PID_SEND="$!"

    if [ "`pgrep ${NAME_SENDER} | wc -l`" -gt "0" ]; then
		echo "${GREEN}OK${RETURN} ]"
		echo "$PID_SEND" > "${PID_DIR}/${NAME_SENDER}"
	else
		echo "${RED}FAILED${RETURN} ]"
    fi

	### LISTENER DRONE ###

    # Check for process already running
    if [ "`pgrep ${NAME_LISTENER} | wc -l`" -gt "0" ]; then
		echo "[ ${NAME_LISTENER} already running ]"
		exit 1
    fi

    # Check for pid file
    if [ -f "${PID_DIR}/${NAME_LISTENER}" ]; then 

        # check for pid. if not exist, delete pid file
        if [ -z "$(ps -p `cat ${PID_DIR}/${NAME_LISTENER} 2> /dev/null` | awk '/'${NAME_LISTENER}'/ {print $4}')" ]; then
            # no process with this pid -> delete
            rm -f "${PID_DIR}/${NAME_LISTENER}"
        else
	        echo "[ ${NAME_LISTENER} already running ]"
	        exit 1
        fi
    fi

    # Starting
    echo -n "[ starting ${NAME_LISTENER} : "
    nohup ${NAME_LISTENER} -i ${INTERFACE} -p ${DEFAULT_LISTENER_PORT} &> /dev/null &
    PID_LISTEN="$!"

    if [ "`pgrep ${NAME_LISTENER} | wc -l`" -gt "0" ]; then
        echo "${GREEN}OK${RETURN} ]"
        echo "$PID_LISTEN" > "${PID_DIR}/${NAME_LISTENER}"
    else
        echo "${RED}FAILED${RETURN} ]"
    fi
}

stop_drones() {
	### SENDER DRONE ###

	# Check for pid file
    if [ -f "${PID_DIR}/${NAME_SENDER}" ]; then

        # check for pid
        if [ -z "$(ps -p `cat ${PID_DIR}/${NAME_SENDER} 2> /dev/null` | awk '/'${NAME_SENDER}'/ {print $4}')" ]; then
            # no process running
            echo "[ ${NAME_SENDER} not running ]"
        else
            echo -n "[ stopping ${NAME_SENDER} : "
            kill -9 `cat ${PID_DIR}/${NAME_SENDER}`

			# check if process is gone
		    if [ "`pgrep ${NAME_SENDER} | wc -l`" -eq "0" ]; then
		        echo "${GREEN}OK${RETURN} ]"
        		rm -f "${PID_DIR}/${NAME_SENDER}"
		    else
		        echo "${RED}FAILED${RETURN} ]"
		    fi
        fi
    fi

	### LISTENER DRONE ###

	# Check for pid file
    if [ -f "${PID_DIR}/${NAME_LISTENER}" ]; then

        # check for pid
        if [ -z "$(ps -p `cat ${PID_DIR}/${NAME_LISTENER} 2> /dev/null` | awk '/'${NAME_LISTENER}'/ {print $4}')" ]; then
            # no process running
            echo "[ ${NAME_LISTENER} not running ]"
        else
            echo -n "[ stopping ${NAME_LISTENER} : "
			kill -9 `cat ${PID_DIR}/${NAME_LISTENER}`

            # check if process is gone
            if [ "`pgrep ${NAME_LISTENER} | wc -l`" -eq "0" ]; then
                echo "${GREEN}OK${RETURN} ]"
                rm -f "${PID}/${NAME_LISTENER}"
            else
                echo "${RED}FAILED${RETURN} ]"
            fi
        fi
    fi
}

status_drones() {
    ### SENDER DRONE ###

    echo -n "[ ${NAME_SENDER} : "

    # Check for pid file
    if [ -f "${PID_DIR}/${NAME_SENDER}" ]; then

        # check for pid
        if [ -z "$(ps -p `cat ${PID_DIR}/${NAME_SENDER} 2> /dev/null` | awk '/'${NAME_SENDER}'/ {print $4}')" ]; then
            # no process with this pid 
            echo "${RED}DOWN${RETURN} ]"
        else
            echo "${GREEN}OK${RETURN} ]"   
        fi
    else
        echo "${RED}DOWN${RETURN} ]"
    fi


    ### LISTENER DRONE ###

	echo -n "[ ${NAME_LISTENER} : "

    # Check for pid file
    if [ -f "${PID_DIR}/${NAME_LISTENER}" ]; then

        # check for pid
        if [ -z "$(ps -p `cat ${PID_DIR}/${NAME_LISTENER} 2> /dev/null` | awk '/'${NAME_LISTENER}'/ {print $4}')" ]; then
            # no process with this pid 
            echo "${RED}DOWN${RETURN} ]"
        else
        	echo "${GREEN}OK${RETURN} ]"   
		fi
	else
		echo "${RED}DOWN${RETURN} ]"
    fi
}

if [ "$#" -lt "1" ]; then
    usage
fi

case "$1" in
    "start")
        start_drones
        ;;
    "stop")
        stop_drones
        ;;
    "restart")
        stop_drones
        sleep 1
        start_drones
        ;;
    "status")
        status_drones
        ;;
    *)
        usage
        ;;
esac

