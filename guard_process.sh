#!/bin/bash 

#daemon guard process
#path
/home/ctf/server &
b=`ps aux | grep server | grep -v grep | awk '{print $2}'`  
prlimit --nofile=102400:1048576 -p $b

while true
do
	a=`ps aux | grep server | grep -v grep | awk '{print $2}'`  
	echo $a
	if [ ! -n "$a" ]; then
		echo "[*]Daemon Not found, relaunch daemon!"
		/home/ctf/server &
		c=`ps aux | grep server | grep -v grep | awk '{print $2}'`  
		prlimit --nofile=102400:1048576 -p $c
	fi
	sleep 5
done
