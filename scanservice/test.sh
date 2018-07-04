#!/bin/bash -x

LIST=`find /nmap_data/ -type f`
if [ $1 -eq 1 ]
then
	OP_CHECK=" -O "
fi
for i in $LIST
do
	ip=${i##*/}
	tcp_ports=`cat /nmap_data/$ip | grep tcp | awk '{printf "%s,",$1}' `
	udp_ports=`cat /nmap_data/$ip | grep udp | awk '{printf "%s,",$1}' `
	if [ $tcp_ports ]
	then
	    nmap $ip -sSV $OP_CHECK -p ${tcp_ports%?} -oX $ip-tcp.xml &
	fi
	if [ $udp_ports ]
	then
	    nmap $ip -sUV $OP_CHECK -p ${udp_ports%?} -oX $ip-udp.xml &
	fi
	rm /nmap_data/$ip
done
wait
