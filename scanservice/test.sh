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
	    nmap $ip -Pn -sSV $OP_CHECK -p ${tcp_ports%?} --open -oX $ip-tcp.xml &
	fi
	if [ $udp_ports ]
	then
	    nmap $ip -Pn -sUV $OP_CHECK -p ${udp_ports%?} --open -oX $ip-udp.xml &
	fi
	rm /nmap_data/$ip
done
wait
