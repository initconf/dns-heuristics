#!/usr/local/bin/bash


if [[ -z $1 ]]; then 
	echo "extract-pcaps.sh  IP bucket TM-HOST " 
	exit 
fi 

ip=$1 ; 
bucket=$2 ; 
host=$3 ; 

ipname=$(echo $ip | tr '/' '-')
HOST=$(echo $host | tr 'a-z' 'A-Z') 
bpf="host" 

if [[ ! -z $ipname ]]; then 
	bpf="net" 
fi 

find /YTM/$HOST/TODAY/ -name "$bucket*" -print  | parallel "tcpdump -nr {} -w $ipname-{/} '$bpf $ip'"

ipsumdump -q --collate --no-tcpdump-nano -w $bucket-$ipname.pcap $ipname-$bucket-*

rm $ipname-$bucket-* 



