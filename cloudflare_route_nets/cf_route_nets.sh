#!/usr/bin/env bash

RULE_N=1399
EXT_IPS="${EXT_IPS:=192.168.33.1}"
CF_NETS=$(curl -s https://www.cloudflare.com/ips-v4 | awk '{print $0","};BEGIN {ORS=""}' | rev | cut -c 2- | rev)
CHECK=$(ipfw show ${RULE_N} >/dev/null && echo $? || echo $?)

if [[ ${CHECK} -ne 0 ]]; then
	ipfw add ${RULE_N} allow tcp from ${CF_NETS} to ${EXT_IPS} dst-port 80,443,1723 in via re0 setup
fi
