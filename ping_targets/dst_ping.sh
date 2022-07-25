#!/usr/bin/env bash
set -euo pipefail

STATUS=good
APP="check_icmp dst hosts"
HOST=$(cat /etc/hostname).mixua.net
TARGETS=${TARGETS:="AntonHomeSW HomeStolbSW GaponStolbRT MaslukStolbRT TulnovaHomeRT KievNetGW"}

function push_slack() {
        if [[ -n "$results" ]] && [[ ! -f tmp.txt ]] ; then
                STATUS=warning
                echo "$results" > tmp.txt
		echo "$results" |grep -E  "failure|denied" > /dev/null && STATUS=danger
                echo "$results" |/usr/local/bin/slacktee.sh -u "$HOST" -t "$APP" -a $STATUS -e "cron date" "$(date)"
        else
                if [ -f tmp.txt ] ; then
                        echo "Connection to $1 restored $results" | \
                        /usr/local/bin/slacktee.sh -u "$HOST" -t "$APP" -a good -e "cron date" "$(date)"
                        rm tmp.txt
                fi
        fi
}

for i in $TARGETS; do
	results=$(ping_result=$(ping -q -W3 -c2 "$i" | grep -E "failure|timeout|Unreachable|denied|100% packet loss")
	[[ -z "$ping_result" ]] && echo > /dev/null || echo "dst $i $ping_result")
	push_slack "$i";
done

