#!/usr/bin/env bash
set -euo pipefail

STATUS=good
APP="check_icmp dst hosts"
HOST=$(cat /etc/hostname).mixua.net
TARGETS="AntonHomeSW HomeStolbSW GaponStolbRT MaslukStolbRT TulnovaHomeRT"

function push_slack() {
        if [[ -n "$results" ]] && [[ ! -f tmp.txt ]] ; then
                STATUS=warning
                echo $result > tmp.txt
		echo "$results" |grep -E  "failure|denied" > /dev/null && STATUS=danger
                echo "$results" |/usr/local/bin/slacktee.sh -u "$HOST" -t "$APP" -a $STATUS -e "cron date" "$(date)"
        else 
                if [ -f tmp.txt ] ; then
                        echo "Connection restored $results" | \
                        /usr/local/bin/slacktee.sh -u "$HOST" -t "$APP" -a good -e "cron date" "$(date)"
                        rm tmp.txt
                fi
        fi
}

for i in $TARGETS; do
	results=$(ping_result=$(ping -q -W3 -c2 "$i" | grep -E "failure|timeout|Unreachable|denied|100% packet loss")
	[[ -z "$ping_result" ]] && echo > /dev/null || echo "dst $i $ping_result")
	push_slack;
done

