#!/usr/bin/env bash
set -euo pipefail

APP="check_icmp dst hosts"
HOST=$(cat /etc/hostname).mixua.net
TARGETS="AntonHomeSW HomeStolbSW GaponStolbRT MaslukStolbRT TulnovaHomeRT"

function push_slack() {
        if [[ ! -z "$results" ]]; then
                echo $results |grep -e "success" > /dev/null && status=good || status="#858feb"
                echo $results |grep -e  "timeout|Unreachable|denied" > /dev/null && status=warning || status=$status
                echo $results |/usr/local/bin/slacktee.sh -u "$HOST" -t "$APP" -a $status -e "cron date" "$(date)"
        fi
}

# AntonHomeSW
for i in $TARGETS; do
	results=$(ping_result=$(ping -w3 -c2 $i | egrep -e "timeout|Unreachable|100% packet loss")
	[[ -z "$ping_result" ]] && echo > /dev/null || echo "dst $i $ping_result")
	push_slack;
done

