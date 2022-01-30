#!/usr/bin/env bash
set -euo pipefail

STATUS=good
APP="check_icmp dst hosts"
HOST=$(cat /etc/hostname).mixua.net
TARGETS="AntonHomeSW HomeStolbSW GaponStolbRT MaslukStolbRT TulnovaHomeRT"

function push_slack() {
        if [[ -n "$results" ]]; then
		echo "$results" |grep -E  "failure" > /dev/null && STATUS=warning
                echo "$results" |grep -E  "timeout|Unreachable|denied|100% packet loss" > /dev/null && STATUS=danger
                echo "$results" |/usr/local/bin/slacktee.sh -u "$HOST" -t "$APP" -a $STATUS -e "cron date" "$(date)"
        fi
}

for i in $TARGETS; do
	results=$(ping_result=$(ping -q -W3 -c2 "$i" | grep -E "failure|timeout|Unreachable|100% packet loss")
	[[ -z "$ping_result" ]] && echo > /dev/null || echo "dst $i $ping_result")
	push_slack;
done

