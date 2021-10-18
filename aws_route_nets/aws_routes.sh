#!/usr/local/bin/bash
ACTION=${ACTION:-add}
NOW=$(date +%Y-%m-%d,%H:%M)
CHECK_TG_IP=${CHECK_TG_IP:-"192.168.1.1"}
PING_STAT=$(ping -c2 "$CHECK_TG_IP" > /dev/null; echo $?)
CURRENT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
RANGES="$CURRENT_DIR"/aws_nets.txt
LOG="$CURRENT_DIR"/aws_nets.log

function adate() {
    while IFS= read -r line; do
        printf '%s %s\n' "$NOW" "$line";
    done
 }

function manage_routes() {
    cat < "$RANGES" | while IFS= read -r line
    do
        sudo /sbin/route "$ACTION" -net "$line" "$CHECK_TG_IP"
    done
    echo "Added routes$(wc -l "$RANGES"|cut -d/ -f-1)" |adate| tee -a "$LOG"
}

function change_routes() {
    if [ "$PING_STAT" -eq 0 ]; then
        echo "Attempting to change routes..." |adate| tee -a "$LOG"
        manage_routes
    else
        echo "Destination gateway does not exists." |adate| tee -a "$LOG"
        ACTION=del; manage_routes
    fi
}

function get_ranges() {
    NEW_RANGES=$(curl -s https://ip-ranges.amazonaws.com/ip-ranges.json \
    |grep ip_prefix|awk -F":" '{gsub(/"/, "", $2);print $2}'|cut -d, -f1|cut -d" " -f2-)
    if [[ -n $NEW_RANGES  ]]; then
        echo "$NEW_RANGES" > "$RANGES"
    else
        echo "Looks like target host unreachable: $NEW_RANGES" |adate|tee -a "$LOG"| exit 1
    fi
}

function main() {
    if [ ! -f "$RANGES" ]; then
        echo "$RANGES File not found!" |adate| tee -a "$LOG"
        get_ranges
        change_routes
    else
        EXIST_ROUTE=$(netstat -nr4|awk '{print $1}'|grep -q "$(head -n1 "$RANGES" \
        |awk -F":" '{gsub(/"/, "", $2); print $2}'|cut -d"," -f1|cut -d" " -f2-)"; echo $?)
        if [ $(( $(date +%s) - $(stat -f %m "$RANGES") )) -gt 43200 ]; then
            echo "$RANGES was no modified in last 12 Hours(43200s)" |adate| tee -a "$LOG"
            get_ranges
            change_routes
        else
            if [ "$EXIST_ROUTE" -ne 0 ]; then
                change_routes
            else
                echo "Looks like aws routes already presented, grep code: $EXIST_ROUTE" |adate| tee -a "$LOG"
            fi
        fi
    fi
}

main