## The script that helps to make sure that target IPs are available.

That small bash script test via ICMP target hosts resolving them by DNS name in case issue will sen the alert message via Slack.

## Requirements:

- Tested on OSX and Ubuntu Linux.
- The `slacktee` configured properly for more see https://github.com/coursehero/slacktee.
- Expected to be performed periodically for example via CRON.

Also please make sure that targets are resolving according to their IPs, other wise fill free to use ip addresses instead.

## How to use:

```
crontab -e
*/1 * * * * bash ~/scripts/ping_targets/dst_ping.sh | logger
```
