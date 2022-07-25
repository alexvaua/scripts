# The script to scan and reporting docker vulnerabilities stored in ECR.

This script is designed to preform scanning and generate reports on vulnerabilities
are that found in the docker images stored in ECR repositories in a particular account
and region.

The summary of findings can be published to the SNS topic if presented via `-o` options.

If the slack token filed up via option `-s` or presented in env `SLACK_TOKEN` the summary
will be published to general channel or particular one via option `-c` or via env
`SLACK_CHANNEL` variable.

The entire report is by default stored in a temporary file on the local file system also
can be stored in particular S3 bucket if presented via `-b` option.

```bash
Usage: ecr_scan_report [OPTIONS]

  Main function, to manage scan on vulnerability of images and generate
  report of findings

Options:
  -a, --account TEXT         AWS_ACCOUNT_ID(AWS_ACCOUNT_ID) can be passed via
                             env  [default: *]

  -r, --region TEXT          AWS_REGION(AWS_REGION) can be passed via env
                             [default: us-east-1]

  -n, --reponame TEXT        specifies a repository name .. defaults to '*',
                             meaning scan all  [default: *]

  -e, --exclude TEXT         Specify repository/s in order to ignore actions
                             on them: -e '[repo1,repo2,...]'  [default: ]

  -o, --snstopicarn TEXT     SNS topic arn to scan summary to.  [default:
                             False]

  -s, --slacktoken TEXT      Slack token to send summary to the slack cannel.
                             [default: False]

  -c, --slackchannel TEXT    Slack token to send summary to the slack channel.
                             [default: random]

  -b, --bucket TEXT          S3 bucket to place reports in json format to.
                             [default: False]

  -m, --imageage INTEGER     The age of an image (h) to considered to be too
                             old for scanning  [default: 48]

  -j, --job [scan|report]    The job should be performed possible can be
                             `report` or `scan`  [default: scan]

  -l, --log_level TEXT       The logging level can be configured via
                             `LOGLEVEL` variable over env  [default: INFO]

  --tags_all / --tag_latest  Perform action on all tags are published within
                             repository  [default: False]

  -h, --help                 Show this message and exit.                Show this message and exit.
```
