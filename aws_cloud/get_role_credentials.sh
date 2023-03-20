#!/usr/bin/env bash
set -e

PROFILE_NAME=${PROFILE_NAME:-"default"}
[[ -z ${ASSUME_ROLE} ]] && echo "Please provide the ASSUME_ROLE=[ARN] of the role to assume tmp credentials from!" && exit 1

role_pass=$(aws sts assume-role --role-arn "${ASSUME_ROLE}" --role-session-name "$PROFILE_NAME" --output json)
aws configure set aws_access_key_id "$(echo "$role_pass" | jq -r ".Credentials.AccessKeyId")" --profile "$PROFILE_NAME"
aws configure set aws_secret_access_key "$(echo "$role_pass" | jq -r ".Credentials.SecretAccessKey")" --profile "$PROFILE_NAME"
aws configure set aws_session_token "$(echo "$role_pass" | jq -r ".Credentials.SessionToken")" --profile "$PROFILE_NAME"

if ! [ $# -eq 0 ]; then
    "$@" --profile "$PROFILE_NAME"
fi