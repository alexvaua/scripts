#!/usr/bin/env bash
set -e

PROFILE_NAME=${PROFILE_NAME:-$(aws sts get-caller-identity --query Arn --output text|cut -d ":" -f6| cut -d "/" -f2)}
JUMP_ACCOUNT_ID=${JUMP_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}
[[ -z ${ASSUME_ROLE} ]] && echo "Please provide the ASSUME_ROLE=[ARN] of the role to assume tmp credentials from!" && exit 1

role_pass=$(aws sts assume-role --role-arn "${ASSUME_ROLE}" --role-session-name "${PROFILE_NAME}" --output json \
	--serial-number arn:aws:iam::"${JUMP_ACCOUNT_ID}":mfa/"${PROFILE_NAME}" \
	--token-code $(ykman oath accounts code | awk -F'[" "]' '$1 {print $5}'))

access_key_id=$(echo "$role_pass" | jq -r ".Credentials.AccessKeyId")
secret_access_key=$(echo "$role_pass" | jq -r ".Credentials.SecretAccessKey")
session_token=$(echo "$role_pass" | jq -r ".Credentials.SessionToken")

aws configure set aws_access_key_id "${access_key_id}" --profile "$PROFILE_NAME"
aws configure set aws_secret_access_key "${secret_access_key}" --profile "$PROFILE_NAME"
aws configure set aws_session_token "${session_token}" --profile "$PROFILE_NAME"

echo -e "export AWS_ACCESS_KEY_ID=${access_key_id}\nexport AWS_SECRET_ACCESS_KEY=${secret_access_key}\nexport AWS_SESSION_TOKEN=${session_token}"

if ! [ $# -eq 0 ]; then
	"$@" --profile "$PROFILE_NAME"
fi
