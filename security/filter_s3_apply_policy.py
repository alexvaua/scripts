import json

import boto3


def deny_s3_access(profile_name, region):
    session = boto3.Session(profile_name=profile_name, region_name=region)

    s3 = session.client("s3")
    bucket_names = [
        bucket["Name"]
        for bucket in s3.list_buckets()["Buckets"]
        if "uat" in bucket["Name"]
    ]

    for bucket_name in bucket_names:
        print(f"Attaching policy to {bucket_name}")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyBeforeRemove",
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Principal": "*",
                }
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    print(f"Access denied for S3 buckets with {bucket_names} in the name.")


if __name__ == "__main__":
    deny_s3_access(profile_name="haiku_dev", region="us-west-2")
