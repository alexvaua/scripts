# EC2 SSH Key Management Script

## Introduction

This Python script is designed to manage SSH keys for EC2 instances in AWS. It allows you to list SSH keys used by running instances across all regions, identify unused SSH keys, and offers the option to delete these unused keys. This can help in managing access to EC2 instances and ensuring security compliance.

## Prerequisites

- Python 3.x
- Boto3 library
- AWS CLI (optional, for configuring AWS credentials)

## Installation

### 1. Install Python 3.x

Ensure you have Python 3 installed on your system. Download it from [python.org](https://www.python.org/downloads/).

### 2. Install Boto3

Boto3 is the Amazon Web Services (AWS) SDK for Python. Install Boto3 using pip:

```bash
pip install boto3
```

### 3. Configure AWS Credentials

The script uses Boto3, which requires AWS credentials to interact with your AWS account. These credentials should have appropriate permissions to access EC2 instances and SSH keys. Configure AWS credentials in one of the following ways:

- Via environment variables:

  ```bash
  export AWS_ACCESS_KEY_ID="your_access_key"
  export AWS_SECRET_ACCESS_KEY="your_secret_key"
  export AWS_DEFAULT_REGION="your_default_region"
  ```

- Using the AWS CLI:

  ```bash
  aws configure
  ```

- Or by directly editing the AWS credentials file, typically located at
  `~/.aws/credentials`

## Usage

### Set AWS Profile (Optional)

If you are using a specific AWS profile, set it using the environment variable `AWS_PROFILE`. If not set, the default profile will be used.

```bash
export AWS_PROFILE="your_aws_profile"
```

### Run the Script

Execute the script using Python:

```bash
python path/to/check_usage_ec2_ssh_key.py
```

### Follow the Prompts

The script will display the SSH keys used by running instances and list any unused SSH keys. You will have the option to delete unused keys based on the script's prompt.

## Note on AWS Credentials

Ensure that the AWS credentials used have the necessary permissions to perform actions on EC2 instances and SSH keys. This includes permissions to list instances, describe key pairs, and delete key pairs. Use the script responsibly, as deleting SSH keys cannot be undone and may affect access to instances.
