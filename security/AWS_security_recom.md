# Security review

## The Suggestion list of security improvements that will help to harden resources, services and managed data according to best practices

### 1. Use AWS Identity and Access Management (IAM)

- **Root Account Protection**: Minimize the use of the root account. Create individual IAM users for people accessing your account.
- **Multi-Factor Authentication (MFA)**: Enable MFA for all users, especially for the root account and privileged IAM users, make sure that users can manage their MFA devices, and have no permissions until the MFA been set.
- **Least Privilege Principle**: Grant the least privileges necessary for users and services to perform their tasks. Regularly review and prune unnecessary permissions.

### 2. Monitor and Audit with AWS CloudTrail and Amazon CloudWatch

- **Use CloudWatch**: Utilize Amazon CloudWatch to monitor and alert on suspicious activities. Set up alarms for unusual API activity or unauthorized resource modifications.

### 3. Secure Your Data

- **Encryption**: Use AWS Key Management Service (KMS) to manage and rotate encryption keys. Encrypt data at rest and in transit across all services (e.g., S3, EBS, RDS).
- **Data Backup**: Regularly back up your data using AWS Backup or other mechanisms to protect against accidental or malicious deletion.

### 4. Network Security

- **VPC Security**: Utilize Virtual Private Cloud (VPC) to isolate your AWS resources. Implement security groups and network access control lists (NACLs) to control inbound and outbound traffic, prevent using the default VPC.
- **Bastion Hosts**: Use ssm instead of bastion hosts for secure SSH access to instances in private subnets.

### 5. Utilize AWS Security Services

- **AWS WAF and AWS Shield**: Use AWS WAF (Web Application Firewall) to protect your web applications from common web exploits. AWS Shield provides managed DDoS protection, configure a public access for the only expected sub net ranges or countries.

  1. Consider to enable WAF SQL database That contains rules that allow you to block request patterns associated with exploitation of SQL databases, like SQL injection attacks. This can help prevent remote injection of unauthorized queries.  Learn More

### 6. Regular Audits and Continuous Improvement

- **Stay Informed**: Keep up with AWS security announcements and best practices. Regularly update and patch services and applications deployed on AWS.

Implementing these practices will significantly improve the security of AWS account and the resources deployed in it. Security is an ongoing process, requiring regular reviews and updates to practices we use as new threats emerge and AWS introduces new features and services as well as performing security tests.
