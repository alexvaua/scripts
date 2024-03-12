# Security Review

## Suggested List of Security Improvements

This document outlines security improvements to harden resources, services, and managed data according to best practices.

### 1. Use AWS Identity and Access Management (IAM)

- **Multi-Factor Authentication (MFA)**: Enable MFA for all users. Ensure users have no permissions until MFA is configured.
- **Least Privilege Principle**: Adhere to the least privilege principle by granting users and services only the permissions necessary to perform their duties. Regularly review and remove unnecessary permissions.
- **Best Practices**: Implement a strong password policy as recommended by AWS IAM best practices [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- **IAM Access Analyzer**: Utilize the IAM Access Analyzer to assess resources for external access and review IAM users and roles for unused permissions. Plan remedial actions based on the review [AWS Access Analyzer](https://us-east-1.console.aws.amazon.com/access-analyzer/home?region=us-east-1).

### 2. Monitor and Audit with AWS CloudTrail and Amazon CloudWatch

- **CloudWatch Usage**: Deploy Amazon CloudWatch to monitor and alert on suspicious activities. Configure alarms for unusual API activity or unauthorized modifications, and forward critical alerts to the appropriate channels.

### 3. Secure Your Data

- **Encryption**: Leverage AWS Key Management Service (KMS) for encryption key management and rotation. Ensure encryption of data at rest and in transit across all services (e.g., EBS, RDS).
- **Data Backup**: Employ regular data backup strategies using AWS Backup or similar services to safeguard against data loss.

### 4. Network Security

- **VPC Security**: Utilize security groups and network access control lists (NACLs) for traffic control. Avoid using the default VPC for enhanced security.

### 5. Extend AWS Security Services

- **AWS WAF and AWS Shield**:

  - Consider to enable `WAF SQL` database That contains rules that allow you to block request patterns associated with exploitation of SQL databases, like SQL injection attacks. This can help prevent remote injection of unauthorized queries. Learn More.

### 6. Penetration Testing & Vulnerability Scanning

- **(Automated)Vulnerability Scans**: Conduct internal vulnerability scans within your VPC using tools like OpenVAS [OpenVAS](https://www.openvas.org) on a regular basis to identify and mitigate potential vulnerabilities - [probely](https://probely.com).

- **(Manual)Penetration Tests**: Engage in penetration testing through bug bounty programs such as HackerOne's Bug Bounty Platform [HackerOne](https://www.hackerone.com/product/bug-bounty-platform), to uncover and rectify security vulnerabilities before they can be exploited.

### 7. Regular Audits and Continuous Improvement

- **Stay Informed**: Keep abreast of AWS security announcements and best practices. Continuously update and patch services and applications deployed on AWS.

Implementing these practices will significantly enhance the security posture of your AWS account and its resources. Remember, security is an ongoing process that requires continuous attention and adaptation to new threats and AWS updates.
