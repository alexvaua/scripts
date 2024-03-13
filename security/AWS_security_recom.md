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

### 7. Vulnerability Scanning and rotation plan

- **(Automated)Vulnerability Scans**: Integrate a image scan in to CI pipeline
- **Develop/implement upgrade plan**: Make sure that you have a back log with rotate and decommission docker images with CRITICAL, HIGH vulnerabilities with at least fixable ones.
- **Upgrade and rotate EC2 AMI**: Establish the pipeline to continuously upgrade and rotate AMI for any EC2 workload.

### 8. Compliance and Best Practices (Inspector, AWS config, SecurityHub)

- Please follow the recommendations collected in Security hub and config rules in order to plan security adjustments according to the [table](./NON_COMPLIANT.md)
- Priorities actions to fix issues according to Security Hub [filter](https://us-east-1.console.aws.amazon.com/securityhub/home?region=us-east-1#/findings?search=SeverityLabel%3D%255Coperator%255C%253AEQUALS%255C%253ACRITICAL%26Title%3D%255Coperator%255C%253APREFIX_NOT_EQUALS%255C%253ACVE%26Region%3Dus-east-1%26WorkflowStatus%3D%255Coperator%255C%253AEQUALS%255C%253ANEW%26WorkflowStatus%3D%255Coperator%255C%253AEQUALS%255C%253ANOTIFIED%26RecordState%3D%255Coperator%255C%253AEQUALS%255C%253AACTIVE%26SeverityLabel%3D%255Coperator%255C%253AEQUALS%255C%253AHIGH)

### 9. Code/IaC delivery protection

- **Access Control**: Limit access to repositories based on the principle of least privilege, setup branch protection for the main branche, no one can push directly in main only via PR/MR, apply the same for IaC repositories.
- **Two-Factor Authentication (2FA)**: Enforce 2FA for accessing code repositories.
- **Pipeline Security**: Ensure CI/CD pipelines are secure by design, with restricted access to the pipeline environment.
- **Automated Testing**: Incorporate automated security testing and code analysis tools into the CI/CD pipeline to detect vulnerabilities early.
- **Peer Reviews**: Implement mandatory peer reviews to identify security flaws and coding errors before code merges, only reviewer can approve PR not commiter.
- **Immutable Artifacts**: Use immutable artifacts for deployment to ensure that the code cannot be tampered with after it has been built.

> **Tools and Technologies**: Leveraging tools that integrate with your development and deployment stack can significantly enhance code delivery protection. Proposed:

- Secrets Management: AWS SSM parameter store, AWS Secrets Manager.
- Code Analysis: SonarQube, Fortify, Checkmarx.
- CI/CD Tools: Consider GitHub Actions with security plugins or extensions insted of CircleCI.
- Monitoring and Alerting: CloudWatch, Slack, possible Panther.

### 10. Regular Audits and Continuous Improvement

- **Incorporate security adjustments in to IaC**: Avoid manual fixes - Consider to implement or extend infrastructure templates according to security recommengations, that will help to avoid potential mistaces and save time in a future.

- **Stay Informed**: Keep abreast of AWS security announcements and best practices. Continuously update and patch services and applications deployed on AWS.

Implementing these practices will significantly enhance the security posture of your AWS account and its resources. Remember, security is an ongoing process that requires continuous attention and adaptation to new threats and AWS updates.
