"""Script to collect security info from the AWS account"""
import os
import boto3

session = boto3.Session(profile_name=os.getenv("AWS_PROFILE", "default"))


def get_running_instances_ip():
    """Connect EC2 IPs"""
    ec2 = session.client("ec2")

    filters = [{"Name": "instance-state-name", "Values": ["running"]}]

    reservations = ec2.describe_instances(Filters=filters)["Reservations"]

    internal_ips = []
    external_ips = []
    for reservation in reservations:
        for instance in reservation["Instances"]:
            internal_ips.append(
                {
                    "Instance ID": instance["InstanceId"],
                    "Private IP": instance.get("PrivateIpAddress"),
                }
            )
            if public_ip := instance.get("PublicIpAddress"):
                external_ips.append(
                    {"Instance ID": instance["InstanceId"], "Public IP": public_ip}
                )
    return internal_ips, external_ips


def get_rds_endpoints():
    """Collect endpoints of RDS instances."""
    rds = session.client("rds")
    db_instances = rds.describe_db_instances()["DBInstances"]
    rds_endpoints = [
        {
            "DBInstanceIdentifier": db["DBInstanceIdentifier"],
            "Endpoint": db["Endpoint"]["Address"],
        }
        for db in db_instances
    ]
    return rds_endpoints


def get_load_balancer_endpoints():
    """Collect DNS names of ALBs and NLBs."""
    elb = session.client("elbv2")
    load_balancers = elb.describe_load_balancers()["LoadBalancers"]
    lb_endpoints = [
        {
            "LoadBalancerName": lb["LoadBalancerName"],
            "DNSName": lb["DNSName"],
            "Type": lb["Type"],
        }
        for lb in load_balancers
        if lb["Type"] in ["application", "network"]
    ]
    return lb_endpoints


def main():
    """Main function"""
    internal_ips, external_ips = get_running_instances_ip()

    response = input("\nDo you want to print the IPs only? (yes/no): ").strip().lower()

    print("Internal IP Addresses:")
    for elem in internal_ips:
        if response == "yes":
            print(elem.get("Private IP"))
        else:
            print(elem)

    print("\nExternal IP Addresses:")
    for elem in external_ips:
        if response == "yes":
            print(elem.get("Public IP"))
        else:
            print(elem)

    print("\nRDS Endpoints:")
    for elem in get_rds_endpoints():
        if response == "yes":
            print(elem.get("Endpoint"))
        else:
            print(elem)

    print("\nLB Endpoints:")
    for elem in get_load_balancer_endpoints():
        if response == "yes":
            print(elem.get("DNSName"))
        else:
            print(elem)


if __name__ == "__main__":
    main()
