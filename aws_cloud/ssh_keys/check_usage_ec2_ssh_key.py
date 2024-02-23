"""The script to get ec2 instance ssh keys and check usage"""
import os
import boto3

session = boto3.Session(profile_name=os.getenv("AWS_PROFILE", "default"))


def get_regions_with_running_instances():
    """Function return the list of regions"""
    ec2_client = session.client('ec2')

    response = ec2_client.describe_regions()

    regions_with_instances = []
    for element in response['Regions']:
        region_name = element['RegionName']

        ec2_client = session.client('ec2', region_name=region_name)

        instances = ec2_client.describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )

        if instances['Reservations']:
            regions_with_instances.append(region_name)

    return regions_with_instances


def get_instance_ssh_keys(aws_region):
    """Function returns the list of instance with keys in the region"""
    ec2_client = session.client('ec2', region_name=aws_region)

    response = ec2_client.describe_instances(
        Filters=[
            {'Name': 'instance-state-name', 'Values': ['running']}
        ]
    )

    ssh_keys = {}
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if 'KeyName' in instance and 'InstanceId' in instance:
                ssh_key_name = instance['KeyName']
                inst_id = instance['InstanceId']
                ssh_keys[inst_id] = ssh_key_name

    return ssh_keys


def get_all_ssh_keys():
    """Function returns the list of all keys"""
    ec2_client = session.client('ec2')

    response = ec2_client.describe_key_pairs()

    return [key['KeyName'] for key in response['KeyPairs']]


def remove_unused_ssh_keys(keys_to_remove):
    """Remove unused keys"""
    ec2_client = session.client('ec2')
    for key in keys_to_remove:
        print(f"Deleting key: {key}")
        ec2_client.delete_key_pair(KeyName=key)
        print(f"Key {key} deleted successfully.")


def main():
    """The entrance function"""
    all_ssh_keys = get_all_ssh_keys()

    for region in get_regions_with_running_instances():
        instance_ssh_keys = get_instance_ssh_keys(region)

        print(f"### Looking into {region}")
        if instance_ssh_keys:
            print("Instance SSH Keys:")
            for instance_id, ssh_key in instance_ssh_keys.items():
                print("Instance ID: ", instance_id)
                print("Key: ", ssh_key)
                print("----------------------")
        else:
            print(f"Found instances are up and running, "
                  f"but No SSH keys are attached in the: {region}")

    unused_keys = [key for key in all_ssh_keys if key not in set(instance_ssh_keys.values())]

    print("\nUnused SSH Keys:")
    if unused_keys:
        for key in unused_keys:
            print(key)
        response = input("\nDo you want to delete these unused keys? (yes/no): ").strip().lower()
        if response == "yes":
            remove_unused_ssh_keys(unused_keys)
        elif response == "no":
            print("Unused keys will not be deleted.")
        else:
            print("Invalid input. Unused keys will not be deleted.")
    else:
        print("No unused SSH keys found.")


if __name__ == "__main__":
    main()
