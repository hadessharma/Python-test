from datetime import datetime, timedelta, timezone
import boto3
import pandas as pd

# Create a session using the default credentials chain
session = boto3.Session()

# Define the associative array mapping session names to role ARNs
session_to_role = {
    "[Account1-name]":"arn:aws:iam::17703213237:role/Admin",
    "[Account2-name]":"arn:aws:iam::17703213237:role/Admin",
    
    # Add other sessions here
}

# Create an empty list to store instance information for EC2 and RDS
instance_data = []

# Iterate over the session names and corresponding role ARNs
for session_name, role_arn in session_to_role.items():
    try:
        # Assume the role
        sts_client = session.client('sts')
        assumed_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)

        # Create a new session using the temporary credentials
        temporary_credentials = assumed_role['Credentials']
        temporary_session = boto3.Session(
            aws_access_key_id=temporary_credentials['AccessKeyId'],
            aws_secret_access_key=temporary_credentials['SecretAccessKey'],
            aws_session_token=temporary_credentials['SessionToken']
        )

        # Create an EC2 client using the temporary session
        ec2_client = temporary_session.client('ec2', region_name='ap-southeast-2')
        # Create an RDS client using the temporary session
        rds_client = temporary_session.client('rds', region_name='ap-southeast-2')

        # Describe EC2 instances
        ec2_instances_response = ec2_client.describe_instances()
        # Describe RDS instances
        rds_instances_response = rds_client.describe_db_instances()

        # Process EC2 instance information
        for reservation in ec2_instances_response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                account_name = session_name
                account_id = assumed_role['AssumedRoleUser']['Arn'].split(":")[4]
                state = instance['State']['Name']
                uptime = None
                if 'LaunchTime' in instance:
                    current_time = datetime.now().replace(tzinfo=timezone.utc)
                    launch_time = instance['LaunchTime'].replace(tzinfo=timezone.utc)
                    uptime_seconds = (current_time - launch_time).total_seconds()
                    uptime_days = uptime_seconds // 86400
                    uptime_hours = (uptime_seconds % 86400) // 3600
                    uptime_minutes = (uptime_seconds % 3600) // 60
                    uptime = f"{int(uptime_days)} days, {int(uptime_hours)} hours, {int(uptime_minutes)} minutes"
                instance_data.append([account_name, account_id, instance_id, instance_type, instance_name, state, uptime, 'EC2'])

        # Process RDS instance information
        for db_instance in rds_instances_response['DBInstances']:
            instance_id = db_instance['DBInstanceIdentifier']
            instance_type = db_instance['DBInstanceClass']
            instance_name = db_instance['DBInstanceIdentifier']
            account_name = session_name
            account_id = assumed_role['AssumedRoleUser']['Arn'].split(":")[4]
            state = db_instance['DBInstanceStatus']
            uptime = None
            if 'InstanceCreateTime' in db_instance:
                current_time = datetime.now().replace(tzinfo=timezone.utc)
                launch_time = db_instance['InstanceCreateTime'].replace(tzinfo=timezone.utc)
                uptime_seconds = (current_time - launch_time).total_seconds()
                uptime_days = uptime_seconds // 86400
                uptime_hours = (uptime_seconds % 86400) // 3600
                uptime_minutes = (uptime_seconds % 3600) // 60
                uptime = f"{int(uptime_days)} days, {int(uptime_hours)} hours, {int(uptime_minutes)} minutes"
            instance_data.append([account_name, account_id, instance_id, instance_type, instance_name, state, uptime, 'RDS'])

    except Exception as e:
        print(f"Error occurred for session '{session_name}': {e}")
        continue  # Skip to the next session in case of error

# Create a DataFrame for all instances
df = pd.DataFrame(instance_data, columns=['Account Name', 'Account ID', 'Instance ID', 'Instance Type', 'Instance Name', 'State', 'Uptime', 'Resource Type'])

# Export DataFrame to Excel
df.to_excel('ec2_rds_details.xlsx', index=False)

print("Instance information exported to ec2_rds_details.xlsx")
