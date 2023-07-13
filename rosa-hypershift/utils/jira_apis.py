import json
import boto3
from botocore.exceptions import ClientError
from jira import JIRA
from jira.exceptions import JIRAError

jira_url = 'https://issues.redhat.com/'

def retreive_api_token(secret_name):
    client = boto3.client('secretsmanager')
    try:
        response = client.get.secret_value(SecretId=secret_name)
        if 'SecretString' in response:
            secret_data = response['SecretString']
            secret_dict = json.loads(secret_data)
            api_token = secret_dict['api_token']
            return api_token
        else:
            print("Secret value is not a string, cannot retreive")
            return None
    except Exception:
        print("Failed to retreive API token from Secrets Manager")
        return None

def aws_get_secret():
    secret_name = "jira_api"
    region_name = "us-west-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']
    return secret

try:
    jira_secret = aws_get_secret()
    api_token = retreive_api_token(jira_secret)
    jira = JIRA(server=jira_url, token_auth=(api_token))
except JIRAError as e:
    print("Failed to connect to JIRA: " + str(e))
    exit(1)
 
def verify_issue_id(issue_id):
    try:
        issue = jira.issue(issue_id)
        print(f"Issue '{issue.key}' exists.")
        return True
    except Exception:
        print(f"Not a valid issue ID: {issue_id}")