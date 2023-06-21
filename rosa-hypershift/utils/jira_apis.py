from jira import JIRA
from jira.exceptions import JIRAError
# import argparse
import boto3
import json

'''
parser = argparse.ArgumentParser(description="hypershift wrapper script")
parser.add_argument(
    '--ticket_id',
    type=str,
    help='Pass issue id'
)

parser.add_argument(
    '--api_token',
    type=str,
    help='Pass JIRA API Token'
)
args = parser.parse_args()
api_token = args.api_token
issue_id = args.ticket_id
'''

jira_url = 'https://issues.redhat.com/'
 
### api_token ='XXXYYYZZZ'

try:
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