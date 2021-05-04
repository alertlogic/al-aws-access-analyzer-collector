# -*- coding: utf-8 -*-

import os
import logging
import sys
import json
import boto3


from almdrlib import Session
from .lib.asset_model_schema import get_asset_key
from .lib.scan_result import add_scan_result
from .vulnerabilities import get_vulnerability 


WAIT_TIME = 5   # Wait for 5 seconds

log_level = os.getenv('LOG_LEVEL', 'INFO')

LOGGER = logging.getLogger()
LOGGER.setLevel(log_level)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)


COLLECTOR_CLEAN_FINDINGS = False
if os.environ.get('Clean')=='True' and os.environ['Clean'] != 'False':
    COLLECTOR_CLEAN_FINDINGS = True


SUPPORTED_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-east-1",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-northeast-1",
    "ap-southeast-2",
    "ap-southeast-1",
    "ca-central-1",
    "eu-central-1",
    "eu-central-1",
    "eu-west-2",
    "eu-south-1",
    "eu-west-3",
    "eu-north-1",
    "me-south-1",
    "sa-east-1"
]


processed_iam_findings=False
def handler(event, context):
    LOGGER.info(f"Received event: {json.dumps(event, default=str)}")
    LOGGER.info("COLLECTOR_CLEAN_FINDINGS: %r" % COLLECTOR_CLEAN_FINDINGS)

    #try:
    status_code = collect(event, SUPPORTED_REGIONS, COLLECTOR_CLEAN_FINDINGS)
    return {'statusCode': status_code}

    #except: # catch *all* exceptions
    #    LOGGER.error(f"Collect raised {sys.exc_info()[0]} exception")
    #    return {'statusCode': 500}

def collect(event, regions, clean_findings):
    # Get AWS Account ID
    session = boto3.session.Session()
    aws_account_id = session.client("sts").get_caller_identity()["Account"]
    LOGGER.info(f"Running in '{aws_account_id}' AWS Account context")

    # Get Alert Logic Deployment
    al_session = _get_al_session(session)
    deployment_id = _get_deployment_id(al_session, aws_account_id)
    if not deployment_id:
        return 404

    # Get AWS Access Analyzer Findings
    account_id = al_session.account_id
    base_url = al_session.get_url('scan_result', account_id=account_id)
    scan_result_url = f'{base_url}/scan_result/v1/{account_id}'
    LOGGER.info(f"Using {scan_result_url} scan result URL")

    iam_client = session.client('iam')

    for region in regions:
        LOGGER.info(f"Getting analyzers for '{region}' region")
        try:
            aws_access_analyzer_client = session.client("accessanalyzer", region_name=region)
            response = aws_access_analyzer_client.list_analyzers(type='ACCOUNT')
            analyzers = json.loads(json.dumps(response, default=str))['analyzers']
    
            # scan_result_client = s.client('scan_result')
            for analyzer in analyzers:
                # Declare findings
                LOGGER.debug(f"### Processing AWS Access Analyzer 'Active' Findings for '{region}' region.")
                process_findings(
                    aws_access_analyzer_client, al_session, scan_result_url,
                    iam_client, aws_account_id,
                    region, analyzer['arn'], deployment_id, active=True
                )
    
                # Clear archived findings
                LOGGER.debug(f"### Processing AWS Access Analyzer 'Archived' Findings for '{region}' region.")
                process_findings(
                    aws_access_analyzer_client, al_session, scan_result_url,
                    iam_client, aws_account_id,
                    region, analyzer['arn'], deployment_id,
                    active=False
                )
                        
        except Exception as e:
            LOGGER.error(f"Failed to get analyzers. Error: {str(e)}")
            continue
        
    return 200

def process_findings(access_client, al_session, scan_result_url,
                    iam_client, aws_account_id,
                    region, analyzer_arn, deployment_id, active=False):
    global processed_iam_findings
    if processed_iam_findings:
        filter = {
                "status": {"eq": ["ACTIVE" if active else "ARCHIVED"]},
                "resourceType": {"neq": ["AWS::IAM::Role"]}
            }
    else:
        filter = {
                "status": {"eq": ["ACTIVE" if active else "ARCHIVED"]}
            }
        processed_iam_findings=True

    # Get Analyzer Findings
    LOGGER.debug("Getting findings. arn: '{analyzer_arn}', filter = '{filter}'")
    response = access_client.list_findings(analyzerArn = analyzer_arn, filter=filter)
    while True:
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            # Declare Vulnerabilities in ActiveWatch
            declare_vulnerabilities(
                    al_session,
                    scan_result_url,
                    iam_client,
                    aws_account_id,
                    deployment_id,
                    response['findings'],
                    active
                )
            if 'nextToken' not in response:
                break
        response = access_client.list_findings(
                analyzerArn = analyzer_arn, filter=filter, nextToken=response['nextToken'])

def declare_vulnerabilities(al_session, scan_result_url, iam_client, aws_account_id, deployment_id, findings, active):
    processed = 0
    for finding in findings:
        key = get_asset_key(
            'aws', finding['resource'],
            native_resource_type=finding['resourceType'], native_account_id=finding['resourceOwnerAccount']
        )
        if key is None:
            LOGGER.warn(f"Unsupported AWS Resource Type for finding: {json.dumps(finding, default=str)}")
            continue

        vulnerability = get_vulnerability(iam_client, finding)
        if vulnerability is None:
            LOGGER.warn(f"No content for {json.dumps(finding, default=str)}")
            continue

        res = add_scan_result(
            al_session, scan_result_url,
            'custom', 'AWSAccessAnalyzerCollector',
            deployment_id, key, 'aws_access_analyzer_collector_v1',
            [vulnerability]
        )
        processed += 1
        LOGGER.debug("Added AWS Access Analyzer scan result. Deployment ID: '{}', Asset: '{}'. Result: {}".format(
            deployment_id, key, json.dumps(res.json(), default=str)))
    LOGGER.info(f"Declared {processed} vulnerabilities")
    
    return 200


### Internal functions

# Get Alert Logic SDK session
def _get_al_session(target_session):
    kwargs = {
        'residency': 'default',
        'global_endpoint': os.environ['Endpoint'].lower()
    }
    
    if 'SecretName' in os.environ:
        al_credentials = _get_secret(target_session, os.environ['SecretName'])
        if not al_credentials:
            raise ValueError(f"Invalid Secret: {secret_name}")

        auth = json.loads(al_credentials)
        LOGGER.info(f"auth: {json.dumps(auth, default=str)}")
        kwargs['access_key_id'] = auth['AccessKeyId']
        kwargs['secret_key'] = auth['SecretKey']
        if 'AccountId' in auth:
            kwargs['account_id'] = auth.get('AccountId')
    else:
        kwargs['access_key_id'] = os.environ.get('AccessKeyId')
        kwargs['secret_key'] = os.environ.get('SecretKey')
        if account_id in os.environ:
            kwargs['account_id'] = os.environ.get('AccountId')

    LOGGER.info(f"Initialization session with {kwargs} arguments")
    return Session(**kwargs)


# Get Deployment ID that protects this AWS Account
def _get_deployment_id(session, aws_account_id):
    try:
        client = session.client("deployments")
        deployments = client.list_deployments().json()
        for deployment in deployments:
            platform = deployment['platform']
            if platform['type'] == 'aws' and platform['id'] == aws_account_id:
                LOGGER.info(f"Alert Logic Deployment ID: {deployment['id']}")
                return deployment['id']

        LOGGER.info(f"Account {aws_account_id} is not protected by Alert Logic MDR")
        return None
    except Exception as e:
        LOGGER.exception(f"Failed to list deployments. Error: {str(e)}")


# Get Alert Logic API credentials from AWS Secrets Manager
def _get_secret(target_session, secret_name):
    '''
    Get Alert Logic API Credentials
    '''
    secret_client = target_session.client('secretsmanager')
    try:
        get_secret_value_response = secret_client.get_secret_value(
            SecretId=secret_name
        )
    except Exception as e:
        LOGGER.info(f"Get Secret Failed: {str(e)}")
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(
                    get_secret_value_response['SecretBinary']
                )
            return decoded_binary_secret

