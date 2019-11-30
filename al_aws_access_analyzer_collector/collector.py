# -*- coding: utf-8 -*-

import os
import sys
import json
import boto3

from activewatch import client
from activewatch.session import Session
from activewatch.asset_model_schema import get_asset_key
from al_aws_access_analyzer_collector.vulnerabilities import get_vulnerability 

COLLECTOR_CLEAN_FINDINGS = False
if os.environ.get('Clean')=='True' and os.environ['Clean'] != 'False':
    COLLECTOR_CLEAN_FINDINGS = True

SUPPORTED_REGIONS = [
    "us-east-1",
    "us-west-2"
]

def handler(event, context):
    print("COLLECTOR_CLEAN_FINDINGS: %r" % COLLECTOR_CLEAN_FINDINGS)
    os.environ['AWS_DATA_PATH'] = os.path.join(os.getcwd(), 'models')

    try:
        status_code = collect(event, SUPPORTED_REGIONS, COLLECTOR_CLEAN_FINDINGS)
        return {'statusCode': status_code}

    except: # catch *all* exceptions
        print("Collect raised {} exception".format(sys.exc_info()[0]))
        return {'statusCode': 500}

def collect(event, regions, clean_findings):
    # Get AWS Account ID
    session = boto3.session.Session()
    aws_account_id = session.client("sts").get_caller_identity()["Account"]
    print("Running in '" + aws_account_id+ "' AWS Account context")

    # Get Alert Logic Deployment
    s = Session(os.environ.get('AccessKeyId'),
                os.environ.get('SecretKey'),
                account_id = os.environ.get('AccountId'),
                global_endpoint = "production" if os.environ.get('Endpoint') is None else os.environ['Endpoint'])

    deployment_id = _get_deployment_id(s, aws_account_id)

    # Get AWS Access Analyzer Findings
    iam_client = session.client('iam')
    for region in regions:
        aws_access_analyzer_client = session.client("citadel", region_name=region)
        response = aws_access_analyzer_client.list_analyzers()
        analyzers = json.loads(json.dumps(response, default=str))['analyzers']

        scan_result_client = s.client('scan_result')
        for analyzer in analyzers:
            # Declare findings
            print("### Processing AWS Access Analyzer Active Findings for '{}' region.".format(region))
            process_findings(aws_access_analyzer_client, scan_result_client, iam_client,
                    region, analyzer['arn'], deployment_id)

            # Clear archived findings
            print("### Processing AWS Access Analyzer Archived Findings for '{}' region.".format(region))
            process_findings(aws_access_analyzer_client, scan_result_client, iam_client,
                    region, analyzer['arn'], deployment_id, False)

    return 200

def process_findings(access_client, scan_result_client, iam_client,
                    region, analyzer_arn, deployment_id, active=False):
    if region == 'us-east-1':
        filter = {
                "status": {"eq": ["Active" if active else "Archived"]},
                "resourceType": {"neq": ["AWS::IAM::Role"]}
            }
    else:
        filter = {
                "status": {"eq": ["Active" if active else "Archived"]}
            }

    # Get Analyzer Findings
    response = access_client.list_findings(analyzerArn = analyzer_arn, filter=filter)
    while True:
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            # Declare Vulnerabilities in ActiveWatch
            declare_vulnerabilities(
                    scan_result_client,
                    iam_client,
                    deployment_id,
                    response['findings'],
                    active
                )
            if 'nextToken' not in response:
                break
        response = access_client.list_findings(
                analyzerArn = analyzer_arn, filter=filter, nextToken=response['nextToken'])

def declare_vulnerabilities(scan_result_client, iam_client, deployment_id, findings, active):
    for finding in findings:
        key = get_asset_key('aws', finding['resource'])
        if key is None:
            print("Unsupported AWS Resource Type: {}".format(finding['resource']))
            continue

        vulnerability = get_vulnerability(iam_client, finding)
        if vulnerability is None:
            continue

        scan_result_client.add_scanresult(
                'custom',
                'AWSAccessAnalyzerCollector',
                deployment_id,
                key,
                'aws_access_analyzer_collector_v1'
                "citadel_integration_v1")
        print("Added AWS Access Analyzer scan result. Deployment ID: '{}', Asset: '{}'. Result: {}".format(
            deployment_id, key, str(res)))
    return 200


# Get Deployment ID that protects this AWS Account
def _get_deployment_id(session, aws_account_id):
    deployments_client = session.client("deployments")
    filters = {'platform.type': 'aws',
                'enabled': 'true',
                'platform.id': aws_account_id
        }
    deployments = deployments_client.list_deployments(filters = filters).json()
    if len(deployments) == 0:
        print("'{}' AWS Account isn't protected by '{}'".format(aws_account_id, s.account_name))
        return 404

    deployment_id = deployments[0]['id']
    deployment_name = deployments[0]['name']
    print("'{}' AWS Account is protected by '{}'. Deployment Name: '{}'".format(aws_account_id,
                                                                                session.account_name,
                                                                                deployment_name))
    return deployment_id
