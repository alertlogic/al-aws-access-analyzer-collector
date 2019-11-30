import json
import boto3

from .content.aws_access_analyzer_findings import VULNERABILITIES

def get_vulnerability(iamClient, finding):
    fun_map = {
        "AWS::S3::Bucket": get_s3_vulnerability,
        "AWS::IAM::Role": get_iam_role_vulnerability,
        "AWS::KMS::Key": get_kms_key_vulnerability
    } 
    return fun_map[finding['resourceType']](iamClient, finding) 

def get_s3_vulnerability(iamClient, finding):
    #print("Finding: " + json.dumps(finding, indent=4, default=str))
    if finding['principal']['AWS'] == "*":
        vulnerability = VULNERABILITIES['citadel-004']
    else:
        vulnerability = VULNERABILITIES['citadel-002']
    vulnerability['evidence'] = json.dumps(finding, indent=4, default=str)
    return vulnerability

def get_iam_role_vulnerability(iamClient, finding):
    print("Evaluating '%s' IAM Role." % (finding['resource']))
    vulnerability = VULNERABILITIES['citadel-001']
    vulnerability['evidence'] = json.dumps(finding, indent=4, default=str)
    return vulnerability

def get_kms_key_vulnerability(iamClient, finding):
    #print("Finding: " + json.dumps(finding, indent=4, default=str))
    vulnerability = VULNERABILITIES['citadel-003']
    vulnerability['evidence'] = json.dumps(finding, indent=4, default=str)
    return vulnerability

