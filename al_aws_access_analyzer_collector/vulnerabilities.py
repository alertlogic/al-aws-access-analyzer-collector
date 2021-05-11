import os
import json
import boto3
import logging

log_level = os.getenv('LOG_LEVEL', 'INFO')
LOGGER = logging.getLogger()
LOGGER.setLevel(log_level)

from .content.aws_access_analyzer_findings import VULNERABILITIES


def get_vulnerability(iamClient, finding):
    fun_map = {
        "AWS::S3::Bucket": get_s3_vulnerability,
        "AWS::IAM::Role": get_iam_role_vulnerability,
        "AWS::KMS::Key": get_kms_key_vulnerability,
        "AWS::Serverless::Function": get_function_vulnerability,
        "AWS::SQS::Queue": get_sqs_vulnerability
    }
    return fun_map[finding['resourceType']](iamClient, finding) 


def get_s3_vulnerability(iamClient, finding):
    LOGGER.info(f"Evaluating s3 Finding: {json.dumps(finding, default=str)}")
    if finding['principal']['AWS'] == "*":
        vulnerability = VULNERABILITIES['citadel-004']
    else:
        vulnerability = VULNERABILITIES['citadel-002']
    vulnerability['evidence'] = json.dumps(finding, indent=4, default=str)
    return vulnerability


def get_iam_role_vulnerability(iamClient, finding):
    LOGGER.info(f"Evaluating IAM Role Finding: {json.dumps(finding, default=str)}")
    vulnerability = VULNERABILITIES['citadel-001']
    vulnerability['evidence'] = json.dumps(finding, indent=4, default=str)
    return vulnerability


def get_kms_key_vulnerability(iamClient, finding):
    LOGGER.info(f"Evaluating KMS Key Finding: {json.dumps(finding, default=str)}")
    vulnerability = VULNERABILITIES['citadel-003']
    vulnerability['evidence'] = json.dumps(finding, indent=4, default=str)
    return vulnerability


def get_function_vulnerability(iamClient, finding):
    LOGGER.info(f"Evaluating Lambda Function Finding: {json.dumps(finding, default=str)}")
    vulnerability = VULNERABILITIES['citadel-005']
    vulnerability['evidence'] = json.dumps(finding, indent=4, default=str)
    return vulnerability


def get_sqs_vulnerability(iamClient, finding):
    LOGGER.info(f"Evaluating SQS Queue Finding: {json.dumps(finding, default=str)}")
    vulnerability = VULNERABILITIES['citadel-006']
    vulnerability['evidence'] = json.dumps(finding, indent=4, default=str)
    return vulnerability

