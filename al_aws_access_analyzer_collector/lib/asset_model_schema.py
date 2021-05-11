# -*- coding: utf-8 -*-

ASSET_TYPE_TO_NATIVE_TYPE = {
    'host': {
        'aws': {
            'key': 'instance',
            'type': 'AWS::EC2::Instance'
        }
    }
}

AWS_ARN_TYPE_MAP = {
    'instance': {
            'aws_type': 'AWS::EC2::Instance',
            'asset_type': 'host'
        },
    'security-group': {
            'aws_type': "AWS::EC2::SecurityGroup",
            'asset_type': 'sg'
        },
    'subnet': {
            'aws_type': 'AWS::EC2::Subnet',
            'asset_type': 'subnet'
        },
    'vpc': {
            'aws_type': 'AWS::EC2::VPC',
            'asset_type': 'vpc'
        },
    'network-acl': {
            'aws_type': 'AWS::EC2::NetworkAcl',
            'asset_type': 'acl'
        },
    'igw': {
            'aws_type': 'AWS::EC2::InternetGateway',
            'asset_type': 'igw'
        },
    'bucket': {
            'aws_type': 'AWS::S3::Bucket',
            'asset_type': 's3-bucket'
        },
    'role': {
            'aws_type': 'AWS::IAM::Role',
            'asset_type': 'role'
        },
    'key': {
            'aws_type': 'AWS::KMS::Key',
            'asset_type': 'kms-key'
        },
    'function': {
            'aws_type': 'AWS::Serverless::Function',
            'asset_type': 'function'
    },
    'sqs': {
            'aws_type': 'AWS::SQS::Queue',
            'asset_type': 'kms-key'
    }
}

AWS_RESOURCE_MAP = {
    "AWS::EC2::Instance": "host",
    "AWS::EC2::SecurityGroup": "sg",
    "AWS::EC2::Subnet": "subnet",
    "AWS::EC2::VPC": "vpc",
    "AWS::EC2::NetworkAcl": "acl",
    "AWS::EC2::RouteTable": "route",
    "AWS::EC2::InternetGateway": "igw",
    "AWS::S3::Bucket": "s3-bucket",
    "AWS::IAM::Role": "role",
    "AWS::KMS::Key": "kms-key",
    "AWS::Serverless::Function": "function",
    "AWS::SQS::Queue": "sqs"
}

def get_asset_key(deployment_type, native_resource_id, native_resource_type, native_account_id):
    if deployment_type == "aws":
        return get_aws_asset_key(native_resource_id, native_resource_type, native_account_id)
    else:
        raise ValueError('{} deployment type is not supported by the library. Please submit a PR'.format(deployment))

def get_aws_asset_key(resource_id, resource_type, aws_account_id):
    parsed_arn = parse_arn(resource_id)

    if resource_type not in AWS_RESOURCE_MAP:
        return None

    if resource_type == "AWS::KMS::Key":
        return "/aws/" + "/".join([parsed_arn['region'], AWS_RESOURCE_MAP[resource_type], parsed_arn['resource']])

    if parsed_arn['region'] is "":
        return "/aws/" + "/".join([aws_account_id, AWS_RESOURCE_MAP[resource_type], parsed_arn['resource']])

    return "/aws/" + "/".join([aws_account_id, parsed_arn['region'],
                                AWS_RESOURCE_MAP[resource_type], parsed_arn['resource']])

def parse_arn(arn):
    # http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
    elements = arn.split(':', 5)
    result = {
        'arn': elements[0],
        'partition': elements[1],
        'service': elements[2],
        'region': elements[3],
        'account': elements[4],
        'resource': elements[5],
        'resource_type': None
    }
    if '/' in result['resource']:
        result['resource_type'], result['resource'] = result['resource'].split('/',1)
    elif ':' in result['resource']:
        result['resource_type'], result['resource'] = result['resource'].split(':',1)
    return result

