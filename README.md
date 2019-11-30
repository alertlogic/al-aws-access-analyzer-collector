# al-aws-access-analyzer-collector
Alert Logic Collector for AWS Identity and Access Management (IAM) Access Analyzer Findings

```al-aws-access-analyzer-collector``` is a python-based AWS Lambda project that uploads AWS Access Analyzer findings to Alert Logic Essentials, Professional and Enterprise.
The lambda function is installed using supplied CloudFormation Template. Along with the lambda function, a CloudWatch Scheduled Event is created to periadically call ```al-aws-access-analyzer-collector``` function.
Active IAM Access Analyzer findings will appear as vulnerabilities and remediations in Alert Logic product, while archived findings will be removed from Alert Logic's product.

### Deploy prepackaged CloudFormation
#### Create Access Key for your account

. Authenticate with Alert Logic portal
```curl -X POST -u username:password https://api.global-services.global.alertlogic.com/aims/v1/authenticate```
2. Create Access Key.
```curl -H 'x-aims-auth-token: {token}' -X POST https://api.global-services.global.alertlogic.com/aims/v1/{user.account_id}/users/{user.id}/access_keys```
{token} - ```token``` field returned in JSON response to the authentication request
{user.account_id} - ```account_id``` field from the ```user``` section of the returned in JSON response to the authentication request
{user.id} - ```id``` field form the ```user``` section of the returned in JSON response to the authentication request
Note: Alertnatively, you can create Access Key in the Alert Logic portal.

#### Deployment
```al-aws-access-analyzer-collector``` Integration needs to be deployed in us-east-1 region only, but will cover all regions in the AWS Account in which it is deployed.

  Region Name             | Region           | CloudFormation Template
 -------------------------| -----------------| -----------------
 US East (N. Virginia)    | us-east-1        | https://s3.amazonaws.com/alertlogic-public-repo.us-east-1/templates/al-aws-access-analyzer-collector.template


