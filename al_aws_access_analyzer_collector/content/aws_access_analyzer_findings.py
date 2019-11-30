
VULNERABILITIES = {
    "citadel-001": {
        "id": "citadel-001",
        "name": "IAM Access Analyzer IAM Finding",
        "description": "IAM Access Analyzer analyzes any Trust policies applied to a role to determine whether that role is accessible by another AWS account or by a user that is not in your account, and reports them as a \"finding\". A IAM Access Analyzer IAM finding has been discovered in your account.",
        "remediation": "Review the IAM findings for this account.",
        "resolution": "IAM Access Analyzer findings stay Active until they are archived, or the offending sharing policy is removed from the account. Review the findings for IAM roles and either archive the finding or remove the offending share policy.",
        "risk": "High",
        "scope": "deployment",
        "ccss_score": 7.6,
        "resolution_type": "enable configuration",
        "reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        "pci_concern": "PCI DSS 3.2.1: Requirement 10: Track and monitor all access to network resources and cardholder data",
        "ccss_vector": "AV:N/AC:H/Au:N/C:C/I:C/A:C/PL:R/EM:A",
        "categories": ["IAM Access Analyzer", "security"],
        "last_modified": "2019-11-14"
        }, 
    "citadel-002": {
        "id": "citadel-002",
        "name": "IAM Access Analyzer S3 Bucket Finding",
        "description": "IAM Access Analyzer analyzes any Trust policies applied to a role to determine whether that role is accessible by another AWS account or by a user that is not in your account, and reports them as a \"finding\". A IAM Access Analyzer S3 Bucket finding has been discovered in your account.",
        "remediation": "Review the findings for this account.",
        "resolution": "IAM Access Analyzer findings stay Active until they are archived, or the offending sharing policy is removed from the account. Review the findings for S3 Buckets and either archive the finding or remove the offending share policy.",
        "risk": "High",
        "scope": "deployment",
        "ccss_score": 7.6,
        "resolution_type": "enable configuration",
        "reference": "https://docs.aws.amazon.com/AmazonS3/latest/user-guide/set-permissions.html",
        "pci_concern": "PCI DSS 3.2.1: Requirement 10: Track and monitor all access to network resources and cardholder data",
        "ccss_vector": "AV:N/AC:H/Au:N/C:C/I:C/A:C/PL:R/EM:A",
        "categories": ["IAM Access Analyzer", "security"],
        "last_modified": "2019-11-14"
    }, 
    "citadel-003": {
        "id": "citadel-003",
        "name": "IAM Access Analyzer KMS Finding",
        "description": "IAM Access Analyzer analyzes any Trust policies applied to a role to determine whether that role is accessible by another AWS account or by a user that is not in your account, and reports them as a \"finding\". A IAM Access Analyzer KMS finding has been discovered in your account.",
        "remediation": "Review the findings for this account.",
        "resolution": "IAM Access Analyzer findings stay Active until they are archived, or the offending sharing policy is removed from the account. Review the findings for KMS and either archive the finding or remove the offending share policy.",
        "risk": "High",
        "scope": "deployment",
        "ccss_score": 7.6,
        "resolution_type": "enable configuration",
        "reference": "https://docs.aws.amazon.com/kms/latest/developerguide/control-access.html",
        "pci_concern": "PCI DSS 3.2.1: Requirement 10: Track and monitor all access to network resources and cardholder data",
        "ccss_vector": "AV:N/AC:H/Au:N/C:C/I:C/A:C/PL:R/EM:A",
        "categories": ["IAM Access Analyzer", "security"],
        "last_modified": "2019-11-14"
    }, 
    "citadel-004": {
        "id": "citadel-004",
        "name": "IAM Access Analyzer Full Administrative Access IAM Role Finding",
        "description": "IAM Access Analyzer analyzes any Trust policies applied to a role to determine whether that role is accessible by another AWS account or by a user that is not in your account, and reports them as a \"finding\". IAM policies should grant access on the principle of 'least-privilege', and avoid allowing full \"*:*\" administrative access. A IAM Access Analyzer full administrative access IAM finding has been discovered in your account.",
        "remediation": "Review the findings for this account.",
        "resolution": "IAM Access Analyzer findings stay Active until they are archived, or the offending sharing policy is removed from the account. Review the findings for IAM Roles and either archive the finding or remove the offending share policy.",
        "risk": "High",
        "scope": "deployment",
        "ccss_score": 10.0,
        "resolution_type": "enable configuration",
        "reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        "pci_concern": "PCI DSS 3.2.1: Requirement 10: Track and monitor all access to network resources and cardholder data",
        "ccss_vector": "AV:N/AC:L/Au:N\C:C/I:C/A:C/PL:A/EM:A",
        "categories": ["IAM Access Analyzer", "security"],
        "last_modified": "2019-11-14"
    }
}

