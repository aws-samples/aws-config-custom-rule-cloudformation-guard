# AWS Config with CloudFormation Guard

AWS Config CloudFormation Guard Custom rules fit as a middle ground between Managed Rules and fully custom Lambda methods. This provides engineers and architects the ability to quickly build rules without needing to know Python, NodeJS, Java required in the other method to deploy custom rules.
This guide aims to accelerate the adoption of the feature by providing workable templates, code and deployment methods. By using this quick start document, an administrator will be able to leverage AWS Config to build custom compliance rules using Configuration Item attributes.

## Prerequisites

- An active AWS account.
- AWS Config must be enabled in your AWS account.

## Limitations

CloudFormation Guard Custom rules are only able to query key/value pairs in a given AWS Config Confirguration Item JSON record.


## Document Outcomes
As a Security Engineer or Operational Engineer, I want to be able to:
- Understand how CloudFormation Guard (cfn-guard) policy code interacts with the AWS Config service.
- Scenario 1 - Deploy a custom AWS Config Custom Rule using cfn-guard syntax to identify compliance for encrypted volumes, status of the drive as in-use AND of type GP3 for compliance.
- Scenario 2 - Deploy a custom AWS Config Custom Rule using cfn-guard syntax to identify all GuardDuty recorders are compliant by having S3 Protection and Kubernetes Protection enabled.

## AWS Config & CloudFormation Guard Overview
Integration Overview
AWS Config provides another method to build custom rules without having to use AWS Lambda functions written in NodeJS, Java or Python. This new method leverages CloudFormation Guard (cfn-guard), as a domain-specific-language (DSL) to build policies and check AWS Config Configuration Items (CI).

The cfn-guard syntax is applied to an AWS Config rule as a custom policy for the service to crawl the hierarchical JSON of each of the AWS Config resources specified.

The AWS Config Configuration Item JSON, which key-value attributes, will be used in the cfn-guard policy syntax as variables assigned to their corresponding value.  The variables when called in the syntax will be prepended with the ‘%’ value.  In the following screenshot, there are three values used as variables and a key of ‘resourceType’ is called out and used as a filter.

Example: EC2 Volume AWS Config - Configuration Item

![Ec2Config](images/ExampleEc2VolumeAWSConfigConfigurationItem)