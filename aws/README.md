# AWS Security Assessment Templates

This directory contains CloudFormation templates for deploying AWS-native security assessments using Prowler. These templates provide a comprehensive, automated approach to security scanning within AWS environments.

## Table of Contents

- [Directory Structure](#directory-structure)
- [Template Overview](#template-overview)
- [Recommended Deployment Account](#recommended-deployment-account)
- [Quick Start](#quick-start)
  - [Single Account Deployment](#single-account-deployment)
  - [Multi-Account Organizations Deployment](#multi-account-organizations-deployment)
  - [Template Selection Guide](#template-selection-guide)
- [Template Details](#template-details)
  - [1. Member Roles](#1-member-roles-1-member-roles-awsyaml)
  - [2. AWS Scanner](#2-aws-scanner-2-codebuild-prowler-awsyaml)
- [Common Configurations](#common-configurations)
  - [Basic Weekly Scans](#basic-weekly-scans)
  - [Comprehensive Security Audit](#comprehensive-security-audit)
  - [High-Performance Multi-Account](#high-performance-multi-account)
  - [AWS Security Hub Import](#aws-security-hub-import)
- [Running Scans](#running-scans)
  - [Automatic Initial Scan](#automatic-initial-scan)
  - [Manual Scan Triggers](#manual-scan-triggers)
  - [Scheduled Scans](#scheduled-scans)
- [Understanding Scan Results](#understanding-scan-results)
  - [Output Formats](#output-formats)
  - [S3 Bucket Structure](#s3-bucket-structure)
  - [Accessing Results](#accessing-results)
- [Scan Types Deep Dive](#scan-types-deep-dive)
  - [Basic Scan](#basic-scan-13-checks)
  - [Intermediate Scan](#intermediate-scan-critical--high-severity)
  - [Full Scan](#full-scan-all-checks)
- [Customization Options](#customization-options)
  - [Prowler Options](#prowler-options)
  - [Prowler Version](#prowler-version)
  - [Concurrent Scanning](#concurrent-scanning)
  - [Timeout Configuration](#timeout-configuration)
- [Troubleshooting](#troubleshooting)
  - [Common Issues and Quick Fixes](#common-issues-and-quick-fixes)
  - [Detailed Troubleshooting](#detailed-troubleshooting)
  - [Diagnostic Commands](#diagnostic-commands)
- [Maintenance and Updates](#maintenance-and-updates)
  - [Regular Tasks](#regular-tasks)
  - [Next Steps After Deployment](#next-steps-after-deployment)
- [Additional Resources](#additional-resources)
- [Support](#support)

## Directory Structure

```
aws/
├── README.md                           # This comprehensive documentation
├── 1-member-roles-aws.yaml             # Multi-account role deployment
├── 2-codebuild-prowler-aws.yaml        # Main AWS scanning solution
├── aws-assessment-architecture.drawio  # Editable architecture source
└── checks/                             # Prowler check definitions
    ├── aws_basic_checks.txt            # 13 fundamental security checks
    ├── aws_intermediate_checks.txt     # Critical and high severity checks
    ├── aws_full_checks.txt             # Complete check list
    └── list-aws-checks.sh              # Script to generate check lists
```

## Template Overview

| Template         | Purpose                    | Deployment Order         | Best For             |
| ---------------- | -------------------------- | ------------------------ | -------------------- |
| **Member Roles** | Deploy cross-account roles | 1st (Multi-account only) | AWS Organizations    |
| **AWS Scanner**  | Main security assessment   | 2nd (Required)           | All AWS environments |

## Recommended Deployment Account

Following [AWS management account best practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html), deploy `2-codebuild-prowler-aws.yaml` in a dedicated security or tooling member account, not the AWS Organizations management account. The scanner account must be registered as a delegated administrator so its CodeBuild role can call Organizations account-discovery APIs. Use management account credentials only for trusted access, delegated-administrator registration, service-managed StackSet operations, and the optional management account member role.

The management account requires separate handling. Service-managed StackSets do not deploy stack instances into it, so automatic discovery excludes it by default. To scan the management account, deploy `1-member-roles-aws.yaml` directly there with the delegated scanner account ID and set `ScanManagementAccount=true`.

## Quick Start

### Single Account Deployment

```bash
# Run from the aws/ directory of this repository

aws cloudformation deploy \
  --template-file 2-codebuild-prowler-aws.yaml \
  --stack-name aws-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides EmailAddress=your-email@company.com
```

### Multi-Account Organizations Deployment

The example profiles are:

- `prowler-admin`: dedicated member account where the scanner runs and the registered delegated administrator
- `management`: AWS Organizations management account used for StackSet administration and other operations that require it

```bash
# Identify the delegated scanner account.
PROWLER_ACCOUNT_ID=$(aws sts get-caller-identity \
  --profile prowler-admin --query Account --output text)

# One-time setup from the management account.
aws cloudformation activate-organizations-access \
  --profile management
aws organizations register-delegated-administrator \
  --service-principal member.org.stacksets.cloudformation.amazonaws.com \
  --account-id "$PROWLER_ACCOUNT_ID" \
  --profile management

# Create the member-role StackSet from the management account.
aws cloudformation create-stack-set \
  --template-body file://1-member-roles-aws.yaml \
  --stack-set-name aws-prowler-member-roles \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=ProwlerAccountID,ParameterValue="$PROWLER_ACCOUNT_ID" \
  --profile management

# Target the organization root and use one region. IAM roles are global.
aws cloudformation create-stack-instances \
  --stack-set-name aws-prowler-member-roles \
  --deployment-targets OrganizationalUnitIds='["r-xxxx"]' \
  --regions '["us-east-1"]' \
  --profile management

# Optional: deploy the role directly in the management account to scan it.
aws cloudformation deploy \
  --template-file 1-member-roles-aws.yaml \
  --stack-name aws-prowler-management-account-role \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ProwlerAccountID="$PROWLER_ACCOUNT_ID" \
  --profile management

# Deploy the scanner in the delegated administrator account.
aws cloudformation deploy \
  --template-file 2-codebuild-prowler-aws.yaml \
  --stack-name aws-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    MultiAccountScan=true \
    EmailAddress=your-email@company.com \
  --profile prowler-admin
```

Wait for the StackSet operation to finish successfully before deploying the scanner. The command above skips the management account. If its direct role stack was deployed, add `ScanManagementAccount=true` to the scanner's parameter overrides.

### Template Selection Guide

| Use Case                  | Template                   | Command                                                                                                                                       |
| ------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **Single AWS account**    | AWS Scanner                | `aws cloudformation deploy --template-file 2-codebuild-prowler-aws.yaml --stack-name aws-prowler-scanner --capabilities CAPABILITY_NAMED_IAM` |
| **Multiple AWS accounts** | Member Roles + AWS Scanner | See multi-account commands above                                                                                                              |

## Template Details

### 1. Member Roles (`1-member-roles-aws.yaml`)

**Purpose**: Deploys IAM roles in member accounts for multi-account Prowler scanning.

#### Key Features

- Creates `ProwlerMemberRole` in target accounts
- Configures cross-account trust relationships
- Sets up required Prowler permissions through AWS managed policies and a customer-managed `ProwlerAdditionsPolicy`
- Supports AWS Organizations StackSet deployment
- Follows least privilege security principles

#### When to Use

- **Multi-account** AWS Organizations
- **Cross-account** security assessments
- **Centralized** security scanning setup
- **Enterprise** environments with multiple accounts

#### Role Permissions

The template creates `ProwlerMemberRole` and attaches policies to the role. It does not create inline IAM role policies.

The role includes these AWS managed policies:

- `SecurityAudit` - AWS managed security audit permissions
- `ViewOnlyAccess` - Read-only access to AWS services

The template also creates `ProwlerAdditionsPolicy`, a customer-managed policy with additional permissions for:

- Account information access
- Service-specific read permissions
- Compliance and security checks
- `securityhub:GetFindings`
- `securityhub:BatchImportFindings`, scoped to the Prowler Security Hub product ARN and the current target account
- API Gateway read access for REST and HTTP API checks

`ProwlerAdditionsPolicy` mirrors upstream Prowler's [`permissions/prowler-additions-policy.json`](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-additions-policy.json) for the pinned `ProwlerVersion`. The [Prowler Permissions Check](../README.md#prowler-permissions-check) workflow fails any PR whose templates are missing an upstream permission. Intentional differences are listed in [`prowler-permissions-exceptions.json`](prowler-permissions-exceptions.json).

#### Deployment Options

**Option 1: StackSet Deployment (Recommended for Organizations)**

```bash
# Run from the Organizations management account.
aws cloudformation create-stack-set \
  --template-body file://1-member-roles-aws.yaml \
  --stack-set-name aws-prowler-member-roles \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=ProwlerAccountID,ParameterValue="$PROWLER_ACCOUNT_ID" \
  --profile management

# Use the organization root and one region. IAM roles are global.
aws cloudformation create-stack-instances \
  --stack-set-name aws-prowler-member-roles \
  --deployment-targets OrganizationalUnitIds='["r-xxxx"]' \
  --regions '["us-east-1"]' \
  --operation-preferences FailureTolerancePercentage=100,MaxConcurrentPercentage=100 \
  --profile management
```

**Option 2: Individual or Management Account Deployment**

```bash
# Run with credentials for the target account. For the management account,
# PROWLER_ACCOUNT_ID is the delegated scanner account ID.
aws cloudformation deploy \
  --template-file 1-member-roles-aws.yaml \
  --stack-name aws-prowler-management-account-role \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ProwlerAccountID="$PROWLER_ACCOUNT_ID" \
  --profile management
```

### 2. AWS Scanner (`2-codebuild-prowler-aws.yaml`)

**Purpose**: Main security assessment solution for AWS environments.

#### Key Features

- Single or multi-account scanning
- Configurable scan types (Basic, Intermediate, Full)
- Email notifications via SNS
- S3 storage for reports with explicit SSE-S3 encryption
- KMS-encrypted SNS email notifications when `EmailAddress` is configured
- CloudWatch logging and monitoring
- Concurrent account scanning
- Custom Prowler options support
- Optional AWS Security Hub finding import
- Customer-managed IAM policies instead of inline role policies
- Cost-optimized design

#### Architecture Components

- **AWS CodeBuild**: Executes Prowler scans
- **AWS Lambda**: Triggers CodeBuild projects
- **Amazon S3**: Stores scan results and reports
- **Amazon SNS**: Sends KMS-encrypted email notifications (optional)
- **CloudWatch Logs**: Stores build logs and monitoring data
- **IAM Roles**: Manages permissions and cross-account access

#### Permission Model

The scanner template creates three customer-managed IAM policies and attaches them to the relevant roles:

- `ProwlerAdditionsPolicy` attaches to `ProwlerMemberRole` when the scanner template creates the local single-account role. In multi-account deployments, the member role template creates the same policy in each target account.
- `CodeBuildStartBuildLambdaPolicy` attaches to the Lambda execution role and allows `codebuild:StartBuild` on the `ProwlerCodeBuild` project.
- `ProwlerCodeBuildPolicy` attaches to `ProwlerCodeBuildRole` and allows CodeBuild to write logs, upload reports to the findings bucket, assume the configured `ProwlerRole`, and list AWS Organizations accounts.

No IAM role in these templates uses inline policies.

#### Scan Types

| Scan Type        | Checks                    | Duration       | Best For                              |
| ---------------- | ------------------------- | -------------- | ------------------------------------- |
| **Basic**        | 13 fundamental checks     | ~5 minutes     | Regular monitoring, quick assessments |
| **Intermediate** | Critical + High severity  | ~15-30 minutes | Comprehensive security reviews        |
| **Full**         | All available checks      | ~45-90 minutes | Complete audits, compliance           |

#### Parameters

```yaml
# Core Configuration
ProwlerScanType: "Intermediate" # Basic, Intermediate, Full
MultiAccountScan: false # Enable multi-account scanning
ScanManagementAccount: false # Include the management account after deploying its role directly
EmailAddress: "security@company.com" # Notification email (optional)

# Advanced Configuration
ConcurrentAccountScans: "Three" # Three, Six, Twelve, FortyEight
CodeBuildTimeout: 300 # Minutes (5-2160)
MultiAccountListOverride: "" # Specific account list
ProwlerOptions: "--ignore-exit-code-3 --output-formats csv json-ocsf html" # Output/reporting options; provider and scan severity are added automatically
# ProwlerVersion: "<x.y.z>" # Optional; omit to use the tested default pinned in the template. Set to a semantic version or "latest" (use "latest" only for exploratory testing)
SecurityHubIntegration: "false" # Import AWS Prowler findings into AWS Security Hub
ProwlerRole: "ProwlerMemberRole" # Cross-account role name
```

#### Multi-Account Scan Coverage

When `MultiAccountScan=true`, the CodeBuild build specification determines coverage as follows:

| Configuration | Accounts scanned |
| ------------- | ---------------- |
| Override empty; `ScanManagementAccount=false` | Every `ACTIVE` member account returned by `organizations list-accounts`, including the delegated scanner account but excluding the management account |
| Override empty; `ScanManagementAccount=true` | Every `ACTIVE` account returned by `organizations list-accounts`, including the management account |
| `MultiAccountListOverride` is set | Exactly the space-delimited account IDs supplied in the parameter |

Automatic discovery is not scoped to the OUs selected for the StackSet. A root-targeted service-managed StackSet provisions the role in active member accounts, including the delegated scanner account, but AWS excludes the management account. The scanner therefore skips the management account by default. Deploy the role directly there and set `ScanManagementAccount=true` to include it.

If member roles are deployed only to selected OUs, set `MultiAccountListOverride` to the accounts in those OUs. An override is authoritative, so `ScanManagementAccount` does not alter it. CodeBuild attempts to assume `ProwlerRole` in every selected account, and any failed account causes the build to fail.

## Common Configurations

### Basic Weekly Scans

```bash
aws cloudformation deploy \
  --template-file 2-codebuild-prowler-aws.yaml \
  --stack-name aws-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ProwlerScanType=Basic \
    EmailAddress=security-team@company.com
```

### Comprehensive Security Audit

```bash
aws cloudformation deploy \
  --template-file 2-codebuild-prowler-aws.yaml \
  --stack-name aws-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ProwlerScanType=Full \
    CodeBuildTimeout=120 \
    EmailAddress=security-team@company.com
```

### High-Performance Multi-Account

```bash
aws cloudformation deploy \
  --template-file 2-codebuild-prowler-aws.yaml \
  --stack-name aws-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    MultiAccountScan=true \
    ConcurrentAccountScans=Six \
    ProwlerScanType=Intermediate \
    EmailAddress=security-team@company.com
```

### AWS Security Hub Import

```bash
aws cloudformation deploy \
  --template-file 2-codebuild-prowler-aws.yaml \
  --stack-name aws-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ProwlerScanType=Full \
    SecurityHubIntegration=true \
    EmailAddress=security-team@company.com
```

Security Hub and the Prowler product integration must be enabled in every scanned account and region where findings should be imported:

```bash
aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:us-east-1::product/prowler/prowler
```

Run that command in each target account and region, replacing `us-east-1` as needed. This option is AWS-only; Prowler exposes `--security-hub` for the AWS provider, not for Azure, GCP, or OCI provider scans.

## Running Scans

### Automatic Initial Scan

The scanner template automatically starts an initial scan when deployed, using a CloudFormation custom resource (`CodeBuildStartBuild`) that invokes the trigger Lambda.

**Note**: The custom resource completes as soon as CodeBuild accepts the start request; it does not wait for the scan to finish. A stack status of `CREATE_COMPLETE` therefore means the scan was launched successfully, not that it completed successfully. Scan duration depends on the selected scan type and the number of accounts. Track completion in CodeBuild and check S3 for results after the build succeeds. The trigger Lambda only starts a build on stack creation; updating the stack does not re-run the scan.

### Manual Scan Triggers

To re-run a scan after the initial deployment, start the CodeBuild project directly. The project name follows the pattern `AWSProwler-<stack-name>` (for a stack named `aws-prowler-scanner`, the project is `AWSProwler-aws-prowler-scanner`). Read the exact name from the stack outputs so you do not have to hardcode it:

```bash
CODEBUILD_PROJECT=$(aws cloudformation describe-stacks \
  --stack-name aws-prowler-scanner \
  --query 'Stacks[0].Outputs[?OutputKey==`ProwlerCodeBuildProject`].OutputValue' \
  --output text)

aws codebuild start-build --project-name "$CODEBUILD_PROJECT"
```

### Scheduled Scans

Create an EventBridge rule that starts the CodeBuild project on a schedule. This example runs daily at 2:00 AM UTC:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)

# Read the CodeBuild project name from the stack outputs
CODEBUILD_PROJECT=$(aws cloudformation describe-stacks \
  --stack-name aws-prowler-scanner \
  --query 'Stacks[0].Outputs[?OutputKey==`ProwlerCodeBuildProject`].OutputValue' \
  --output text)

# Role that lets EventBridge start the build
ROLE_ARN=$(aws iam create-role \
  --role-name aws-prowler-scheduled-scan \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --query Role.Arn --output text)

aws iam put-role-policy \
  --role-name aws-prowler-scheduled-scan \
  --policy-name StartProwlerBuild \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"codebuild:StartBuild\",\"Resource\":\"arn:aws:codebuild:${REGION}:${ACCOUNT_ID}:project/${CODEBUILD_PROJECT}\"}]}"

aws events put-rule \
  --name aws-prowler-daily-scan \
  --schedule-expression "cron(0 2 * * ? *)" \
  --description "Daily AWS Prowler security scan"

aws events put-targets \
  --rule aws-prowler-daily-scan \
  --targets "Id=1,Arn=arn:aws:codebuild:${REGION}:${ACCOUNT_ID}:project/${CODEBUILD_PROJECT},RoleArn=${ROLE_ARN}"
```

## Understanding Scan Results

### Output Formats

Each scan generates reports in Prowler's default formats:

- **HTML**: Interactive web reports with filtering capabilities
- **CSV**: Structured data for analysis and automation
- **JSON-OCSF**: Open Cybersecurity Schema Framework format for security tool integration

### S3 Bucket Structure

```
aws-prowler-findings-{account-id}-{region}/
└── output/
    ├── compliance/
    │   └── (compliance framework reports)
    ├── prowler-output-{account-id}-{timestamp}.csv
    ├── prowler-output-{account-id}-{timestamp}.html
    └── prowler-output-{account-id}-{timestamp}.ocsf.json
```

**Note**: All Prowler output files are stored directly in the `output/` folder. The `compliance/` subfolder contains compliance framework-specific reports when compliance checks are enabled.

### Accessing Results

#### Quick Result Access

```bash
# Find your bucket
BUCKET=$(aws s3 ls | grep aws-prowler-findings | awk '{print $3}')

# List recent scans
aws s3 ls s3://$BUCKET/ --recursive --human-readable

# Download latest HTML report
aws s3 cp s3://$BUCKET/output/ ./ --recursive --exclude "*" --include "*.html"
```

#### Manual Access

1. **AWS Console**: Navigate to S3 → Find bucket starting with `aws-prowler-findings`
2. **CodeBuild Console**: Monitor scan progress
3. **Email**: Receive notifications when scans complete

## Scan Types Deep Dive

### Basic Scan (13 Checks)

Perfect for regular monitoring and quick security assessments:

- CloudTrail enabled in all regions
- MFA enabled for root account
- No security groups allow 0.0.0.0/0 access
- GuardDuty enabled
- S3 buckets not publicly accessible
- IAM password policy requirements
- Access key rotation
- Current contact details maintained
- Lambda using supported runtimes
- AWS Config enabled

### Intermediate Scan (Critical + High Severity)

Comprehensive security review covering:

- All Basic scan checks
- Certificate expiration monitoring
- Secrets detection in code and variables
- Public accessibility checks
- Encryption validation
- Network security configurations
- Identity and access management
- Data protection measures

### Full Scan (All Checks)

Complete security audit including:

- All Intermediate scan checks
- Compliance framework validation
- Service-specific security configurations

## Customization Options

### Prowler Options

The `ProwlerOptions` parameter controls output/reporting and additional filtering options. The provider (`aws`) and the scan severity are added automatically — do not include `aws` or `--severity` here. Scan severity is controlled separately by `ProwlerScanType` (see [Scan Types](#scan-types)).

```bash
# Scan specific services only
--parameter-overrides ProwlerOptions="--ignore-exit-code-3 --output-formats csv json-ocsf html --services s3 iam ec2"

# Filter by severity: use ProwlerScanType instead of passing --severity here
--parameter-overrides ProwlerScanType=Intermediate

# Exclude specific checks
--parameter-overrides ProwlerOptions="--ignore-exit-code-3 --output-formats csv json-ocsf html --excluded-checks s3_bucket_public_access"

# Compliance framework focus
--parameter-overrides ProwlerOptions="--ignore-exit-code-3 --output-formats csv json-ocsf html --compliance cis_1.5_aws"

# Import AWS findings into Security Hub
--parameter-overrides SecurityHubIntegration=true
```

### Prowler Version

The `ProwlerVersion` parameter controls which Prowler release the scanner installs. It defaults to the tested release pinned in the template; use `latest` only for exploratory testing:

```bash
# Recommended: use the tested default
# No ProwlerVersion override needed

# Explicitly pin a specific version (use the version you want, e.g. from the Prowler releases page)
--parameter-overrides ProwlerVersion="<x.y.z>"

# Exploratory testing only: install the newest release
--parameter-overrides ProwlerVersion="latest"
```

### Concurrent Scanning

Optimize scan performance with concurrent account processing:

- **Three**: Three accounts concurrently (BUILD_GENERAL1_SMALL)
- **Six**: Six accounts concurrently (BUILD_GENERAL1_MEDIUM)
- **Twelve**: Twelve accounts concurrently (BUILD_GENERAL1_LARGE)
- **FortyEight**: Forty-eight accounts concurrently (BUILD_GENERAL1_XLARGE)

### Timeout Configuration

Adjust `CodeBuildTimeout` based on environment size:

- **Small environments**: 30-60 minutes
- **Medium environments**: 60-120 minutes
- **Large environments**: 120-480 minutes

## Troubleshooting

### Common Issues and Quick Fixes

#### Permission Denied Errors

```bash
# Verify your IAM permissions
aws sts get-caller-identity
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names cloudformation:CreateStack iam:CreateRole codebuild:CreateProject
```

#### Scan Timeouts

```bash
# Increase timeout and reduce concurrency
--parameter-overrides CodeBuildTimeout=180 ConcurrentAccountScans=Three
```

#### No Email Notifications

```bash
# Check SNS subscription in email and confirm email address
--parameter-overrides EmailAddress=correct-email@company.com
```

#### Missing CloudFormation Capabilities

```bash
# Always include capabilities flag
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name stack-name \
  --capabilities CAPABILITY_NAMED_IAM  # This is required
```

### Detailed Troubleshooting

#### CloudFormation Deployment Failures

**Issue: "User is not authorized to perform: iam:CreateRole"**
**Solution**: Ensure your user/role has permissions to deploy IAM roles and customer-managed policies. For deploy, update, and cleanup workflows, include permissions such as the following. Replace `{account-id}` and `{stack-name}` with your deployment values.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:*",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListPolicyVersions",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "codebuild:*",
        "lambda:*",
        "s3:*",
        "sns:*",
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:PutKeyPolicy",
        "kms:EnableKeyRotation",
        "kms:DescribeKey",
        "kms:ScheduleKeyDeletion",
        "logs:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::{account-id}:role/service-role/ProwlerCodeBuildRole",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "codebuild.amazonaws.com"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::{account-id}:role/{stack-name}-CodeBuildStartBuildLambdaRole-*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    }
  ]
}
```

**Issue: "Parameter validation failed"**
**Solution**: Check parameter constraints in template:

```bash
# Example: Account ID must be 12 digits
--parameter-overrides ProwlerAccountID=123456789012  # Correct
--parameter-overrides ProwlerAccountID=12345         # Wrong - too short
```

#### Service Control Policy (SCP) Issues

**Issue: "Service Control Policy denies access to service"**
**Solution**: Update SCPs to allow required services or deploy in an account outside the SCP scope. If your organization uses allow-list SCPs, allow the same actions shown in the deployment policy above, and keep the two `iam:PassRole` statements scoped to the solution roles (`arn:aws:iam::*:role/service-role/ProwlerCodeBuildRole` for `codebuild.amazonaws.com` and `arn:aws:iam::*:role/*-CodeBuildStartBuildLambdaRole-*` for `lambda.amazonaws.com`).

**Issue: "Cross-account role assumption failed"**
**Solution**: Verify member roles are deployed:

```bash
# Verify member role exists in target account
aws iam get-role --role-name ProwlerMemberRole --profile target-account

# Redeploy member roles if needed
aws cloudformation deploy \
  --template-file 1-member-roles-aws.yaml \
  --stack-name aws-prowler-member-role \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ProwlerAccountID="$PROWLER_ACCOUNT_ID" \
  --profile target-account
```

#### CodeBuild Execution Issues

**Issue: "Build timed out after X minutes"**
**Solutions**:

```bash
# Option 1: Increase timeout
aws cloudformation update-stack \
  --stack-name aws-prowler-scanner \
  --use-previous-template \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides CodeBuildTimeout=180

# Option 2: Reduce scan scope
--parameter-overrides ProwlerOptions="--ignore-exit-code-3 --output-formats csv json-ocsf html --services s3 iam"

# Option 3: Use basic scan type
--parameter-overrides ProwlerScanType=Basic
```

**Issue: "No accounts found to scan"**
**Solutions**:

```bash
# Check Organizations access
aws organizations list-accounts

# Override account list if needed
--parameter-overrides MultiAccountListOverride="111111111111 222222222222"
```

#### Results and Notification Issues

**Issue: "No results generated"**
**Solutions**:

```bash
# Check CodeBuild logs for Prowler output (project/log group are AWSProwler-<stack-name>)
aws logs tail /aws/codebuild/AWSProwler-aws-prowler-scanner --since 1h

# Verify Prowler options are correct
--parameter-overrides ProwlerOptions="--ignore-exit-code-3 --output-formats csv json-ocsf html -v"
```

**Issue: "Not receiving email notifications"**
**Solutions**:

```bash
# Check SNS topic and subscription
aws sns list-topics --query 'Topics[?contains(TopicArn, `aws-prowler-scanner`)]'

# Check email spam/junk folders
# Whitelist AWS SNS sender addresses
```

### Diagnostic Commands

#### Check Stack Status

```bash
# Get stack status and outputs
aws cloudformation describe-stacks --stack-name aws-prowler-scanner

# Check stack events for errors
aws cloudformation describe-stack-events --stack-name aws-prowler-scanner
```

#### Monitor CodeBuild

```bash
# List recent builds (project name is AWSProwler-<stack-name>)
aws codebuild list-builds-for-project --project-name AWSProwler-aws-prowler-scanner

# Stream build logs
aws logs tail /aws/codebuild/AWSProwler-aws-prowler-scanner --follow
```

#### Verify Permissions

```bash
# Test cross-account role assumption
aws sts assume-role \
  --role-arn "arn:aws:iam::TARGET-ACCOUNT:role/service-role/ProwlerMemberRole" \
  --role-session-name "test-session"

# Check Organizations access
aws organizations describe-organization
```

## Maintenance and Updates

### Regular Tasks

1. **Update Prowler version**: Controlled by the `ProwlerVersion` parameter; update the tested default after validating a newer Prowler release. Run `python scripts/check_prowler_permissions.py` from the repository root to confirm `ProwlerAdditionsPolicy` still covers that release's permissions (see [Prowler Permissions Check](../README.md#prowler-permissions-check))
2. **Review scan results**: Set up regular review processes
3. **Update email notifications**: Keep contact information current
4. **Monitor costs**: Review AWS billing for optimization opportunities

### Next Steps After Deployment

1. **Review Results**: Check S3 bucket for generated reports
2. **Set Up Automation**: Create EventBridge rules for scheduled scans
3. **Integrate Results**: Use CSV/JSON outputs for automation
4. **Monitor Costs**: Set up billing alerts for CodeBuild usage
5. **Expand Coverage**: Add more accounts or enable additional checks

## Additional Resources

- [Prowler Documentation](https://docs.prowler.com/)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [CloudFormation User Guide](https://docs.aws.amazon.com/cloudformation/)
- [StackSets Delegated Administrators](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html)
- [Management Account Best Practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html)
- [AWS Organizations Guide](https://docs.aws.amazon.com/organizations/)

## Support

Check the [Troubleshooting](#troubleshooting) section and the CloudWatch logs for error messages first. For unresolved problems, open an issue in the repository.
