# Multicloud Security Posture Assessment (MSPA) Solution

[![License](https://img.shields.io/badge/License-MIT--0-blue.svg)](https://github.com/aws/mit-0)
[![CloudFormation](https://img.shields.io/badge/CloudFormation-Templates-orange.svg)](https://aws.amazon.com/cloudformation/)

> **Automated security assessments for AWS, Azure, Google Cloud Platform, and Oracle Cloud Infrastructure environments using Prowler running from an AWS environment**

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Repository Structure](#repository-structure)
- [Documentation](#documentation)
- [Architecture](#architecture)
- [Deployment](#deployment)
- [Running Scans](#running-scans)
- [Results and Reporting](#results-and-reporting)
- [Security Assessment Summary](#security-assessment-summary-deliverable-generation)
- [Ongoing Security Monitoring](#ongoing-security-monitoring)
- [Notifications](#notifications)
- [Cleanup / Uninstall](#cleanup--uninstall)
- [Cost Considerations](#cost-considerations)
- [Security Best Practices](#security-best-practices)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)
- [Related Resources](#related-resources)

## Overview

This solution provides fast, inexpensive, point-in-time security assessments across AWS, Azure, Google Cloud Platform, and Oracle Cloud Infrastructure — all from a single deployment in AWS. It is built on the open-source [Prowler](https://github.com/prowler-cloud/prowler) security tool, which evaluates each environment against industry best practices and cloud-specific frameworks to surface potential risk areas.

Provider-native services such as [Amazon GuardDuty](https://aws.amazon.com/guardduty/), [AWS Security Hub](https://aws.amazon.com/security-hub/), [Microsoft Defender for Cloud](https://azure.microsoft.com/en-us/products/defender-for-cloud), [Google Cloud Security Command Center](https://cloud.google.com/security/products/security-command-center), and [OCI Cloud Guard](https://www.oracle.com/security/cloud-security/cloud-guard/) offer deeper, continuous coverage. This solution complements them by delivering an immediate, unified assessment — useful before those services are fully rolled out, or for rapid, cross-cloud reviews.

The solution enables organizations to:

- **Assess multiple cloud platforms** from a single, centralized deployment within AWS
- **Standardize security evaluations** across diverse cloud environments
- **Accelerate security reviews** for rapid cloud adoption scenarios
- **Maintain consistent security posture** across hybrid and multicloud architectures

> **Note**: Prowler is not owned by any cloud provider. Organizations should independently review Prowler before deployment. Dependencies should be kept up to date. This solution installs Prowler from pip; the version is controlled by the `ProwlerVersion` template parameter. Use version `latest` only for exploratory testing.

## Quick Start

Pick the template for the cloud you want to scan and deploy it. To cover more than one provider, deploy each relevant template independently.

| Cloud Platform   | Template                                                                   | Best For                                                     |
| ---------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------ |
| **AWS**          | [`aws/2-codebuild-prowler-aws.yaml`](aws/2-codebuild-prowler-aws.yaml)     | Single-account, multi-account, and Security Hub scanning     |
| **Azure**        | [`azure/codebuild-prowler-azure.yaml`](azure/codebuild-prowler-azure.yaml) | Concurrent multi-subscription scanning                       |
| **Google Cloud** | [`gcp/codebuild-prowler-gcp.yaml`](gcp/codebuild-prowler-gcp.yaml)         | Concurrent multi-project scanning                            |
| **Oracle Cloud** | [`oci/codebuild-prowler-oci.yaml`](oci/codebuild-prowler-oci.yaml)         | Tenancy or compartment-scoped scanning                       |

> For multi-account AWS scanning, first deploy [`aws/1-member-roles-aws.yaml`](aws/1-member-roles-aws.yaml) through StackSets to create the cross-account roles. See [Multi-Account AWS Organizations](#multi-account-aws-organizations) below.

## Repository Structure

```
├── aws/                                  # AWS-specific templates
│   ├── 1-member-roles-aws.yaml           # Multi-account role setup
│   ├── 2-codebuild-prowler-aws.yaml      # AWS scanning
│   ├── aws-assessment-architecture.drawio # Editable architecture source
│   ├── README.md                         # AWS deployment guide
│   └── checks/                           # Prowler AWS checks listing
├── azure/                                # Azure-specific templates
│   ├── codebuild-prowler-azure.yaml      # Azure scanning
│   ├── azure-assessment-architecture.drawio # Editable architecture source
│   ├── README.md                         # Azure deployment guide
│   └── checks/                           # Prowler Azure checks listing
├── gcp/                                  # Google Cloud templates
│   ├── codebuild-prowler-gcp.yaml        # GCP scanning
│   ├── gcp-assessment-architecture.drawio # Editable architecture source
│   ├── README.md                         # GCP deployment guide
│   └── checks/                           # Prowler GCP checks listing
├── oci/                                  # Oracle Cloud templates
│   ├── codebuild-prowler-oci.yaml        # OCI scanning
│   ├── oci-assessment-architecture.drawio # Editable architecture source
│   ├── README.md                         # OCI deployment guide
│   └── checks/                           # Prowler OCI checks listing
├── security-assessment-summary/          # Post-scan analysis & deliverable generation
│   ├── kiro-agent/                       # Kiro CLI agent variant
│   ├── python-script/                    # Standalone Python/Node pipeline
│   ├── quick-skill/                      # Amazon Quick skill variant
│   └── README.md                         # Variant overview and quick start
└── img/                                  # README architecture diagram exports
```

## Documentation

| Guide                          | Description                                 |
| ------------------------------ | ------------------------------------------- |
| [AWS Guide](aws/README.md)     | AWS-specific deployment and configuration   |
| [Azure Guide](azure/README.md) | Azure-specific deployment and configuration |
| [GCP Guide](gcp/README.md)     | GCP-specific deployment and configuration   |
| [OCI Guide](oci/README.md)     | OCI-specific deployment and configuration   |
| [Security Assessment Summary](security-assessment-summary/README.md) | Post-scan analysis and deliverable generation |

## Architecture

The solution deploys the following AWS components:

- **AWS CodeBuild**: Runs Prowler security assessments
- **Amazon S3**: Stores generated reports and findings
- **AWS Lambda**: Triggers CodeBuild projects
- **AWS Secrets Manager and AWS KMS**: Store and encrypt external-provider credentials for Azure, GCP, and OCI scans; encrypt optional SNS notification topics
- **Amazon SNS**: (Optional) KMS-encrypted email notifications
- **Amazon EventBridge**: Routes CodeBuild state-change notifications
- **IAM Roles and Policies**: CodeBuild/Lambda execution permissions and AWS cross-account access for multi-account scanning
- **AWS Organizations and AWS Security Hub**: Optional AWS account discovery and AWS-only finding import

The scanner projects use the AWS-managed Amazon Linux 2023 CodeBuild image `aws/codebuild/amazonlinux-x86_64-standard:6.0` with Python 3.12.

### Architecture Diagrams

| Cloud Platform | Architecture Diagram                              | Description                                   |
| -------------- | ------------------------------------------------- | --------------------------------------------- |
| **AWS**        | ![AWS Architecture](img/aws-architecture.svg)         | AWS-native security assessment architecture   |
| **Azure**      | ![Azure Architecture](img/azure-architecture.svg) | Cross-cloud Azure scanning from AWS CodeBuild |
| **GCP**        | ![GCP Architecture](img/gcp-architecture.svg)     | Cross-cloud GCP scanning from AWS CodeBuild   |
| **OCI**        | ![OCI Architecture](img/oci-architecture.svg)     | Cross-cloud OCI scanning from AWS CodeBuild   |

Each diagram shows the data flow, security controls, and cross-cloud authentication for scanning that platform from AWS.

## Deployment

The examples below show common deployments. See the provider-specific guides for full parameter details.

### AWS Environment Scanning

#### Single Account Scanning

Ideal for individual AWS accounts or initial testing:

```bash
aws cloudformation deploy \
  --template-file aws/2-codebuild-prowler-aws.yaml \
  --stack-name aws-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM
```

To import AWS scan findings into AWS Security Hub, add `--parameter-overrides SecurityHubIntegration=true` to the command above. Security Hub and the Prowler product integration must already be enabled in each scanned account and region.

#### Multi-Account AWS Organizations

For enterprise environments, follow [AWS management account best practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html): deploy `aws/2-codebuild-prowler-aws.yaml` in a dedicated security or tooling member account rather than the Organizations management account. The scanner account must be registered as a delegated administrator so its CodeBuild role can call Organizations account-discovery APIs. The examples below use `prowler-admin` for that delegated administrator profile and `management` for the Organizations management account profile.

1. **Set the scanner account ID**:

```bash
PROWLER_ACCOUNT_ID=$(aws sts get-caller-identity \
  --profile prowler-admin \
  --query Account \
  --output text)
```

2. **Enable trusted access and register the delegated administrator**. These one-time operations require management account credentials:

```bash
aws cloudformation activate-organizations-access \
  --profile management

aws organizations register-delegated-administrator \
  --service-principal member.org.stacksets.cloudformation.amazonaws.com \
  --account-id "$PROWLER_ACCOUNT_ID" \
  --profile management
```

3. **Create the member-role StackSet from the management account**:

```bash
aws cloudformation create-stack-set \
  --template-body file://aws/1-member-roles-aws.yaml \
  --stack-set-name aws-prowler-member-roles \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=ProwlerAccountID,ParameterValue="$PROWLER_ACCOUNT_ID" \
  --profile management
```

4. **Deploy member roles to the organization**. For automatic discovery, target the organization root so every member account receives the role. Replace `r-xxxx` with the root ID and choose one StackSet region. The template creates a named IAM role, which is global within an account, so do not deploy it to multiple regions:

```bash
aws cloudformation create-stack-instances \
  --stack-set-name aws-prowler-member-roles \
  --deployment-targets OrganizationalUnitIds='["r-xxxx"]' \
  --regions '["us-east-1"]' \
  --profile management
```

Wait for the StackSet operation to succeed before continuing.

5. **Optionally enable management account scanning**. Automatic discovery excludes the management account by default because service-managed StackSets never deploy stack instances there.

To scan it, deploy the member-role template directly in the management account. The role trusts only the delegated scanner account's `ProwlerCodeBuildRole`:

```bash
aws cloudformation deploy \
  --template-file aws/1-member-roles-aws.yaml \
  --stack-name aws-prowler-management-account-role \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ProwlerAccountID="$PROWLER_ACCOUNT_ID" \
  --profile management
```

Then add `ScanManagementAccount=true` to the scanner deployment in the next step. Otherwise, omit this direct stack and leave `ScanManagementAccount` at its default of `false`.

6. **Deploy the scanner in the delegated administrator account**:

```bash
aws cloudformation deploy \
  --template-file aws/2-codebuild-prowler-aws.yaml \
  --stack-name aws-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides MultiAccountScan=true \
  --profile prowler-admin
```

The command above scans every active member account returned by `organizations list-accounts`, including the delegated scanner account, and skips the management account. To include the management account after deploying its role, use `--parameter-overrides MultiAccountScan=true ScanManagementAccount=true`.

If the StackSet targets selected OUs instead of the root, provide `MultiAccountListOverride` so CodeBuild scans only accounts provisioned with the member role. An override is authoritative and scans exactly the supplied account IDs.

### Azure Environment Scanning

For Azure-focused organizations:

```bash
aws cloudformation deploy \
  --template-file azure/codebuild-prowler-azure.yaml \
  --stack-name azure-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    AzureClientId=your-client-id \
    AzureClientSecret=your-client-secret \
    AzureTenantId=your-tenant-id \
    AzureSubscriptionIds=sub1,sub2,sub3
```

### Google Cloud Platform Scanning

For GCP environments:

```bash
aws cloudformation deploy \
  --template-file gcp/codebuild-prowler-gcp.yaml \
  --stack-name gcp-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GCPServiceAccountKey="$(cat prowler-key.json | jq -c .)" \
    GCPProjectIds=project1,project2,project3
```

### Oracle Cloud Infrastructure Scanning

For OCI environments:

```bash
aws cloudformation deploy \
  --template-file oci/codebuild-prowler-oci.yaml \
  --stack-name oci-prowler-scanner \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    OCIUserOCID=ocid1.user.oc1..aaaaaaaexample \
    OCITenancyOCID=ocid1.tenancy.oc1..aaaaaaaexample \
    OCIFingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 \
    OCIPrivateKey="$(jq -Rs . < ~/.oci/oci_api_key.pem)" \
    OCIRegion=us-ashburn-1
```

## Running Scans

### Initial Scan

Each scanner stack starts an initial CodeBuild scan when the stack is first created. The CloudFormation custom resource completes after CodeBuild accepts the start request; it does not wait for the assessment to finish. A stack status of `CREATE_COMPLETE` therefore means that the scan was launched successfully, not that the scan completed successfully.

Monitor the build in the [CodeBuild console](https://console.aws.amazon.com/codesuite/codebuild/projects) or use the AWS CLI. The CodeBuild project name and findings bucket name are available in the scanner stack outputs:

```bash
aws cloudformation describe-stacks \
  --stack-name <scanner-stack-name> \
  --query 'Stacks[0].Outputs' \
  --output table
```

After the build succeeds, review the generated reports under the findings bucket's `output/` prefix.

### Manual Rerun

Start another scan using the CodeBuild project name from the stack outputs:

```bash
aws codebuild start-build \
  --project-name <codebuild-project-name>
```

Manual reruns use the scanner's current stack configuration, credentials, and `ProwlerVersion`.

## Results and Reporting

### Output Formats

Each scan generates reports in Prowler's default formats:

- **HTML**: Interactive web reports with filtering
- **CSV**: Structured data for analysis
- **JSON-OCSF**: Open Cybersecurity Schema Framework format for security tool integration

### Accessing Results

1. **Navigate to S3 Console**
2. **Find bucket**: `aws-prowler-findings-*`, `azure-prowler-findings-*`, `gcp-prowler-findings-*`, or `oci-prowler-findings-*` based on the scan used.
3. **Browse the `output/` prefix**
4. **Download or view reports directly**

### Prowler Dashboard (Local Analysis)

For advanced analysis, use Prowler's built-in dashboard. This is particularly useful for analyzing the entire environment at once.

```bash
# Install Prowler locally to analyze results (match the version deployed via the
# ProwlerVersion parameter; use a pinned version below for reproducible output)
pip install prowler==<x.y.z>  # use the version set in the ProwlerVersion parameter

# Download results from S3
aws s3 sync s3://your-bucket-name/output/ output/

# Launch dashboard
prowler dashboard
```

### Security Assessment Summary (Deliverable Generation)

After a scan completes, use the **Security Assessment Summary** tool to transform raw Prowler output into a full set of customer-ready deliverables: an interactive HTML dashboard, an executive PowerPoint deck, a phased PDF remediation plan, Terraform remediation modules, and a tying-it-together README.

The tool supports all four clouds (AWS, Azure, GCP, OCI) and is available in three variants — pick whichever fits your workflow:

| Variant | Best For |
|---------|----------|
| **Kiro Agent** | Interactive, conversational workflow using Kiro CLI |
| **Python Scripts** | Standalone CLI pipeline — no AI runtime needed |
| **Amazon Quick Skill** | Amazon Q Developer / Quick skill integration |

```bash
# Example: run the Python pipeline against your downloaded scan output
python3 security-assessment-summary/python-script/scripts/analyze_security_data.py output/ deliverables/analysis.json --customer "My Customer" --anonymize
```

See the [Security Assessment Summary guide](security-assessment-summary/README.md) for full usage instructions and variant-specific setup.

## Ongoing Security Monitoring

This solution produces a point-in-time assessment. It does not provide continuous, event-driven monitoring by itself. For ongoing coverage, consider one or more of the following approaches:

| Approach | Recommended use |
| --- | --- |
| **AWS Security Hub and Security Hub CSPM** | Use [AWS Security Hub](https://aws.amazon.com/security-hub/) to prioritize and respond to security findings, and use Security Hub CSPM for continuous configuration assessment. Security Hub CSPM supports AWS environments and can also [integrate with Microsoft Azure](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-azure.html) to continuously evaluate Azure resources against supported security standards. Azure standards can be managed through the Security Hub CSPM console, APIs, and AWS CloudFormation, but are not supported by Security Hub CSPM central configuration. |
| **Prowler Cloud** | [Prowler Cloud](https://prowler.com/prowler-cloud/) provides managed recurring Prowler scans, centralized findings, compliance reporting, scan history, and integrations without operating the scanner infrastructure. Review supported providers, credential permissions, data handling, and pricing before adoption. |
| **Scheduled self-managed scans** | Use [Amazon EventBridge Scheduler](https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html) to start the CodeBuild project on a daily or weekly schedule, with retries, failure notifications, and preferably a dead-letter queue. This produces recurring snapshots rather than real-time monitoring; you remain responsible for credentials, costs, and failed executions. |
| **Existing CSPM or CNAPP platform** | Organizations that already operate an approved enterprise cloud-security platform should onboard these environments there rather than create a parallel monitoring workflow. |

> **Important**: Setting `SecurityHubIntegration=true` imports findings generated by an AWS Prowler scan into Security Hub. It does not schedule additional scans or make this solution continuous. For native continuous configuration assessment, enable Security Hub CSPM standards and the required resource recording in the accounts and Regions being monitored.

Configuration-posture scanning also does not replace workload threat detection or vulnerability management. For AWS environments, consider Security Hub together with services such as Amazon GuardDuty and Amazon Inspector.

## Notifications

Enable email notifications for scan completion:

```bash
--parameter-overrides EmailAddress=security-team@company.com
```

Monitor progress in real-time via the [CodeBuild Console](https://console.aws.amazon.com/codesuite/codebuild/projects).

## Cleanup / Uninstall

Deleting a scanner stack removes the CodeBuild project, Lambda, IAM roles, and log groups, but **the S3 findings bucket is intentionally retained** (`DeletionPolicy: Retain`) so your scan history is not lost automatically. You must remove it separately.

1. **Delete the scanner stack** (substitute the stack name you deployed):

```bash
aws cloudformation delete-stack --stack-name aws-prowler-scanner
aws cloudformation wait stack-delete-complete --stack-name aws-prowler-scanner
```

Use the matching name for other clouds: `azure-prowler-scanner`, `gcp-prowler-scanner`, or `oci-prowler-scanner`.

2. **Empty and delete the retained findings bucket.** The bucket has versioning enabled, so all object versions and delete markers must be purged before it can be removed — a plain delete will fail while any versions remain. The bucket is named `<cloud>-prowler-findings-<account-id>-<region>` (e.g. `aws-prowler-findings-123456789012-us-east-1`). The following commands require `jq` and delete versions in batches of at most 1,000:

```bash
set -euo pipefail

BUCKET="aws-prowler-findings-<account-id>-<region>"
while true; do
  DELETE_PAYLOAD=$(
    aws s3api list-object-versions --bucket "$BUCKET" \
      --max-keys 1000 --no-paginate --output json |
      jq -c '{
        Objects: ([.Versions[]?, .DeleteMarkers[]?] |
          map({Key: .Key, VersionId: .VersionId})),
        Quiet: true
      }'
  )

  DELETE_COUNT=$(jq '.Objects | length' <<<"$DELETE_PAYLOAD")
  if (( DELETE_COUNT == 0 )); then
    break
  fi

  DELETE_RESULT=$(
    aws s3api delete-objects --bucket "$BUCKET" \
      --delete "$DELETE_PAYLOAD" --output json
  )
  DELETE_ERROR_COUNT=$(jq '(.Errors // []) | length' <<<"$DELETE_RESULT")
  if (( DELETE_ERROR_COUNT != 0 )); then
    jq '.Errors' <<<"$DELETE_RESULT" >&2
    exit 1
  fi
done

aws s3 rb "s3://$BUCKET"
```

> **Download any findings you want to keep before running the commands above — deletion is permanent.**

3. **Multi-account deployments:** also delete the member-role StackSet instances and the StackSet itself:

```bash
STACK_SET_OPERATION_ID=$(
  aws cloudformation delete-stack-instances \
    --stack-set-name aws-prowler-member-roles \
    --regions '<region>' \
    --deployment-targets OrganizationalUnitIds='<root-or-ou-id>' \
    --no-retain-stacks \
    --profile management \
    --query OperationId \
    --output text
)

while true; do
  STACK_SET_STATUS=$(
    aws cloudformation describe-stack-set-operation \
      --stack-set-name aws-prowler-member-roles \
      --operation-id "$STACK_SET_OPERATION_ID" \
      --profile management \
      --query 'StackSetOperation.Status' \
      --output text
  )

  case "$STACK_SET_STATUS" in
    SUCCEEDED)
      break
      ;;
    RUNNING|QUEUED|STOPPING)
      sleep 10
      ;;
    *)
      echo "StackSet instance deletion ended with status $STACK_SET_STATUS" >&2
      aws cloudformation describe-stack-set-operation \
        --stack-set-name aws-prowler-member-roles \
        --operation-id "$STACK_SET_OPERATION_ID" \
        --profile management \
        --output table >&2
      exit 1
      ;;
  esac
done

aws cloudformation delete-stack-set --stack-set-name aws-prowler-member-roles \
  --profile management

# If deployed, remove the management account role separately.
aws cloudformation delete-stack --stack-name aws-prowler-management-account-role \
  --profile management
```

## Cost Considerations

The solution has both scan-related usage costs and ongoing costs for resources that remain deployed or retain data. Actual charges vary by AWS Region, scan duration and frequency, environment size, notification volume, and data retention.

| Resource | Cost behavior |
| -------- | ------------- |
| **AWS CodeBuild** | Compute charges accrue whenever a scan runs. Larger environments, higher concurrency settings, and more frequent scans increase usage. |
| **Amazon S3** | Findings, reports, and object versions incur storage and request charges for as long as they remain in the findings bucket, including after stack deletion (the bucket is retained). |
| **Amazon CloudWatch Logs** | Lambda and CodeBuild log ingestion and storage incur charges while execution logs are retained. |
| **AWS Secrets Manager and AWS KMS** | External-provider scanner stacks create encrypted secrets and KMS keys that can incur recurring and request charges while deployed. Email notifications can create an additional KMS key. |
| **AWS Lambda, Amazon EventBridge, and Amazon SNS** | Initial or scheduled scan triggers and optional notifications incur usage-based charges. |
| **AWS Security Hub CSPM and AWS Config** | These services have separate pricing when enabled for continuous monitoring. Their charges are not included in the scanner stack's costs. |
| **IAM member roles** | IAM roles and policies do not have a direct charge. |

When the assessment is complete, delete resources that are no longer needed by following [Cleanup / Uninstall](#cleanup--uninstall). Note that the findings S3 bucket keeps accruing storage charges until you empty and delete it separately, and that deleting the scanner stack does not disable separately enabled services such as Security Hub CSPM and AWS Config.

## Security Best Practices

- **Purpose-Built Permissions**: Templates scope permissions to the scanner roles and target resources where the underlying service APIs support it
- **Dedicated Scanner Account**: For organization-wide scans, deploy `aws/2-codebuild-prowler-aws.yaml` in a security or tooling member account registered as a delegated administrator instead of the Organizations management account
- **Managed Policies**: AWS templates use customer-managed IAM policies rather than inline role policies
- **AWS Cross-Account Access**: Uses IAM roles, not access keys
- **Encryption**: S3 report buckets explicitly use SSE-S3 encryption; external-provider credentials and optional SNS notification topics are encrypted with stack-managed AWS KMS keys
- **Build Environment**: CodeBuild runs scans in ephemeral AWS-managed containers. The projects are not attached to a VPC and require outbound network access to download dependencies and call cloud-provider APIs
- **Audit Trail**: AWS control-plane activity is available through CloudTrail, and Lambda/CodeBuild scan execution logs are written to CloudWatch Logs

## Contributing

We welcome contributions! Please see:

- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## License

This project is licensed under the MIT No Attribution (MIT-0) license - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs or request features through this repository's issue tracker.

## Related Resources

- [Prowler Documentation](https://docs.prowler.com/)
- [AWS Security Hub](https://aws.amazon.com/security-hub/)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
---