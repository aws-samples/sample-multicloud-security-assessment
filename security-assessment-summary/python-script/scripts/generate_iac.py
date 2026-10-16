#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
generate_iac.py — Generate Terraform remediation modules (multi-cloud, provider-aware).

Terraform is the single IaC language for all clouds. The correct provider block
(aws / azurerm / google / oci) is emitted based on the detected provider.

Usage:
    python3 generate_iac.py <analysis_json> <selections> <output_dir> [--provider <aws|azure|gcp|oci>]

    selections: comma-separated remediation IDs. You may use either PROVIDER-NEUTRAL
    capability names (recommended in docs/menus) or PROVIDER-SPECIFIC catalog keys.

    Provider-neutral names (resolved to the right key per detected provider):
        object_storage_public_access, identity_mfa, network_ingress,
        disk_db_encryption, audit_logging, flow_logs, key_management

    Provider-specific catalog keys:
        aws:   s3_public_access, iam_mfa, security_groups, encryption_at_rest,
               audit_logging, flow_logs, kms_rotation
        azure: storage_secure, entra_mfa, nsg_restrict, disk_sql_encryption,
               activity_log, keyvault_protection
        gcp:   gcs_public_access, iam_least_privilege, firewall_restrict,
               cmek_encryption, audit_logs, kms_rotation
        oci:   object_storage_visibility, iam_policy, security_lists,
               volume_db_encryption, audit_logging, vault_rotation

If --provider is omitted, it is taken from the analysis JSON (first detected provider).

⚠️  DISCLAIMER: This Terraform is AUTO-GENERATED from Prowler remediation data and
    touches sensitive controls (identity, network, logging, encryption/key stores).
    Review it, run `terraform init && terraform validate && terraform plan`, and
    validate against your environment and change-management process BEFORE `apply`.
    It is a starting point, not guaranteed production-ready.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime

import safe_io


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------

PROVIDER_TF = {
    "aws": {
        "provider_block": 'provider "aws" {\n  region = var.region\n}',
    },
    "azure": {
        # storage_use_azuread: the storage module disables shared keys (Entra-only auth).
        "provider_block": 'provider "azurerm" {\n  features {}\n  storage_use_azuread = true\n}',
    },
    "gcp": {
        "provider_block": 'provider "google" {\n  project = var.project_id\n  region  = var.region\n}',
    },
    "oci": {
        "provider_block": 'provider "oci" {\n  tenancy_ocid = var.tenancy_ocid\n  region       = var.region\n}',
    },
}

# Version-pinned required_providers per cloud. Pinning avoids surprise breakage when
# a new major provider release changes/removes arguments. azurerm is pinned to ~> 4.0
# because the storage module uses https_traffic_only_enabled (the v4 name; v3 used the
# now-removed enable_https_traffic_only).
REQUIRED_PROVIDERS = {
    "aws":   '\n    aws = {\n      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }',
    "azure": '\n    azurerm = {\n      source  = "hashicorp/azurerm"\n      version = "~> 4.0"\n    }',
    "gcp":   '\n    google = {\n      source  = "hashicorp/google"\n      version = "~> 5.0"\n    }',
    "oci":   '\n    oci = {\n      source  = "oracle/oci"\n      version = "~> 5.0"\n    }',
}

# Azure identity remediation additionally needs the separate azuread provider.
AZUREAD_REQUIRED = '\n    azuread = {\n      source  = "hashicorp/azuread"\n      version = "~> 2.0"\n    }'
AZURE_IDENTITY_KEYS = {"entra_mfa"}


# Provider-appropriate remediation catalog. Each entry: title, description, and a
# Terraform body builder () -> HCL string for the resource(s).
#
# IMPORTANT: These are REFERENCE TEMPLATES, not surgical in-place fixes for specific
# failing resources. They create new correctly-configured resources that demonstrate
# the required security posture. Operators MUST customize them (e.g. attach NSGs to
# existing subnets, associate security groups with existing instances) before applying.
# Always run `terraform plan` and review the execution plan before `terraform apply`.
REMEDIATION_CATALOG = {
    # ----------------------------- AWS -----------------------------
    "aws": {
        "s3_public_access": {
            "title": "S3 Block Public Access & Default Encryption",
            "description": "Account-level S3 public access block + default SSE-KMS (each opt-in).",
            "body": lambda: '''# BEFORE APPLY — capture current settings so a rollback can restore them exactly:
#   aws s3control get-public-access-block --account-id <account-id>
#   aws s3api get-bucket-encryption --bucket <bucket_name>
#   aws s3api get-bucket-policy --bucket <bucket_name> --query Policy --output text
# Every resource below takes over an EXISTING account/bucket setting. If one already
# exists, `terraform import` it first. They carry prevent_destroy so `terraform destroy`
# cannot silently remove them (which would leave the account WEAKER than before) —
# see the README "Rollback" section for the targeted rollback procedure.

# ACCOUNT-WIDE: blocks public access for EVERY bucket in the account, including
# intentionally public buckets / S3 static websites. Opt-in via
# manage_account_public_access_block. Existing setting: terraform import
#   'aws_s3_account_public_access_block.this[0]' <account-id>
resource "aws_s3_account_public_access_block" "this" {
  count                   = var.manage_account_public_access_block ? 1 : 0
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  lifecycle { prevent_destroy = true }
}

# Switching a bucket to SSE-KMS breaks readers that lack kms:Decrypt on var.kms_key_arn
# (CloudFront OAI, cross-account consumers, some AWS services). Grant them first.
# Opt-in via manage_bucket_sse.
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  count  = var.manage_bucket_sse ? 1 : 0
  bucket = var.bucket_name
  lifecycle { prevent_destroy = true }
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# Deny any request not using TLS (aws:SecureTransport = false). CIS/Prowler flag buckets
# without this policy.
#
# WARNING: a bucket has exactly ONE policy and aws_s3_bucket_policy REPLACES it. To keep
# existing statements (CloudFront OAC, cross-account access, VPC-endpoint rules), paste
# the bucket's CURRENT policy into var.existing_bucket_policy_json — it is merged with
# the TLS statement below:
#   aws s3api get-bucket-policy --bucket <bucket_name> --query Policy --output text
# Set enforce_tls_bucket_policy = false to leave the bucket policy untouched.
data "aws_iam_policy_document" "require_tls" {
  source_policy_documents = var.existing_bucket_policy_json == "" ? [] : [var.existing_bucket_policy_json]

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.bucket_name}",
      "arn:aws:s3:::${var.bucket_name}/*"
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "require_tls" {
  count  = var.enforce_tls_bucket_policy ? 1 : 0
  bucket = var.bucket_name
  policy = data.aws_iam_policy_document.require_tls.json
  # destroy would delete the WHOLE policy, including the merged pre-existing statements.
  lifecycle { prevent_destroy = true }
}''',
        },
        "iam_mfa": {
            "title": "IAM MFA Enforcement",
            "description": "Managed policy denying actions when MFA is absent.",
            "body": lambda: '''resource "aws_iam_policy" "enforce_mfa" {
  name        = "${var.name_prefix}-enforce-mfa"
  description = "Deny all except MFA self-management when MFA not present"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllExceptMFAManagement"
        Effect   = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:GetUser",
          "iam:ListMFADevices", "iam:ListVirtualMFADevices", "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource  = "*"
        Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
      }
    ]
  })
}''',
        },
        "security_groups": {
            "title": "Security Group Restriction",
            "description": "Security group with no unrestricted (0.0.0.0/0) SSH/RDP ingress.",
            "body": lambda: '''# NEW security group (reference template): attach it to the intended instances/ENIs.
resource "aws_security_group" "restricted" {
  #checkov:skip=CKV2_AWS_5:Template security group; the operator attaches it to the intended resources.
  #checkov:skip=CKV_AWS_382:Egress CIDRs are an explicit required operator decision (var.allowed_egress_cidrs).
  name        = "${var.name_prefix}-restricted"
  description = "No unrestricted ingress on sensitive ports"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from corporate CIDR only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }
  # WARNING: egress is an explicit decision (no default). Narrowing it below 0.0.0.0/0
  # cuts internet AND AWS public-endpoint access (S3, STS, SSM, ECR...) for anything
  # attached to this group unless VPC endpoints / a proxy cover that traffic.
  egress {
    description = "Egress limited to operator-approved CIDRs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.allowed_egress_cidrs
  }
  tags = local.tags
}''',
        },
        "encryption_at_rest": {
            "title": "EBS/RDS Encryption at Rest",
            "description": "Enable account-default EBS encryption (regional, opt-in).",
            "body": lambda: '''# REGION-WIDE: every new EBS volume in var.region is encrypted with var.kms_key_arn.
# The key policy MUST grant the AutoScaling service-linked role (and any other launcher)
# kms:CreateGrant/Decrypt/GenerateDataKey*, or Auto Scaling / Spot launches will fail.
# BEFORE APPLY capture: aws ec2 get-ebs-encryption-by-default; aws ec2 get-ebs-default-kms-key-id
# prevent_destroy: destroy would DISABLE default encryption (weaker than before).
resource "aws_ebs_encryption_by_default" "this" {
  count   = var.manage_ebs_default_encryption ? 1 : 0
  enabled = true
  lifecycle { prevent_destroy = true }
}

resource "aws_ebs_default_kms_key" "this" {
  count   = var.manage_ebs_default_encryption ? 1 : 0
  key_arn = var.kms_key_arn
  lifecycle { prevent_destroy = true }
}''',
        },
        "audit_logging": {
            "title": "Multi-Region CloudTrail",
            "description": "Multi-region CloudTrail with a hardened (versioned, encrypted, HTTPS-only, CloudTrail-only-write) log bucket.",
            "body": lambda: '''# create_log_bucket = true  -> creates a NEW, hardened log bucket named var.log_bucket_name
#                            (versioning + Object Lock). Object Lock can only be enabled
#                            at creation, so the name must NOT already exist.
# create_log_bucket = false -> uses an EXISTING bucket as-is; nothing about it is changed.
#                            Its policy must already allow this trail to write, e.g. the
#                            AWSCloudTrailAclCheck / AWSCloudTrailWrite statements below.
data "aws_caller_identity" "trail" {}
data "aws_partition" "trail" {}
data "aws_region" "trail" {}

locals {
  cloudtrail_name = "${var.name_prefix}-trail"
  cloudtrail_arn  = "arn:${data.aws_partition.trail.partition}:cloudtrail:${data.aws_region.trail.name}:${data.aws_caller_identity.trail.account_id}:trail/${local.cloudtrail_name}"
}

resource "aws_cloudtrail" "this" {
  name                          = local.cloudtrail_name
  s3_bucket_name                = var.log_bucket_name
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.cloudtrail_kms_key_arn
  # CIS 3.4: deliver events to CloudWatch Logs for metric filters / alarms.
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_cloudwatch.arn
  sns_topic_name             = aws_sns_topic.trail.name
  depends_on = [aws_s3_bucket_policy.trail_logs, aws_sns_topic_policy.trail,
  aws_iam_role_policy.trail_cloudwatch]
  lifecycle { prevent_destroy = true }
  tags = local.tags
}

# CloudWatch Logs destination, encrypted with var.log_kms_key_arn: its key policy must allow
# logs.<region>.amazonaws.com for this log group (and the flow-log group, if used).
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${local.cloudtrail_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = local.tags
}

resource "aws_iam_role" "trail_cloudwatch" {
  name = "${local.cloudtrail_name}-cloudwatch"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceArn" = local.cloudtrail_arn } }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "trail_cloudwatch" {
  name = "write-trail-log-group"
  role = aws_iam_role.trail_cloudwatch.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:log-stream:*"
    }]
  })
}

# Delivery notifications (CKV_AWS_252), encrypted with the trail key. The key policy of
# var.cloudtrail_kms_key_arn must ALSO allow cloudtrail.amazonaws.com kms:GenerateDataKey*
# and kms:Decrypt WITHOUT the aws:cloudtrail:arn encryption-context condition, or
# CloudTrail cannot publish to this encrypted topic (failures are silent).
resource "aws_sns_topic" "trail" {
  name              = "${local.cloudtrail_name}-notifications"
  kms_master_key_id = var.cloudtrail_kms_key_arn
  tags              = local.tags
}

resource "aws_sns_topic_policy" "trail" {
  arn = aws_sns_topic.trail.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AWSCloudTrailSNSPolicy"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.trail.arn
      Condition = { StringEquals = { "aws:SourceArn" = local.cloudtrail_arn } }
    }]
  })
}

resource "aws_s3_bucket" "trail_logs" {
  #checkov:skip=CKV_AWS_144:Cross-region replication needs a customer-chosen DR bucket/region and replication role; enable per DR policy.
  count               = var.create_log_bucket ? 1 : 0
  bucket              = var.log_bucket_name
  object_lock_enabled = true
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.access_log_bucket_name != ""
      error_message = "access_log_bucket_name is required when create_log_bucket = true (CIS 3.6 access logging)."
    }
  }
  tags = local.tags
}

# CIS 3.6: server access logging for the trail bucket, into a SEPARATE existing bucket.
resource "aws_s3_bucket_logging" "trail_logs" {
  count         = var.create_log_bucket ? 1 : 0
  bucket        = aws_s3_bucket.trail_logs[0].id
  target_bucket = var.access_log_bucket_name
  target_prefix = "${var.log_bucket_name}/"
}

# Move older logs to cheaper storage; never expire (Object Lock retains them).
resource "aws_s3_bucket_lifecycle_configuration" "trail_logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail_logs[0].id
  rule {
    id     = "archive-trail-logs"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
  depends_on = [aws_s3_bucket_versioning.trail_logs]
}

# Emit object events to EventBridge (no target required; enables detection rules).
resource "aws_s3_bucket_notification" "trail_logs" {
  count       = var.create_log_bucket ? 1 : 0
  bucket      = aws_s3_bucket.trail_logs[0].id
  eventbridge = true
}

# Versioning so log objects cannot be silently overwritten.
resource "aws_s3_bucket_versioning" "trail_logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail_logs[0].id
  versioning_configuration { status = "Enabled" }
}

# Object Lock (governance) retains logs against deletion/overwrite for
# var.log_object_lock_days. Objects cannot be removed early without governance bypass.
resource "aws_s3_bucket_object_lock_configuration" "trail_logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail_logs[0].id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.log_object_lock_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.trail_logs]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail_logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.cloudtrail_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  count                   = var.create_log_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.trail_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy: require TLS, and allow ONLY this account's trail (aws:SourceArn +
# aws:SourceAccount) to read the ACL and write under AWSLogs/<account-id>/ — so no other
# account's trail can write (Object-Locked) files into this bucket.
resource "aws_s3_bucket_policy" "trail_logs" {
  count  = var.create_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.trail_logs[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.trail_logs[0].arn,
          "${aws_s3_bucket.trail_logs[0].arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_logs[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceArn"     = local.cloudtrail_arn
            "aws:SourceAccount" = data.aws_caller_identity.trail.account_id
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_logs[0].arn}/AWSLogs/${data.aws_caller_identity.trail.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceArn"     = local.cloudtrail_arn
            "aws:SourceAccount" = data.aws_caller_identity.trail.account_id
          }
        }
      }
    ]
  })
}''',
        },
        "flow_logs": {
            "title": "VPC Flow Logs",
            "description": "Enable VPC Flow Logs to an encrypted CloudWatch Log group with CIS-compliant retention.",
            "body": lambda: '''resource "aws_flow_log" "this" {
  vpc_id          = var.vpc_id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = var.flow_log_role_arn
  tags            = local.tags
}

resource "aws_cloudwatch_log_group" "flow" {
  name = "/vpc/flowlogs/${var.vpc_id}"
  # CIS AWS Foundations requires log retention of at least 90 days; default to 365.
  # Set var.log_retention_days = 0 only if you intentionally want never-expire.
  retention_in_days = var.log_retention_days
  # Encrypt log data at rest with a customer-managed KMS key (CIS logging controls).
  kms_key_id = var.log_kms_key_arn
}''',
        },
        "kms_rotation": {
            "title": "KMS Key Rotation",
            "description": "Customer-managed KMS key with annual rotation.",
            "body": lambda: '''data "aws_caller_identity" "kms" {}
data "aws_partition" "kms" {}

# Explicit key policy (CKV2_AWS_64): account-root administration, which delegates key
# access to IAM. Add service/role statements (e.g. logs, AutoScaling) as needed.
data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109:Standard KMS key-policy root statement; in a key policy, Resource "*" means this key only.
  #checkov:skip=CKV_AWS_111:Standard KMS key-policy root statement; access is delegated to IAM policies.
  #checkov:skip=CKV_AWS_356:In a KMS key policy, Resource "*" refers to the key the policy is attached to.
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.kms.partition}:iam::${data.aws_caller_identity.kms.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name_prefix} CMK with rotation"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
  lifecycle { prevent_destroy = true }
  tags                    = local.tags
}''',
        },
    },
    # ----------------------------- Azure -----------------------------
    "azure": {
        "storage_secure": {
            "title": "Storage Account Secure Transfer & Private Access",
            "description": "NEW storage account: HTTPS-only, no public/network access, Entra-only auth, CMK, soft-delete, private endpoint.",
            "body": lambda: '''# NEW storage account (reference template). Data-plane access is ONLY via the private
# endpoint below and Entra ID (shared keys disabled); the provider uses
# storage_use_azuread = true for this reason.
resource "azurerm_storage_account" "this" {
  #checkov:skip=CKV_AZURE_33:Queue logging is set by the azurerm_monitor_diagnostic_setting below (Azure Monitor), which this check does not evaluate.
  name                            = var.storage_account_name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
  shared_access_key_enabled       = false

  identity {
    type         = "UserAssigned"
    identity_ids = [var.storage_cmk_identity_id]
  }
  customer_managed_key {
    key_vault_key_id          = var.storage_cmk_key_id
    user_assigned_identity_id = var.storage_cmk_identity_id
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  sas_policy {
    expiration_period = "01.00:00:00"
    expiration_action = "Log"
  }

  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 30 }
    container_delete_retention_policy { days = 30 }
  }

  tags = local.tags
}

# Queue read/write/delete logging via Azure Monitor diagnostic settings (control plane),
# so apply works without data-plane network access to the private account.
resource "azurerm_monitor_diagnostic_setting" "storage_queue" {
  name                       = "${var.name_prefix}-st-queue-logs"
  target_resource_id         = "${azurerm_storage_account.this.id}/queueServices/default"
  log_analytics_workspace_id = var.log_analytics_workspace_id
  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }
}

resource "azurerm_private_endpoint" "storage_blob" {
  name                = "${var.name_prefix}-st-blob-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id
  private_service_connection {
    name                           = "${var.name_prefix}-st-blob"
    private_connection_resource_id = azurerm_storage_account.this.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  tags = local.tags
}''',
        },
        "entra_mfa": {
            "title": "Entra ID MFA / Conditional Access",
            "description": "Conditional access policy requiring MFA (report-only by default, break-glass excluded).",
            "body": lambda: '''# Starts in REPORT-ONLY mode (var.conditional_access_state) so impact can be reviewed in
# the sign-in logs before enforcement. Break-glass / emergency-access accounts MUST be
# excluded, or a misconfiguration can lock every administrator out of the tenant.
# Modern-auth clients only; block legacy authentication with a separate policy.
resource "azuread_conditional_access_policy" "require_mfa" {
  display_name = "${var.name_prefix}-require-mfa"
  state        = var.conditional_access_state
  conditions {
    users {
      included_users  = ["All"]
      excluded_users  = var.ca_excluded_user_ids
      excluded_groups = var.ca_excluded_group_ids
    }
    applications { included_applications = ["All"] }
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]
  }
  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
  lifecycle {
    precondition {
      condition     = length(var.ca_excluded_user_ids) + length(var.ca_excluded_group_ids) > 0
      error_message = "Exclude at least one break-glass account or group (ca_excluded_user_ids / ca_excluded_group_ids)."
    }
  }
}''',
        },
        "nsg_restrict": {
            "title": "NSG Restriction",
            "description": "Network security group denying broad internet inbound to management ports.",
            "body": lambda: '''resource "azurerm_network_security_group" "restricted" {
  name                = "${var.name_prefix}-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  # Deny Internet-sourced management traffic at a HIGH priority (low number) so it is
  # evaluated BEFORE any existing permissive allow rules. A deny placed at a high
  # priority number (e.g. 4096) would be evaluated last and lose to earlier allow
  # rules, so it would NOT remediate the finding. Processing order is lowest-number-
  # first, so this (100) wins over typical allow rules.
  security_rule {
    name                       = "deny-internet-ssh-rdp-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_ranges    = ["22", "3389"]
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
  tags = local.tags
}''',
        },
        "disk_sql_encryption": {
            "title": "Disk / SQL Encryption",
            "description": "Azure SQL TDE with a customer-managed key (never downgrades to service-managed).",
            "body": lambda: '''# Takes over the server's EXISTING TDE setting. Without key_vault_key_id this resource
# would switch a CMK-protected server back to service-managed keys, so the key is
# required. The server's managed identity needs get/wrapKey/unwrapKey on the key.
# BEFORE APPLY capture: az sql server tde-key show --server <name> --resource-group <rg>
# prevent_destroy: destroy resets TDE to service-managed keys (weaker than before).
resource "azurerm_mssql_server_transparent_data_encryption" "this" {
  server_id             = var.sql_server_id
  key_vault_key_id      = var.tde_key_vault_key_id
  auto_rotation_enabled = true
  lifecycle { prevent_destroy = true }
}''',
        },
        "activity_log": {
            "title": "Activity Log + Diagnostic Settings",
            "description": "Route activity logs to a Log Analytics workspace.",
            "body": lambda: '''resource "azurerm_monitor_diagnostic_setting" "activity" {
  name                       = "${var.name_prefix}-activity"
  target_resource_id         = var.subscription_id
  log_analytics_workspace_id = var.log_analytics_workspace_id
  enabled_log { category_group = "audit" }
}''',
        },
        "keyvault_protection": {
            "title": "Key Vault Soft-Delete & Purge Protection",
            "description": "NEW Key Vault: soft-delete + purge protection, no public network access, private endpoint.",
            "body": lambda: '''resource "azurerm_key_vault" "this" {
  name                          = var.key_vault_name
  location                      = var.location
  resource_group_name           = var.resource_group_name
  tenant_id                     = var.tenant_id
  sku_name                      = "standard"
  soft_delete_retention_days    = 90
  purge_protection_enabled      = true
  public_network_access_enabled = false
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
  tags = local.tags
}

resource "azurerm_private_endpoint" "key_vault" {
  name                = "${var.name_prefix}-kv-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id
  private_service_connection {
    name                           = "${var.name_prefix}-kv"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
  tags = local.tags
}''',
        },
    },
    # ----------------------------- GCP -----------------------------
    "gcp": {
        "gcs_public_access": {
            "title": "GCS Uniform Access & Public Access Prevention",
            "description": "Uniform bucket-level access + enforced public access prevention.",
            "body": lambda: '''resource "google_storage_bucket" "this" {
  name                        = var.bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning { enabled = true }
  logging { log_bucket = var.gcs_access_log_bucket }
  labels = local.labels
}''',
        },
        "iam_least_privilege": {
            "title": "IAM Least Privilege",
            "description": "Custom role scoped to least privilege.",
            "body": lambda: '''resource "google_project_iam_custom_role" "least_priv" {
  role_id     = "${replace(var.name_prefix, "-", "_")}_least_priv"
  title       = "${var.name_prefix} least privilege"
  permissions = var.permissions
}''',
        },
        "firewall_restrict": {
            "title": "Firewall Rule Restriction",
            "description": "Deny internet SSH/RDP; allow management only from a trusted range to tagged VMs.",
            "body": lambda: '''# GCP firewall ALLOW rules are additive, so restriction needs an explicit DENY. For VMs
# tagged var.mgmt_target_tags ONLY: deny SSH/RDP from every source (priority 900, above
# default-allow-ssh/rdp/internal at 65534), then allow it from var.allowed_mgmt_cidrs
# (priority 800). Untagged VMs are unaffected. Include 35.235.240.0/20 in
# allowed_mgmt_cidrs if you use IAP TCP forwarding, and your bastion/VPC ranges if needed.
resource "google_compute_firewall" "deny_mgmt_internet" {
  name          = "${var.name_prefix}-deny-mgmt"
  network       = var.network
  direction     = "INGRESS"
  priority      = 900
  source_ranges = ["0.0.0.0/0"]
  target_tags   = var.mgmt_target_tags
  deny {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
  log_config { metadata = "INCLUDE_ALL_METADATA" }
}

resource "google_compute_firewall" "allow_mgmt_trusted" {
  name          = "${var.name_prefix}-allow-mgmt-trusted"
  network       = var.network
  direction     = "INGRESS"
  priority      = 800
  source_ranges = var.allowed_mgmt_cidrs
  target_tags   = var.mgmt_target_tags
  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
  log_config { metadata = "INCLUDE_ALL_METADATA" }
}''',
        },
        "cmek_encryption": {
            "title": "CMEK Encryption",
            "description": "Customer-managed encryption key (CMEK) with rotation.",
            "body": lambda: '''resource "google_kms_crypto_key" "this" {
  name            = "${var.name_prefix}-cmek"
  key_ring        = var.key_ring_id
  rotation_period = "7776000s"
  lifecycle { prevent_destroy = true }
}''',
        },
        "audit_logs": {
            "title": "Cloud Audit Logs",
            "description": "Enable data-access audit logging for all services.",
            "body": lambda: '''# Takes over the project's EXISTING allServices audit config. Import it first if one
# exists: terraform import google_project_iam_audit_config.this "<project-id> allServices"
# prevent_destroy: destroy would REMOVE audit logging (weaker than before).
resource "google_project_iam_audit_config" "this" {
  lifecycle { prevent_destroy = true }
  project = var.project_id
  service = "allServices"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}''',
        },
        "kms_rotation": {
            "title": "KMS Key Rotation",
            "description": "Rotate KMS crypto keys automatically.",
            "body": lambda: '''resource "google_kms_crypto_key" "rotating" {
  name            = "${var.name_prefix}-rotating"
  key_ring        = var.key_ring_id
  rotation_period = "7776000s"
  lifecycle { prevent_destroy = true }
}''',
        },
    },
    # ----------------------------- OCI -----------------------------
    "oci": {
        "object_storage_visibility": {
            "title": "Object Storage Private Visibility",
            "description": "Ensure object storage buckets are private.",
            "body": lambda: '''resource "oci_objectstorage_bucket" "this" {
  compartment_id = var.compartment_ocid
  name           = var.bucket_name
  namespace      = var.namespace
  access_type           = "NoPublicAccess"
  versioning            = "Enabled"
  kms_key_id            = var.kms_key_id
  object_events_enabled = true
}''',
        },
        "iam_policy": {
            "title": "IAM Policy Hardening",
            "description": "Least-privilege IAM policy in the tenancy.",
            "body": lambda: '''resource "oci_identity_policy" "least_priv" {
  compartment_id = var.tenancy_ocid
  name           = "${var.name_prefix}-least-priv"
  description    = "Least privilege policy"
  statements     = var.policy_statements
}''',
        },
        "security_lists": {
            "title": "Security List Restriction",
            "description": "Restrict ingress in the VCN security list.",
            "body": lambda: '''resource "oci_core_security_list" "restricted" {
  compartment_id = var.compartment_ocid
  vcn_id         = var.vcn_id
  display_name   = "${var.name_prefix}-restricted"
  # Security lists are additive across a subnet's lists: this permits ONLY SSH (tcp/22)
  # from var.allowed_cidr. Remove broader rules from the subnet's other lists separately.
  ingress_security_rules {
    protocol = "6"
    source   = var.allowed_cidr
    tcp_options {
      min = 22
      max = 22
    }
  }
}''',
        },
        "volume_db_encryption": {
            "title": "Block Volume / DB Encryption",
            "description": "Encrypt block volumes with a Vault key.",
            "body": lambda: '''resource "oci_core_volume" "encrypted" {
  #checkov:skip=CKV_OCI_2:Backups use oci_core_volume_backup_policy_assignment below (the deprecated backup_policy_id attribute is what this check reads).
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  kms_key_id          = var.kms_key_id
}

# Oracle-defined "silver" backup policy (weekly incrementals, monthly fulls).
data "oci_core_volume_backup_policies" "silver" {
  filter {
    name   = "display_name"
    values = ["silver"]
  }
}

resource "oci_core_volume_backup_policy_assignment" "encrypted" {
  asset_id  = oci_core_volume.encrypted.id
  policy_id = data.oci_core_volume_backup_policies.silver.volume_backup_policies[0].id
}''',
        },
        "audit_logging": {
            "title": "Audit Logging",
            "description": "Ensure the tenancy audit retention is configured.",
            "body": lambda: '''resource "oci_audit_configuration" "this" {
  compartment_id                  = var.tenancy_ocid
  retention_period_days           = 365
}''',
        },
        "vault_rotation": {
            "title": "Vault Key Rotation",
            "description": "Vault master encryption key with automatic rotation.",
            "body": lambda: '''# Auto-rotation requires a Virtual Private Vault (OCI limitation).
resource "oci_kms_key" "this" {
  compartment_id          = var.compartment_ocid
  display_name            = "${var.name_prefix}-key"
  management_endpoint     = var.management_endpoint
  protection_mode         = "HSM"
  is_auto_rotation_enabled = true
  auto_key_rotation_details {
    rotation_interval_in_days = 90
  }
  key_shape {
    algorithm = "AES"
    length    = 32
  }
  lifecycle { prevent_destroy = true }
}''',
        },
    },
}

DISCLAIMER = (
    "# ⚠️  AUTO-GENERATED — REVIEW BEFORE DEPLOY\n"
    "# This Terraform is generated from Prowler remediation data and touches sensitive\n"
    "# controls (identity, network, logging, encryption/key stores). Review it, run\n"
    "# `terraform init && terraform validate && terraform plan`, and validate against\n"
    "# your environment and change-management process BEFORE `terraform apply`.\n"
    "# It is a starting point, not guaranteed production-ready.\n"
)


def load_analysis(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# Available variable definitions for each provider. Referenced variables are
# declared once in shared variables.tf. Format:
# name -> (hcl_type, default_or_None, description)
PROVIDER_VARIABLES = {
    "aws": {
        "region": ("string", "us-east-1", "Target AWS region."),
        "bucket_name": ("string", None, "Target S3 bucket name (for encryption config)."),
        "kms_key_arn": ("string", None, "KMS key ARN for encryption at rest."),
        "vpc_id": ("string", None, "VPC ID for security group / flow logs."),
        "allowed_cidr": ("string", None, "Trusted management CIDR for SSH ingress (not 0.0.0.0/0)."),
        "manage_account_public_access_block": ("bool", None, "Manage ACCOUNT-WIDE S3 Block Public Access. Breaks intentionally public buckets / static websites."),
        "manage_bucket_sse": ("bool", None, "Manage SSE-KMS on bucket_name. Readers without kms:Decrypt on kms_key_arn lose access."),
        "manage_ebs_default_encryption": ("bool", None, "Manage REGION-WIDE default EBS encryption with kms_key_arn. The key policy must allow the AutoScaling service-linked role."),
        "access_log_bucket_name": ("string", "", "Existing bucket that receives S3 server access logs for a newly created trail bucket (required when create_log_bucket = true)."),
        "enforce_tls_bucket_policy": ("bool", None, "Manage the bucket policy to deny non-TLS requests. REPLACES the existing policy unless existing_bucket_policy_json is set."),
        "existing_bucket_policy_json": ("string", "", "Current bucket policy JSON to merge with the TLS statement (aws s3api get-bucket-policy). Empty = bucket has no policy today."),
        "allowed_egress_cidrs": ("list(string)", None, "Egress CIDRs for the security group. Anything narrower than 0.0.0.0/0 blocks internet and AWS public endpoints unless VPC endpoints exist."),
        "create_log_bucket": ("bool", None, "true = create a NEW CloudTrail log bucket (Object Lock, name must not exist); false = use an EXISTING bucket unchanged."),
        "log_bucket_name": ("string", None, "CloudTrail log bucket name. New bucket name if create_log_bucket = true, otherwise an existing bucket that already allows this trail to write."),
        "log_object_lock_days": ("number", 365, "Object Lock governance retention in days for a newly created log bucket."),
        "cloudtrail_kms_key_arn": ("string", None, "KMS key for CloudTrail logs (SSE-KMS) and the trail SNS topic. Key policy must allow cloudtrail.amazonaws.com GenerateDataKey* (log files) and GenerateDataKey*+Decrypt without encryption context (SNS)."),
        "log_retention_days": ("number", 365, "CloudWatch log retention in days (CIS requires >= 90)."),
        "log_kms_key_arn": ("string", None, "KMS key for the CloudWatch log groups (VPC flow logs and CloudTrail). Key policy must allow logs.<region>.amazonaws.com for those log group ARNs."),
        "flow_log_role_arn": ("string", None, "IAM role ARN for VPC flow logs."),
    },
    "azure": {
        "location": ("string", "eastus", "Azure location."),
        "resource_group_name": ("string", None, "Azure resource group name."),
        "storage_account_name": ("string", None, "Storage account name."),
        "key_vault_name": ("string", None, "Key Vault name."),
        "tenant_id": ("string", None, "Entra ID tenant ID."),
        "subscription_id": ("string", None, "Azure subscription resource ID."),
        "sql_server_id": ("string", None, "Azure SQL server resource ID."),
        "log_analytics_workspace_id": ("string", None, "Log Analytics workspace ID."),
        "storage_cmk_key_id": ("string", None, "Key Vault key ID (versionless) for storage CMK. The vault needs purge protection; storage_cmk_identity_id needs the Key Vault Crypto Service Encryption User role."),
        "storage_cmk_identity_id": ("string", None, "User-assigned managed identity ID with get/wrapKey/unwrapKey on storage_cmk_key_id."),
        "private_endpoint_subnet_id": ("string", None, "Subnet ID for the storage / Key Vault private endpoints."),
        "tde_key_vault_key_id": ("string", None, "Key Vault key ID for Azure SQL TDE (customer-managed). Required so TDE is never downgraded."),
        "conditional_access_state": ("string", "enabledForReportingButNotEnforced", "Conditional Access state: enabledForReportingButNotEnforced (report-only), enabled, or disabled."),
        "ca_excluded_user_ids": ("list(string)", [], "Object IDs of break-glass / emergency-access users excluded from the MFA policy (this or ca_excluded_group_ids must be non-empty)."),
        "ca_excluded_group_ids": ("list(string)", [], "Object IDs of groups excluded from the MFA policy (e.g. break-glass group)."),
    },
    "gcp": {
        "project_id": ("string", None, "GCP project ID."),
        "region": ("string", "us-central1", "GCP region."),
        "bucket_name": ("string", None, "Cloud Storage bucket name."),
        "network": ("string", "default", "VPC network name."),
        "allowed_mgmt_cidrs": ("list(string)", None, "Trusted source ranges for SSH/RDP to tagged VMs (e.g. corporate, bastion, IAP 35.235.240.0/20). Not 0.0.0.0/0."),
        "mgmt_target_tags": ("list(string)", None, "Network tags of the VMs that may receive SSH from allowed_cidr."),
        "gcs_access_log_bucket": ("string", None, "Existing bucket that receives access logs for bucket_name."),
        "key_ring_id": ("string", None, "KMS key ring ID."),
        "permissions": ("list(string)", None, "Custom role permissions (least privilege; must not be empty)."),
    },
    "oci": {
        "region": ("string", "us-ashburn-1", "OCI region."),
        "tenancy_ocid": ("string", None, "OCI tenancy OCID."),
        "compartment_ocid": ("string", None, "Compartment OCID."),
        "bucket_name": ("string", None, "Object Storage bucket name."),
        "namespace": ("string", None, "Object Storage namespace."),
        "vcn_id": ("string", None, "VCN OCID."),
        "allowed_cidr": ("string", None, "Trusted management CIDR for SSH (not 0.0.0.0/0)."),
        "kms_key_id": ("string", None, "Vault key OCID for volume / bucket encryption. Bucket use requires the IAM policy: Allow service objectstorage-<region> to use keys in compartment <compartment>."),
        "management_endpoint": ("string", None, "Vault management endpoint."),
        "availability_domain": ("string", None, "Availability domain."),
        "policy_statements": ("list(string)", None, "IAM policy statements (least privilege; must not be empty)."),
    },
}


# Variable validation blocks: name -> (condition, error_message). Applied for every
# provider that declares the variable.
VARIABLE_VALIDATIONS = {
    "allowed_cidr": ('can(cidrhost(var.allowed_cidr, 0)) && var.allowed_cidr != "0.0.0.0/0"',
                     "allowed_cidr must be a valid CIDR and must not be 0.0.0.0/0."),
    "allowed_egress_cidrs": ("length(var.allowed_egress_cidrs) > 0",
                             "allowed_egress_cidrs must list at least one CIDR."),
    "conditional_access_state": ('contains(["enabledForReportingButNotEnforced", "enabled", "disabled"], var.conditional_access_state)',
                                 "conditional_access_state must be enabledForReportingButNotEnforced, enabled, or disabled."),
    "allowed_mgmt_cidrs": ('length(var.allowed_mgmt_cidrs) > 0 && alltrue([for c in var.allowed_mgmt_cidrs : can(cidrhost(c, 0)) && c != "0.0.0.0/0"])',
                           "allowed_mgmt_cidrs must list valid CIDRs and must not include 0.0.0.0/0."),
    "mgmt_target_tags": ("length(var.mgmt_target_tags) > 0",
                         "mgmt_target_tags must name at least one network tag."),
    "permissions": ("length(var.permissions) > 0",
                    "permissions must not be empty (an empty custom role fails to apply)."),
    "policy_statements": ("length(var.policy_statements) > 0",
                          "policy_statements must not be empty."),
}


def _hcl_string_literal(value: str) -> str:
    """Quote text as a literal Terraform string, including template markers."""
    escapes = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    escaped = []
    for char in value:
        codepoint = ord(char)
        if char in escapes:
            escaped.append(escapes[char])
        elif codepoint < 32 or 127 <= codepoint <= 159:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(char)
    text = "".join(escaped)
    return '"' + text.replace("${", "$${").replace("%{", "%%{") + '"'


def _hcl_default(value):
    """Render a Python default as an HCL literal for a variable default."""
    if value is None:
        return None  # required variable, no default
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[]" if not value else "[" + ", ".join(_hcl_string_literal(v) for v in value) + "]"
    return _hcl_string_literal(value)


def _selected_variables(provider: str, terraform_parts: list) -> set:
    """Find variables referenced by the selected resources, provider, and locals."""
    referenced = set()
    for part in terraform_parts:
        referenced.update(re.findall(r"\bvar\.([A-Za-z_][A-Za-z0-9_]*)\b", part))
    available = {"environment", "name_prefix", *PROVIDER_VARIABLES[provider]}
    missing = referenced - available
    if missing:
        raise ValueError(f"Missing variable definitions: {', '.join(sorted(missing))}")
    return referenced


def _render_variables_tf(provider: str, customer: str, selected_variables: set) -> str:
    """Build shared variables.tf for variables referenced by generated Terraform."""
    lines = [
        "# Shared variable declarations for all remediation modules in this directory.",
        "# Declared once here so modules never redeclare them. Fill values in terraform.tfvars.",
        "",
    ]
    # environment + name_prefix are common to every provider
    common = {
        "environment": ("string", "production", "Deployment environment tag/label."),
        "name_prefix": ("string", customer.lower().replace(" ", "-"), "Prefix for resource names."),
    }
    allvars = {**common, **PROVIDER_VARIABLES.get(provider, {})}
    for name, (vtype, default, desc) in allvars.items():
        if name not in selected_variables:
            continue
        block = [f'variable "{name}" {{', f'  type        = {vtype}', f'  description = "{desc}"']
        d = _hcl_default(default)
        if d is not None:
            block.append(f"  default     = {d}")
        if name in VARIABLE_VALIDATIONS:
            condition, message = VARIABLE_VALIDATIONS[name]
            block.extend(["  validation {", f"    condition     = {condition}",
                          f'    error_message = "{message}"', "  }"])
        block.append("}")
        lines.append("\n".join(block))
        lines.append("")
    return "\n".join(lines)


# Example values + warnings for variables that are deliberate operator DECISIONS (no
# default). Rendered into terraform.tfvars.example so the choice is visible.
TFVARS_EXAMPLES = {
    "azure": {
        "ca_excluded_user_ids": (
            '["<break-glass-user-object-id>"]',
            "DECIDE: break-glass accounts that must never be blocked by the MFA policy"),
        "conditional_access_state": (
            '"enabledForReportingButNotEnforced"',
            "report-only first; switch to \"enabled\" after reviewing sign-in logs"),
    },
    "gcp": {
        "allowed_mgmt_cidrs": ('["10.0.0.0/8", "35.235.240.0/20"]',
                               "DECIDE: trusted SSH/RDP sources (35.235.240.0/20 = IAP)"),
        "mgmt_target_tags": ('["ssh-managed"]', "DECIDE: only VMs with these tags accept SSH from allowed_cidr"),
        "permissions": ('["storage.objects.get"]', "DECIDE: least-privilege permission list"),
    },
    "oci": {
        "allowed_cidr": ('"10.0.0.0/8"', "DECIDE: trusted management CIDR only"),
        "policy_statements": ('["Allow group <group> to read buckets in compartment <compartment>"]',
                              "DECIDE: least-privilege statements"),
    },
    "aws": {
        "enforce_tls_bucket_policy": (
            "false",
            "DECIDE: true REPLACES the bucket policy - set existing_bucket_policy_json first"),
        "existing_bucket_policy_json": (
            '""',
            "paste output of: aws s3api get-bucket-policy --bucket <name> --query Policy --output text"),
        "allowed_egress_cidrs": (
            '["0.0.0.0/0"]',
            "DECIDE: narrower CIDRs block internet + AWS public endpoints unless VPC endpoints exist"),
        "manage_account_public_access_block": (
            "false",
            "DECIDE: true blocks public access for EVERY bucket in the account (static sites break)"),
        "manage_bucket_sse": (
            "false",
            "DECIDE: true switches bucket_name to SSE-KMS; grant readers kms:Decrypt first"),
        "manage_ebs_default_encryption": (
            "false",
            "DECIDE: true encrypts all new EBS volumes in the region; key policy must allow AutoScaling"),
        "allowed_cidr": (
            '"10.0.0.0/8"',
            "DECIDE: trusted management CIDR only"),
        "create_log_bucket": (
            "false",
            "DECIDE: true creates a NEW Object-Locked bucket (name must not exist); false uses an existing one unchanged"),
    },
}


def _render_tfvars_example(provider: str, customer: str, selected_variables: set) -> str:
    """Build an example tfvars file for referenced variables."""
    lines = [
        "# Example variables — copy to terraform.tfvars and fill in real values.",
        "# Variables with a sensible default may be omitted.",
        "",
    ]
    if "environment" in selected_variables:
        lines.append('environment = "production"')
    if "name_prefix" in selected_variables:
        lines.append(f'name_prefix = {_hcl_string_literal(customer.lower().replace(" ", "-"))}')
    examples = TFVARS_EXAMPLES.get(provider, {})
    for name, (vtype, default, desc) in PROVIDER_VARIABLES.get(provider, {}).items():
        if name not in selected_variables:
            continue
        if name in examples:
            example, warning = examples[name]
            marker = "   # REQUIRED" if default is None else ""
            lines.append(f"{name} = {example}{marker} - {warning}" if marker
                         else f"{name} = {example}   # {warning}")
            continue
        if vtype.startswith("list"):
            example = "[]"
        elif vtype in ("number", "bool"):
            example = _hcl_default(default) if default is not None else "0"
        else:
            example = _hcl_string_literal(default) if default else '"REPLACE_ME"'
        marker = "" if default not in (None, "") else "   # REQUIRED"
        lines.append(f'{name} = {example}{marker}')
    return "\n".join(lines) + "\n"


def _render_locals_tf(customer: str, provider: str) -> str:
    """Shared locals.tf with tags/labels appropriate to the provider."""
    if provider == "gcp":
        # Bucket label values are limited to 63 lowercase ASCII letters, digits,
        # underscores, and dashes. The environment is supplied later via tfvars.
        safe_customer = re.sub(r"[^a-z0-9_-]", "_", customer.lower())[:63]
        return (
            "# Shared Cloud Storage-compatible labels for remediation modules.\n"
            "locals {\n  labels = {\n"
            '    environment = substr(replace(lower(var.environment), "/[^a-z0-9_-]/", "_"), 0, 63)\n'
            '    managed_by   = "terraform"\n'
            '    purpose      = "security_remediation"\n'
            f'    customer     = "{safe_customer}"\n'
            "  }\n}\n"
        )

    key = "tags"
    return (
        "# Shared tags/labels applied by the remediation modules.\n"
        f'locals {{\n  {key} = {{\n'
        f'    Environment = var.environment\n'
        f'    ManagedBy   = "Terraform"\n'
        f'    Purpose     = "SecurityRemediation"\n'
        f'    Customer    = {_hcl_string_literal(customer)}\n'
        f'  }}\n}}\n'
    )


# Map provider-NEUTRAL capability names (used in docs / the interactive menu) to the
# provider-SPECIFIC catalog keys. This lets users pass either form. Each neutral name
# maps to the right key per provider.
NEUTRAL_ALIASES = {
    "object_storage_public_access": {"aws": "s3_public_access", "azure": "storage_secure",
                                     "gcp": "gcs_public_access", "oci": "object_storage_visibility"},
    # Only providers whose module actually enforces MFA. GCP/OCI least-privilege modules
    # remain selectable by their own keys (iam_least_privilege / iam_policy).
    "identity_mfa": {"aws": "iam_mfa", "azure": "entra_mfa"},
    "network_ingress": {"aws": "security_groups", "azure": "nsg_restrict",
                        "gcp": "firewall_restrict", "oci": "security_lists"},
    "disk_db_encryption": {"aws": "encryption_at_rest", "azure": "disk_sql_encryption",
                           "gcp": "cmek_encryption", "oci": "volume_db_encryption"},
    "audit_logging": {"aws": "audit_logging", "azure": "activity_log", "gcp": "audit_logs",
                      "oci": "audit_logging"},
    "flow_logs": {"aws": "flow_logs"},
    "key_management": {"aws": "kms_rotation", "azure": "keyvault_protection",
                       "gcp": "kms_rotation", "oci": "vault_rotation"},
}


def normalize_selection(sel: str, provider: str, catalog: dict) -> str:
    """Resolve a selection ID to a valid catalog key for the provider.

    Accepts either a provider-specific key (returned as-is if valid) or a
    provider-neutral capability name (mapped via NEUTRAL_ALIASES). Returns the
    resolved key, or "" if it cannot be resolved for this provider.
    """
    if sel in catalog:
        return sel
    mapped = NEUTRAL_ALIASES.get(sel, {}).get(provider)
    if mapped and mapped in catalog:
        return mapped
    return ""


# Header lines every manifest-less generator version wrote. A file is only treated as
# generated if its header matches; anything else is assumed hand-written.
_LEGACY_SHARED_MARKERS = {
    "providers.tf": "# ⚠️  AUTO-GENERATED — REVIEW BEFORE DEPLOY",
    "variables.tf": "# Shared variable declarations for all remediation modules in this directory.",
    "locals.tf": ("# Shared tags/labels applied by the remediation modules.",
                  "# Shared Cloud Storage-compatible labels for remediation modules."),
    "terraform.tfvars.example": "# Example variables — copy to terraform.tfvars and fill in real values.",
}
_LEGACY_MODULE_MARKER = "# Variables are declared in variables.tf; providers/locals are shared."
_LEGACY_MODULE_NAME = re.compile(r"^.+_(aws|azure|gcp|oci)_[a-z0-9_]+\.tf$")


def _terraform_loads(name: str) -> bool:
    """True for directory entries Terraform reads or executes on init/plan/apply.

    Includes local-backend state and the dependency lock file: `terraform init` installs
    every provider named in state (not only in config) and `plan`/`apply` act on the
    resource IDs state maps, so a planted terraform.tfstate is as dangerous as a .tf."""
    lower = name.lower()
    return (lower.endswith((".tf", ".tf.json", ".auto.tfvars", ".auto.tfvars.json"))
            or ".tfstate" in lower
            or lower in ("terraform.tfvars", "terraform.tfvars.json", ".terraform",
                         ".terraform.lock.hcl", "terraform.tfstate.d"))


def _sha256_file(path: str) -> str:
    """SHA-256 of a file's bytes (used to detect operator edits to generated files)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _legacy_generated_files(output_dir: str) -> list:
    """Return basenames in ``output_dir`` that an older (manifest-less) run generated."""
    found = []
    try:
        names = os.listdir(output_dir)
    except OSError:
        return found
    for name in names:
        path = os.path.join(output_dir, name)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(2048)
        except OSError:
            continue
        marker = _LEGACY_SHARED_MARKERS.get(name)
        if marker is not None:
            markers = marker if isinstance(marker, tuple) else (marker,)
            if any(head.startswith(m) for m in markers):
                found.append(name)
        elif _LEGACY_MODULE_NAME.match(name) and _LEGACY_MODULE_MARKER in head:
            found.append(name)
    return sorted(found)


def generate_terraform(customer: str, provider: str, selections: list, output_dir: str,
                       force: bool = False, keep_existing: bool = False):
    """Generate provider-aware Terraform for a directory.

    Emits SHARED files (providers.tf, variables.tf, locals.tf, terraform.tfvars.example)
    exactly once, and one resource-only .tf per selected remediation. This avoids
    duplicate variable/locals declarations and undeclared-variable errors when
    Terraform loads every .tf in the directory together.

    Refuses to overwrite a shared file that already exists but was NOT written by a
    previous run of this generator (i.e. a hand-written file the operator keeps in the
    same directory), unless ``force`` is set.
    """
    if provider not in REMEDIATION_CATALOG:
        valid_providers = ", ".join(sorted(REMEDIATION_CATALOG.keys()))
        print(f"  [ERROR] Unknown provider '{provider}'. Valid providers: {valid_providers}",
              file=sys.stderr)
        return []
    catalog = REMEDIATION_CATALOG[provider]
    tf_meta = PROVIDER_TF[provider]

    # Resolve each selection (accepts provider-neutral names or provider-specific keys),
    # then validate. Fail loudly on unknown IDs rather than silently skipping.
    resolved = [(s, normalize_selection(s, provider, catalog)) for s in selections]
    valid = [r for (_s, r) in resolved if r]
    unknown = [s for (s, r) in resolved if not r]
    # de-dupe while preserving order (neutral aliases can collapse to same key)
    seen = set(); valid = [v for v in valid if not (v in seen or seen.add(v))]
    if unknown:
        print(f"  [ERROR] Unknown {provider} remediation ID(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"          Valid {provider} IDs: {', '.join(catalog.keys())}", file=sys.stderr)
        return []
    if not valid:
        print(f"  [ERROR] No valid remediation selections for provider '{provider}'. Nothing generated.", file=sys.stderr)
        return []

    # --- Shared files (written once) ---
    # Build a version-pinned required_providers block. Add azuread when an Azure
    # identity remediation is selected (its resources use the azuread provider).
    req = REQUIRED_PROVIDERS.get(provider, "")
    needs_azuread = provider == "azure" and any(v in AZURE_IDENTITY_KEYS for v in valid)
    if needs_azuread:
        req = req + AZUREAD_REQUIRED
    provider_blocks = tf_meta["provider_block"]
    if needs_azuread:
        provider_blocks = provider_blocks + '\n\nprovider "azuread" {}'
    locals_tf = _render_locals_tf(customer, provider)
    resource_bodies = {sel: catalog[sel]["body"]() for sel in valid}
    selected_variables = _selected_variables(
        provider, [provider_blocks, locals_tf, *resource_bodies.values()]
    )

    # Re-runs must replace stale generated files (Terraform loads EVERY .tf in the
    # directory) without ever destroying operator work. Rules:
    #   * the conflict check runs BEFORE anything is touched, so a refused run changes nothing;
    #   * a generated file is deleted only if its SHA-256 still matches the manifest;
    #   * a generated file the operator has EDITED is refused (or, with --force, moved to
    #     .cloud-sec-assessment-backup/<timestamp>/) — never deleted;
    #   * pre-manifest (legacy) files can't be verified, so they are always backed up.
    os.makedirs(output_dir, exist_ok=True)
    if os.path.islink(output_dir):
        print(f"  [ERROR] Refusing to write into symlinked output directory: {output_dir}",
              file=sys.stderr)
        return []
    _manifest_name = ".cloud-sec-assessment-manifest.json"
    _manifest_path = os.path.join(output_dir, _manifest_name)
    _output_real = os.path.realpath(output_dir)
    _prior, _hashes = [], {}
    try:
        with open(_manifest_path, "r", encoding="utf-8") as mf:
            _manifest = json.load(mf)
        _prior = [n for n in _manifest.get("generated", []) if isinstance(n, str)]
        _hashes = _manifest.get("sha256", {}) or {}
    except (OSError, ValueError, AttributeError):
        # No (readable) manifest: the folder may hold output from an OLDER generator
        # version. Recognise those files by the headers every version wrote.
        _prior = _legacy_generated_files(output_dir)
        if _prior:
            print(f"  [INFO] No manifest found; {len(_prior)} file(s) from an earlier version "
                  "of this generator will be backed up and replaced.", file=sys.stderr)

    def _safe_target(name):
        """Return the path for a manifest basename, or None if it is unsafe to touch."""
        if name != os.path.basename(name) or name in ("", ".", ".."):
            return None
        target = os.path.join(output_dir, name)
        if not os.path.lexists(target):
            return None
        if os.path.islink(target) or not os.path.isfile(target):
            print(f"  [WARN] Skipping cleanup of non-regular/symlinked entry: {target}",
                  file=sys.stderr)
            return None
        if os.path.realpath(target) != os.path.join(_output_real, name):
            print(f"  [WARN] Skipping cleanup outside output root: {target}", file=sys.stderr)
            return None
        return target

    _shared_files = ["providers.tf", "variables.tf", "locals.tf", "terraform.tfvars.example"]
    _safe_name = re.sub(r'[^\w\-]', '_', customer)
    _targets = _shared_files + [f"{_safe_name}_{provider}_{sel}.tf" for sel in valid]
    _edited = [n for n in _prior
               if n in _hashes and _safe_target(n) and _sha256_file(_safe_target(n)) != _hashes[n]]
    # Any file we are about to write that we did not generate is hand-written.
    _conflicts = [n for n in _targets
                  if os.path.lexists(os.path.join(output_dir, n)) and n not in _prior]
    # Terraform loads EVERY *.tf / *.tf.json / *.auto.tfvars / terraform.tfvars in the
    # directory (and runs providers from .terraform/ and from local state). The default output folder lives
    # inside the untrusted input tree, so an archive could plant e.g. backdoor.tf with
    # data "external". Refuse anything Terraform would load that we did not generate.
    # The manifest itself sits in that untrusted tree, so a manifest entry only vouches for
    # a plain regular file (the only thing this tool writes). A listed .terraform/ folder or
    # symlinked .tf would otherwise skip this refusal AND the cleanup below.
    def _is_plain_file(name):
        path = os.path.join(output_dir, name)
        return not os.path.islink(path) and os.path.isfile(path)

    _unknown = sorted(
        n for n in os.listdir(output_dir)
        if _terraform_loads(n)
        and not ((n in _prior or n in _targets) and _is_plain_file(n)))
    if keep_existing and _unknown:
        print(f"  [WARN] Keeping operator Terraform file(s) Terraform will also load: "
              f"{', '.join(_unknown)} (--keep-existing-terraform).", file=sys.stderr)
        _unknown = []
    if _unknown and not force:
        print(f"  [ERROR] {output_dir} contains file(s) Terraform would load that this tool "
              f"did not generate: {', '.join(_unknown)}.", file=sys.stderr)
        print("          Nothing was changed. If they are your own, re-run with "
              "--keep-existing-terraform; otherwise remove them (delete .terraform/ and re-run "
              "terraform init) or re-run with --force to move them to "
              ".cloud-sec-assessment-backup/.", file=sys.stderr)
        return []
    if (_conflicts or _edited) and not force:
        if _conflicts:
            print(f"  [ERROR] Refusing to overwrite hand-written file(s) in {output_dir}: "
                  f"{', '.join(_conflicts)}.", file=sys.stderr)
        if _edited:
            print(f"  [ERROR] Generated file(s) were edited since the last run: "
                  f"{', '.join(_edited)}.", file=sys.stderr)
        print("          Nothing was changed. Move/rename them, choose a different --output-dir, "
              "or re-run with --force (affected files are moved to "
              ".cloud-sec-assessment-backup/, never deleted).", file=sys.stderr)
        return []

    _backup_root = os.path.join(output_dir, ".cloud-sec-assessment-backup")
    _backup_dir = os.path.join(_backup_root, datetime.now().strftime("%Y%m%dT%H%M%S"))
    # The backup folder sits in the untrusted tree too: refuse a planted symlink (or file)
    # there BEFORE touching anything, so backed-up files can't be moved outside the root.
    if os.path.lexists(_backup_root) and (os.path.islink(_backup_root)
                                          or not os.path.isdir(_backup_root)):
        print(f"  [ERROR] {_backup_root} is a symlink or not a directory. Nothing was "
              "changed. Remove it and re-run.", file=sys.stderr)
        return []
    for name in sorted(set(_prior) | set(_conflicts) | set(_unknown)):
        if name in _unknown:
            # Forced: quarantine unknown Terraform-loaded entries (incl. .terraform/).
            path = os.path.join(output_dir, name)
            if os.path.lexists(path):
                safe_io.ensure_dir_within(_backup_dir, output_dir, mode=0o700)
                os.replace(path, os.path.join(_backup_dir, name))
                print(f"  ↪ quarantined {name} → {os.path.relpath(_backup_dir, output_dir)}/",
                      file=sys.stderr)
            continue
        target = _safe_target(name)
        if target is None:
            continue
        if name in _hashes and _sha256_file(target) == _hashes[name]:
            os.remove(target)
            print(f"  - removed stale generated file {name}")
        else:
            safe_io.ensure_dir_within(_backup_dir, output_dir, mode=0o700)
            os.replace(target, os.path.join(_backup_dir, name))
            print(f"  ↪ backed up {name} → {os.path.relpath(_backup_dir, output_dir)}/",
                  file=sys.stderr)

    with safe_io.open_write_nofollow(os.path.join(output_dir, "providers.tf"), root=output_dir) as fh:
        fh.write(f"{DISCLAIMER}\n"
                 f"# Shared provider + terraform settings for the remediation modules.\n\n"
                 'terraform {\n  required_version = ">= 1.5"\n\n'
                 '  required_providers {'
                 f"{req}\n"
                 '  }\n}\n\n'
                 f"{provider_blocks}\n")
    with safe_io.open_write_nofollow(os.path.join(output_dir, "variables.tf"), root=output_dir) as fh:
        fh.write(_render_variables_tf(provider, customer, selected_variables) + "\n")
    with safe_io.open_write_nofollow(os.path.join(output_dir, "locals.tf"), root=output_dir) as fh:
        fh.write(locals_tf)
    with safe_io.open_write_nofollow(os.path.join(output_dir, "terraform.tfvars.example"), root=output_dir) as fh:
        fh.write(_render_tfvars_example(provider, customer, selected_variables))

    # --- One resource-only module file per selection ---
    generated = ["providers.tf", "variables.tf", "locals.tf", "terraform.tfvars.example"]
    for sel in valid:
        entry = catalog[sel]
        content = (
            f"# {_hcl_string_literal(customer)[1:-1]} — {entry['title']}\n"
            f"# {entry['description']}\n"
            f"# Variables are declared in variables.tf; providers/locals are shared.\n"
            f"#\n"
            f"# NOTE: This is a REFERENCE TEMPLATE. It creates new resources demonstrating\n"
            f"# the correct security posture. You must customize it to target your existing\n"
            f"# resources (e.g. attach to existing subnets/instances) before applying.\n"
            f"# Always run `terraform plan` to review changes before `terraform apply`.\n\n"
            f"{resource_bodies[sel]}\n"
        )
        # Sanitized customer name (computed above) prevents path traversal in filenames.
        filename = f"{_safe_name}_{provider}_{sel}.tf"
        with safe_io.open_write_nofollow(os.path.join(output_dir, filename), root=output_dir) as fh:
            fh.write(content)
        generated.append(filename)
        print(f"  ✓ {filename}")

    # Record exactly what we generated (with content hashes) so the NEXT run removes only
    # our own unmodified files, never hand-written or hand-edited Terraform.
    _written_hashes = {name: _sha256_file(os.path.join(output_dir, name)) for name in generated}
    with safe_io.open_write_nofollow(_manifest_path, root=output_dir) as mf:
        json.dump({"generated": generated, "sha256": _written_hashes}, mf, indent=2)

    return generated


def main():
    parser = argparse.ArgumentParser(description="Generate Terraform remediation modules (multi-cloud)")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("selections", help="Comma-separated remediation IDs")
    parser.add_argument("output_dir", help="Output directory for .tf files")
    parser.add_argument("--provider", default="", help="Cloud provider (aws|azure|gcp|oci). Defaults to first in analysis.")
    parser.add_argument("--force", action="store_true",
                        help="Replace hand-written shared files (providers.tf, variables.tf, "
                             "locals.tf, terraform.tfvars.example) and generated files edited since "
                             "the last run. Affected files are moved to "
                             ".cloud-sec-assessment-backup/<timestamp>/, never deleted.")
    parser.add_argument("--keep-existing-terraform", action="store_true",
                        help="Proceed even though the output directory holds Terraform files this "
                             "tool did not generate (your own modules). Terraform will load them "
                             "too, so only use this for files you wrote and trust.")
    args = parser.parse_args()

    data = load_analysis(args.analysis_json)
    provider = args.provider.strip().lower()
    if not provider:
        providers = (data.get("metadata", {}).get("providers")
            or list(data.get("summary", {}).get("findings_by_provider", {}).keys())
            or data.get("providers")
            or [])
        provider = providers[0] if providers else "aws"

    customer = data.get("metadata", {}).get("customer", "Customer")
    selections = [s.strip() for s in args.selections.split(",") if s.strip()]
    print(f"Generating Terraform ({provider}) for: {', '.join(selections)}")
    generated = generate_terraform(customer, provider, selections, args.output_dir,
                                   force=args.force, keep_existing=args.keep_existing_terraform)
    if not generated:
        print(f"\n❌ No Terraform modules generated — check errors above.", file=sys.stderr)
        sys.exit(1)
    print(f"\n✅ Generated {len(generated)} Terraform module(s) → {args.output_dir}")
    print("⚠️  Review + `terraform plan` before `apply`.")


if __name__ == "__main__":
    main()
