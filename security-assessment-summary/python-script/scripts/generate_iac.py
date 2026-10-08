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
        "provider_block": 'provider "azurerm" {\n  features {}\n}',
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
            "description": "Account-level S3 public access block + default SSE-KMS.",
            "body": lambda: '''resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = var.bucket_name
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# Deny any request not using TLS (aws:SecureTransport = false). CIS/Prowler flag buckets
# without this policy; it ensures data in transit is always encrypted.
resource "aws_s3_bucket_policy" "require_tls" {
  bucket = var.bucket_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.bucket_name}",
          "arn:aws:s3:::${var.bucket_name}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
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
            "body": lambda: '''resource "aws_security_group" "restricted" {
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
  egress {
    description = "Restricted egress to approved CIDR only (no 0.0.0.0/0)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.allowed_egress_cidr]
  }
  tags = local.tags
}''',
        },
        "encryption_at_rest": {
            "title": "EBS/RDS Encryption at Rest",
            "description": "Enable account-default EBS encryption.",
            "body": lambda: '''resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  key_arn = var.kms_key_arn
}''',
        },
        "audit_logging": {
            "title": "Multi-Region CloudTrail",
            "description": "Multi-region CloudTrail with a hardened (versioned, encrypted, HTTPS-only, CloudTrail-only-write) log bucket.",
            "body": lambda: '''resource "aws_cloudtrail" "this" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.cloudtrail_kms_key_arn
  depends_on                    = [aws_s3_bucket_policy.trail_logs]
  lifecycle { prevent_destroy = true }
  tags = local.tags
}

resource "aws_s3_bucket" "trail_logs" {
  bucket              = var.log_bucket_name
  object_lock_enabled = true
  lifecycle { prevent_destroy = true }
  tags = local.tags
}

# Versioning so log objects cannot be silently overwritten.
resource "aws_s3_bucket_versioning" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  versioning_configuration { status = "Enabled" }
}

# Object Lock (governance) retains logs against deletion/overwrite. Requires the bucket
# to be created with object_lock_enabled; shown here as the hardened target state.
resource "aws_s3_bucket_object_lock_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.cloudtrail_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy: require TLS, and allow ONLY CloudTrail to read ACL / write logs.
resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.trail_logs.arn,
          "${aws_s3_bucket.trail_logs.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_logs.arn}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
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
            "body": lambda: '''resource "aws_kms_key" "this" {
  description             = "${var.name_prefix} CMK with rotation"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}''',
        },
    },
    # ----------------------------- Azure -----------------------------
    "azure": {
        "storage_secure": {
            "title": "Storage Account Secure Transfer & Private Access",
            "description": "Enforce HTTPS-only + disable public blob access.",
            "body": lambda: '''resource "azurerm_storage_account" "this" {
  name                            = var.storage_account_name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = local.tags
}''',
        },
        "entra_mfa": {
            "title": "Entra ID MFA / Conditional Access",
            "description": "Conditional access policy requiring MFA.",
            "body": lambda: '''resource "azuread_conditional_access_policy" "require_mfa" {
  display_name = "${var.name_prefix}-require-mfa"
  state        = "enabled"
  conditions {
    users     { included_users = ["All"] }
    applications { included_applications = ["All"] }
    client_app_types = ["all"]
  }
  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
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
            "description": "Enforce encryption on managed disks and Azure SQL.",
            "body": lambda: '''resource "azurerm_mssql_server_transparent_data_encryption" "this" {
  server_id = var.sql_server_id
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
            "description": "Enable soft-delete + purge protection on Key Vault.",
            "body": lambda: '''resource "azurerm_key_vault" "this" {
  name                       = var.key_vault_name
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
  tags                       = local.tags
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
  labels                      = local.labels
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
            "description": "Firewall rule limiting ingress to a trusted range.",
            "body": lambda: '''resource "google_compute_firewall" "restricted" {
  name    = "${var.name_prefix}-restricted"
  network = var.network
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = [var.allowed_cidr]
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
            "body": lambda: '''resource "google_project_iam_audit_config" "this" {
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
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
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
  ingress_security_rules {
    protocol = "6"
    source   = var.allowed_cidr
  }
}''',
        },
        "volume_db_encryption": {
            "title": "Block Volume / DB Encryption",
            "description": "Encrypt block volumes with a Vault key.",
            "body": lambda: '''resource "oci_core_volume" "encrypted" {
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  kms_key_id          = var.kms_key_id
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
            "description": "Vault master encryption key.",
            "body": lambda: '''resource "oci_kms_key" "this" {
  compartment_id      = var.compartment_ocid
  display_name        = "${var.name_prefix}-key"
  management_endpoint = var.management_endpoint
  key_shape {
    algorithm = "AES"
    length    = 32
  }
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
        "allowed_cidr": ("string", "10.0.0.0/8", "Allowed ingress CIDR (no 0.0.0.0/0)."),
        "allowed_egress_cidr": ("string", "10.0.0.0/8", "Allowed egress CIDR (no 0.0.0.0/0). Widen deliberately only if egress to the internet is required."),
        "log_bucket_name": ("string", None, "S3 bucket name for CloudTrail logs."),
        "cloudtrail_kms_key_arn": ("string", None, "KMS key ARN used to encrypt CloudTrail log files (SSE-KMS)."),
        "log_retention_days": ("number", 365, "CloudWatch log retention in days (CIS requires >= 90)."),
        "log_kms_key_arn": ("string", None, "KMS key ARN used to encrypt the flow-log CloudWatch log group."),
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
    },
    "gcp": {
        "project_id": ("string", None, "GCP project ID."),
        "region": ("string", "us-central1", "GCP region."),
        "bucket_name": ("string", None, "Cloud Storage bucket name."),
        "network": ("string", "default", "VPC network name."),
        "allowed_cidr": ("string", "10.0.0.0/8", "Allowed ingress CIDR (no 0.0.0.0/0)."),
        "key_ring_id": ("string", None, "KMS key ring ID."),
        "permissions": ("list(string)", [], "Custom role permissions."),
    },
    "oci": {
        "region": ("string", "us-ashburn-1", "OCI region."),
        "tenancy_ocid": ("string", None, "OCI tenancy OCID."),
        "compartment_ocid": ("string", None, "Compartment OCID."),
        "bucket_name": ("string", None, "Object Storage bucket name."),
        "namespace": ("string", None, "Object Storage namespace."),
        "vcn_id": ("string", None, "VCN OCID."),
        "allowed_cidr": ("string", "10.0.0.0/8", "Allowed ingress CIDR (no 0.0.0.0/0)."),
        "kms_key_id": ("string", None, "Vault key OCID for volume encryption."),
        "management_endpoint": ("string", None, "Vault management endpoint."),
        "availability_domain": ("string", None, "Availability domain."),
        "policy_statements": ("list(string)", [], "IAM policy statements."),
    },
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
        block.append("}")
        lines.append("\n".join(block))
        lines.append("")
    return "\n".join(lines)


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
    for name, (vtype, default, desc) in PROVIDER_VARIABLES.get(provider, {}).items():
        if name not in selected_variables:
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
    "identity_mfa": {"aws": "iam_mfa", "azure": "entra_mfa", "gcp": "iam_least_privilege",
                     "oci": "iam_policy"},
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


def generate_terraform(customer: str, provider: str, selections: list, output_dir: str,
                       force: bool = False):
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

    # Clean up ONLY files this generator created in a prior run, tracked in a manifest.
    # Terraform loads ALL .tf files in a directory, so stale remediation files from a
    # previous run must be removed — but we must NEVER delete hand-written files an
    # operator may keep in the same directory (e.g. their own providers.tf/variables.tf).
    # Using a manifest of our own prior outputs (instead of deleting by name pattern)
    # guarantees we only remove files we previously wrote.
    os.makedirs(output_dir, exist_ok=True)
    _manifest_name = ".cloud-sec-assessment-manifest.json"
    _manifest_path = os.path.join(output_dir, _manifest_name)
    _output_real = os.path.realpath(output_dir)
    _prior = []
    try:
        with open(_manifest_path, "r", encoding="utf-8") as mf:
            _prior = json.load(mf).get("generated", [])
    except (OSError, ValueError):
        _prior = []
    for existing_tf in _prior:
        # Only basenames are stored; ignore anything that tries to escape via separators.
        if existing_tf != os.path.basename(existing_tf):
            continue
        _target = os.path.join(output_dir, existing_tf)
        if not os.path.exists(_target):
            continue
        # Security: never delete through a symlink, and never delete anything whose real
        # path escapes the output directory.
        if os.path.islink(_target):
            print(f"  [WARN] Skipping cleanup of symlinked entry: {_target}", file=sys.stderr)
            continue
        if os.path.realpath(_target) != os.path.join(_output_real, existing_tf):
            print(f"  [WARN] Skipping cleanup outside output root: {_target}", file=sys.stderr)
            continue
        os.remove(_target)

    # Refuse to overwrite a hand-written shared file: one that exists on disk but was
    # NOT recorded as generated by a prior run of this tool. O_TRUNC writes below would
    # otherwise silently destroy an operator's own providers.tf/variables.tf/locals.tf/
    # terraform.tfvars.example. --force bypasses this.
    _shared_files = ["providers.tf", "variables.tf", "locals.tf", "terraform.tfvars.example"]
    if not force:
        _conflicts = [
            name for name in _shared_files
            if os.path.exists(os.path.join(output_dir, name)) and name not in _prior
        ]
        if _conflicts:
            print(f"  [ERROR] Refusing to overwrite hand-written file(s) in {output_dir}: "
                  f"{', '.join(_conflicts)}.", file=sys.stderr)
            print("          These are not recorded as generated by this tool. Move/rename "
                  "them, choose a different --output-dir, or re-run with --force to overwrite.",
                  file=sys.stderr)
            return []

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
        # Sanitize customer name for use in filenames (prevent path traversal)
        safe_name = re.sub(r'[^\w\-]', '_', customer)
        filename = f"{safe_name}_{provider}_{sel}.tf"
        with safe_io.open_write_nofollow(os.path.join(output_dir, filename), root=output_dir) as fh:
            fh.write(content)
        generated.append(filename)
        print(f"  ✓ {filename}")

    # Record exactly what we generated so the NEXT run's cleanup removes only our own
    # files, never hand-written Terraform the operator keeps in this directory.
    with safe_io.open_write_nofollow(_manifest_path, root=output_dir) as mf:
        json.dump({"generated": generated}, mf, indent=2)

    return generated


def main():
    parser = argparse.ArgumentParser(description="Generate Terraform remediation modules (multi-cloud)")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("selections", help="Comma-separated remediation IDs")
    parser.add_argument("output_dir", help="Output directory for .tf files")
    parser.add_argument("--provider", default="", help="Cloud provider (aws|azure|gcp|oci). Defaults to first in analysis.")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite hand-written shared files (providers.tf, variables.tf, "
                             "locals.tf, terraform.tfvars.example) that this tool did not generate. "
                             "Off by default to protect operator-authored Terraform.")
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
                                   force=args.force)
    if not generated:
        print(f"\n❌ No Terraform modules generated — check errors above.", file=sys.stderr)
        sys.exit(1)
    print(f"\n✅ Generated {len(generated)} Terraform module(s) → {args.output_dir}")
    print("⚠️  Review + `terraform plan` before `apply`.")


if __name__ == "__main__":
    main()
