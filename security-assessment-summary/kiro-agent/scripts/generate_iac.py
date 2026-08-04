#!/usr/bin/env python3
"""
generate_iac.py — Generate Terraform remediation modules (multi-cloud, provider-aware).

Terraform is the single IaC language for all clouds. The correct provider block
(aws / azurerm / google / oci) is emitted based on the detected provider.

Usage:
    python3 generate_iac.py <analysis_json> <selections> <output_dir> [--provider <aws|azure|gcp|oci>]

    selections: comma-separated remediation IDs. Provider-appropriate options:
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
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------

PROVIDER_TF = {
    "aws": {
        "provider_block": 'provider "aws" {\n  region = var.region\n}',
        "region_var": 'variable "region" {\n  type        = string\n  description = "Target cloud region."\n  default     = "us-east-1"\n}',
    },
    "azure": {
        "provider_block": 'provider "azurerm" {\n  features {}\n}',
        "region_var": 'variable "location" {\n  type        = string\n  description = "Azure location."\n  default     = "eastus"\n}',
    },
    "gcp": {
        "provider_block": 'provider "google" {\n  project = var.project_id\n  region  = var.region\n}',
        "region_var": 'variable "project_id" {\n  type        = string\n  description = "GCP project ID."\n}\n\nvariable "region" {\n  type        = string\n  default     = "us-central1"\n}',
    },
    "oci": {
        "provider_block": 'provider "oci" {\n  tenancy_ocid = var.tenancy_ocid\n  region       = var.region\n}',
        "region_var": 'variable "tenancy_ocid" {\n  type        = string\n  description = "OCI tenancy OCID."\n}\n\nvariable "region" {\n  type        = string\n  default     = "us-ashburn-1"\n}',
    },
}

# Provider-appropriate remediation catalog. Each entry: title, description, and a
# Terraform body builder (customer, environment) -> HCL string for the resource(s).
REMEDIATION_CATALOG = {
    # ----------------------------- AWS -----------------------------
    "aws": {
        "s3_public_access": {
            "title": "S3 Block Public Access & Default Encryption",
            "description": "Account-level S3 public access block + default SSE-KMS.",
            "body": lambda c, e: '''resource "aws_s3_account_public_access_block" "this" {
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
}''',
        },
        "iam_mfa": {
            "title": "IAM MFA Enforcement",
            "description": "Managed policy denying actions when MFA is absent.",
            "body": lambda c, e: '''resource "aws_iam_policy" "enforce_mfa" {
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
            "body": lambda c, e: '''resource "aws_security_group" "restricted" {
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
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}''',
        },
        "encryption_at_rest": {
            "title": "EBS/RDS Encryption at Rest",
            "description": "Enable account-default EBS encryption.",
            "body": lambda c, e: '''resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  key_arn = var.kms_key_arn
}''',
        },
        "audit_logging": {
            "title": "Multi-Region CloudTrail",
            "description": "Multi-region CloudTrail with log-file validation.",
            "body": lambda c, e: '''resource "aws_cloudtrail" "this" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = var.log_bucket_name
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  lifecycle { prevent_destroy = true }
  tags = local.tags
}''',
        },
        "flow_logs": {
            "title": "VPC Flow Logs",
            "description": "Enable VPC Flow Logs to CloudWatch Logs.",
            "body": lambda c, e: '''resource "aws_flow_log" "this" {
  vpc_id          = var.vpc_id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = var.flow_log_role_arn
  tags            = local.tags
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/vpc/flowlogs/${var.vpc_id}"
  retention_in_days = 14
}''',
        },
        "kms_rotation": {
            "title": "KMS Key Rotation",
            "description": "Customer-managed KMS key with annual rotation.",
            "body": lambda c, e: '''resource "aws_kms_key" "this" {
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
            "body": lambda c, e: '''resource "azurerm_storage_account" "this" {
  name                            = var.storage_account_name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = local.tags
}''',
        },
        "entra_mfa": {
            "title": "Entra ID MFA / Conditional Access",
            "description": "Conditional access policy requiring MFA.",
            "body": lambda c, e: '''resource "azuread_conditional_access_policy" "require_mfa" {
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
            "description": "Network security group denying broad inbound access.",
            "body": lambda c, e: '''resource "azurerm_network_security_group" "restricted" {
  name                = "${var.name_prefix}-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name
  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  tags = local.tags
}''',
        },
        "disk_sql_encryption": {
            "title": "Disk / SQL Encryption",
            "description": "Enforce encryption on managed disks and Azure SQL.",
            "body": lambda c, e: '''resource "azurerm_mssql_server_transparent_data_encryption" "this" {
  server_id = var.sql_server_id
}''',
        },
        "activity_log": {
            "title": "Activity Log + Diagnostic Settings",
            "description": "Route activity logs to a Log Analytics workspace.",
            "body": lambda c, e: '''resource "azurerm_monitor_diagnostic_setting" "activity" {
  name                       = "${var.name_prefix}-activity"
  target_resource_id         = var.subscription_id
  log_analytics_workspace_id = var.log_analytics_workspace_id
  enabled_log { category_group = "audit" }
}''',
        },
        "keyvault_protection": {
            "title": "Key Vault Soft-Delete & Purge Protection",
            "description": "Enable soft-delete + purge protection on Key Vault.",
            "body": lambda c, e: '''resource "azurerm_key_vault" "this" {
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
            "body": lambda c, e: '''resource "google_storage_bucket" "this" {
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
            "body": lambda c, e: '''resource "google_project_iam_custom_role" "least_priv" {
  role_id     = "${replace(var.name_prefix, "-", "_")}_least_priv"
  title       = "${var.name_prefix} least privilege"
  permissions = var.permissions
}''',
        },
        "firewall_restrict": {
            "title": "Firewall Rule Restriction",
            "description": "Firewall rule limiting ingress to a trusted range.",
            "body": lambda c, e: '''resource "google_compute_firewall" "restricted" {
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
            "body": lambda c, e: '''resource "google_kms_crypto_key" "this" {
  name            = "${var.name_prefix}-cmek"
  key_ring        = var.key_ring_id
  rotation_period = "7776000s"
  lifecycle { prevent_destroy = true }
}''',
        },
        "audit_logs": {
            "title": "Cloud Audit Logs",
            "description": "Enable data-access audit logging for all services.",
            "body": lambda c, e: '''resource "google_project_iam_audit_config" "this" {
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
            "body": lambda c, e: '''resource "google_kms_crypto_key" "rotating" {
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
            "body": lambda c, e: '''resource "oci_objectstorage_bucket" "this" {
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
            "body": lambda c, e: '''resource "oci_identity_policy" "least_priv" {
  compartment_id = var.tenancy_ocid
  name           = "${var.name_prefix}-least-priv"
  description    = "Least privilege policy"
  statements     = var.policy_statements
}''',
        },
        "security_lists": {
            "title": "Security List Restriction",
            "description": "Restrict ingress in the VCN security list.",
            "body": lambda c, e: '''resource "oci_core_security_list" "restricted" {
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
            "body": lambda c, e: '''resource "oci_core_volume" "encrypted" {
  compartment_id      = var.compartment_ocid
  availability_domain = var.availability_domain
  kms_key_id          = var.kms_key_id
}''',
        },
        "audit_logging": {
            "title": "Audit Logging",
            "description": "Ensure the tenancy audit retention is configured.",
            "body": lambda c, e: '''resource "oci_audit_configuration" "this" {
  compartment_id                  = var.tenancy_ocid
  retention_period_days           = 365
}''',
        },
        "vault_rotation": {
            "title": "Vault Key Rotation",
            "description": "Vault master encryption key.",
            "body": lambda c, e: '''resource "oci_kms_key" "this" {
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


def _tags_locals(customer: str, provider: str) -> str:
    """Return a locals block with tags/labels appropriate to the provider."""
    key = "labels" if provider == "gcp" else "tags"
    return (
        f'locals {{\n  {key} = {{\n'
        f'    Environment = var.environment\n'
        f'    ManagedBy   = "Terraform"\n'
        f'    Purpose     = "SecurityRemediation"\n'
        f'    Customer    = "{customer}"\n'
        f'  }}\n}}'
    )


def generate_terraform(customer: str, provider: str, selections: list, output_dir: str):
    """Generate provider-aware Terraform modules (one .tf per selection)."""
    provider = provider if provider in REMEDIATION_CATALOG else "aws"
    catalog = REMEDIATION_CATALOG[provider]
    tf_meta = PROVIDER_TF[provider]
    generated = []

    for sel in selections:
        entry = catalog.get(sel)
        if not entry:
            print(f"  [WARN] No {provider} Terraform template for: {sel}", file=sys.stderr)
            continue

        header = (
            f"{DISCLAIMER}\n"
            f"# {customer} — {entry['title']}\n"
            f"# {entry['description']}\n\n"
            'terraform {\n  required_version = ">= 1.5"\n}\n\n'
            f"{tf_meta['provider_block']}\n\n"
            f"{tf_meta['region_var']}\n\n"
            'variable "environment" {\n  type    = string\n  default = "production"\n}\n\n'
            'variable "name_prefix" {\n  type    = string\n  default = "'
            f"{customer.lower().replace(' ', '-')}"
            '"\n}\n\n'
            f"{_tags_locals(customer, provider)}\n\n"
        )
        body = entry["body"](customer, "production")
        content = header + body + "\n"

        filename = f"{customer.replace(' ', '_')}_{provider}_{sel}.tf"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(content)
        generated.append(filename)
        print(f"  ✓ {filename}")

        # Example tfvars
        tfvars = os.path.join(output_dir, f"{customer.replace(' ', '_')}_{provider}_{sel}.tfvars.example")
        with open(tfvars, "w", encoding="utf-8") as fh:
            fh.write(f'# Example variables for {entry["title"]}\nenvironment = "production"\n')

    return generated


def main():
    parser = argparse.ArgumentParser(description="Generate Terraform remediation modules (multi-cloud)")
    parser.add_argument("analysis_json", help="Path to analysis.json")
    parser.add_argument("selections", help="Comma-separated remediation IDs")
    parser.add_argument("output_dir", help="Output directory for .tf files")
    parser.add_argument("--provider", default="", help="Cloud provider (aws|azure|gcp|oci). Defaults to first in analysis.")
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
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Generating Terraform ({provider}) for: {', '.join(selections)}")
    generated = generate_terraform(customer, provider, selections, args.output_dir)
    print(f"\n✅ Generated {len(generated)} Terraform module(s) → {args.output_dir}")
    print("⚠️  Review + `terraform plan` before `apply`.")


if __name__ == "__main__":
    main()
