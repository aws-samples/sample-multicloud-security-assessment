#!/usr/bin/env python3
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

# Version-pinned required_providers per cloud. Pinning avoids surprise breakage when
# a new major provider release changes/removes arguments (e.g. azurerm v4 removed
# enable_https_traffic_only). The azuread provider is added dynamically when an Azure
# identity remediation is selected (see generate_terraform).
REQUIRED_PROVIDERS = {
    "aws":   '\n    aws = {\n      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }',
    "azure": '\n    azurerm = {\n      source  = "hashicorp/azurerm"\n      version = "~> 3.0"\n    }',
    "gcp":   '\n    google = {\n      source  = "hashicorp/google"\n      version = "~> 5.0"\n    }',
    "oci":   '\n    oci = {\n      source  = "oracle/oci"\n      version = "~> 5.0"\n    }',
}

# Azure identity remediation additionally needs the separate azuread provider.
AZUREAD_REQUIRED = '\n    azuread = {\n      source  = "hashicorp/azuread"\n      version = "~> 2.0"\n    }'
AZURE_IDENTITY_KEYS = {"entra_mfa"}


# Provider-appropriate remediation catalog. Each entry: title, description, and a
# Terraform body builder () -> HCL string for the resource(s).
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
            "body": lambda: '''resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  key_arn = var.kms_key_arn
}''',
        },
        "audit_logging": {
            "title": "Multi-Region CloudTrail",
            "description": "Multi-region CloudTrail with log-file validation.",
            "body": lambda: '''resource "aws_cloudtrail" "this" {
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
            "body": lambda: '''resource "aws_flow_log" "this" {
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
            "description": "Network security group denying broad inbound access.",
            "body": lambda: '''resource "azurerm_network_security_group" "restricted" {
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


# All variables that resource bodies may reference, per provider. Declared ONCE in
# a shared variables.tf so multiple selected modules never redeclare them, and no
# resource references an undeclared variable. Format: name -> (hcl_type, default_or_None, description)
PROVIDER_VARIABLES = {
    "aws": {
        "region": ("string", "us-east-1", "Target AWS region."),
        "bucket_name": ("string", "", "Target S3 bucket name (for encryption config)."),
        "kms_key_arn": ("string", "", "KMS key ARN for encryption at rest."),
        "vpc_id": ("string", "", "VPC ID for security group / flow logs."),
        "allowed_cidr": ("string", "10.0.0.0/8", "Allowed ingress CIDR (no 0.0.0.0/0)."),
        "log_bucket_name": ("string", "", "S3 bucket name for CloudTrail logs."),
        "flow_log_role_arn": ("string", "", "IAM role ARN for VPC flow logs."),
    },
    "azure": {
        "location": ("string", "eastus", "Azure location."),
        "resource_group_name": ("string", "", "Azure resource group name."),
        "storage_account_name": ("string", "", "Storage account name."),
        "key_vault_name": ("string", "", "Key Vault name."),
        "tenant_id": ("string", "", "Entra ID tenant ID."),
        "subscription_id": ("string", "", "Azure subscription resource ID."),
        "sql_server_id": ("string", "", "Azure SQL server resource ID."),
        "log_analytics_workspace_id": ("string", "", "Log Analytics workspace ID."),
    },
    "gcp": {
        "project_id": ("string", None, "GCP project ID."),
        "region": ("string", "us-central1", "GCP region."),
        "bucket_name": ("string", "", "Cloud Storage bucket name."),
        "network": ("string", "default", "VPC network name."),
        "allowed_cidr": ("string", "10.0.0.0/8", "Allowed ingress CIDR (no 0.0.0.0/0)."),
        "key_ring_id": ("string", "", "KMS key ring ID."),
        "permissions": ("list(string)", [], "Custom role permissions."),
    },
    "oci": {
        "region": ("string", "us-ashburn-1", "OCI region."),
        "tenancy_ocid": ("string", None, "OCI tenancy OCID."),
        "compartment_ocid": ("string", "", "Compartment OCID."),
        "bucket_name": ("string", "", "Object Storage bucket name."),
        "namespace": ("string", "", "Object Storage namespace."),
        "vcn_id": ("string", "", "VCN OCID."),
        "allowed_cidr": ("string", "10.0.0.0/8", "Allowed ingress CIDR (no 0.0.0.0/0)."),
        "kms_key_id": ("string", "", "Vault key OCID for volume encryption."),
        "management_endpoint": ("string", "", "Vault management endpoint."),
        "availability_domain": ("string", "", "Availability domain."),
        "policy_statements": ("list(string)", [], "IAM policy statements."),
    },
}


def _hcl_default(value):
    """Render a Python default as an HCL literal for a variable default."""
    if value is None:
        return None  # required variable, no default
    if isinstance(value, list):
        return "[]" if not value else "[" + ", ".join(f'"{v}"' for v in value) + "]"
    return f'"{value}"'


def _render_variables_tf(provider: str, customer: str) -> str:
    """Build the shared variables.tf declaring every variable the modules may use."""
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
        block = [f'variable "{name}" {{', f'  type        = {vtype}', f'  description = "{desc}"']
        d = _hcl_default(default)
        if d is not None:
            block.append(f"  default     = {d}")
        block.append("}")
        lines.append("\n".join(block))
        lines.append("")
    return "\n".join(lines)


def _render_tfvars_example(provider: str, customer: str) -> str:
    """Build a single terraform.tfvars.example covering all variables."""
    lines = [
        "# Example variables — copy to terraform.tfvars and fill in real values.",
        "# Variables with a sensible default may be omitted.",
        "",
        'environment = "production"',
        f'name_prefix = "{customer.lower().replace(" ", "-")}"',
    ]
    for name, (vtype, default, desc) in PROVIDER_VARIABLES.get(provider, {}).items():
        if vtype.startswith("list"):
            example = "[]"
        else:
            example = f'"{default}"' if default else '"REPLACE_ME"'
        marker = "" if default not in (None, "") else "   # REQUIRED"
        lines.append(f'{name} = {example}{marker}')
    return "\n".join(lines) + "\n"


def _render_locals_tf(customer: str, provider: str) -> str:
    """Shared locals.tf with tags/labels appropriate to the provider."""
    key = "labels" if provider == "gcp" else "tags"
    return (
        "# Shared tags/labels applied by the remediation modules.\n"
        f'locals {{\n  {key} = {{\n'
        f'    Environment = var.environment\n'
        f'    ManagedBy   = "Terraform"\n'
        f'    Purpose     = "SecurityRemediation"\n'
        f'    Customer    = "{customer}"\n'
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
    "flow_logs": {"aws": "flow_logs", "azure": "activity_log", "gcp": "audit_logs",
                  "oci": "audit_logging"},
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


def generate_terraform(customer: str, provider: str, selections: list, output_dir: str):
    """Generate provider-aware Terraform for a directory.

    Emits SHARED files (providers.tf, variables.tf, locals.tf, terraform.tfvars.example)
    exactly once, and one resource-only .tf per selected remediation. This avoids
    duplicate variable/locals declarations and undeclared-variable errors when
    Terraform loads every .tf in the directory together.
    """
    provider = provider if provider in REMEDIATION_CATALOG else "aws"
    catalog = REMEDIATION_CATALOG[provider]
    tf_meta = PROVIDER_TF[provider]
    os.makedirs(output_dir, exist_ok=True)

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
    with open(os.path.join(output_dir, "providers.tf"), "w", encoding="utf-8") as fh:
        fh.write(f"{DISCLAIMER}\n"
                 f"# Shared provider + terraform settings for the remediation modules.\n\n"
                 'terraform {\n  required_version = ">= 1.5"\n\n'
                 '  required_providers {'
                 f"{req}\n"
                 '  }\n}\n\n'
                 f"{provider_blocks}\n")
    with open(os.path.join(output_dir, "variables.tf"), "w", encoding="utf-8") as fh:
        fh.write(_render_variables_tf(provider, customer) + "\n")
    with open(os.path.join(output_dir, "locals.tf"), "w", encoding="utf-8") as fh:
        fh.write(_render_locals_tf(customer, provider))
    with open(os.path.join(output_dir, "terraform.tfvars.example"), "w", encoding="utf-8") as fh:
        fh.write(_render_tfvars_example(provider, customer))

    # --- One resource-only module file per selection ---
    generated = ["providers.tf", "variables.tf", "locals.tf", "terraform.tfvars.example"]
    for sel in valid:
        entry = catalog[sel]
        content = (
            f"# {customer} — {entry['title']}\n"
            f"# {entry['description']}\n"
            f"# Variables are declared in variables.tf; providers/locals are shared.\n\n"
            f"{entry['body']()}\n"
        )
        filename = f"{customer.replace(' ', '_')}_{provider}_{sel}.tf"
        with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as fh:
            fh.write(content)
        generated.append(filename)
        print(f"  ✓ {filename}")

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
