#!/usr/bin/env python3
"""
providers.py — Canonical multi-cloud provider metadata shared across the scripts.

Single source of truth for provider labels, scope terminology, and provider CLIs.
Import from here instead of redefining these constants per file, so adding a new
provider or fixing a label is a one-place change.

(The Node script generate_pptx.js keeps its own copy of PROVIDER_LABEL because it
cannot import a Python module — keep it consistent with PROVIDER_LABELS below.)
"""

# Human-friendly provider labels.
PROVIDER_LABELS = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "oci": "OCI",
    "kubernetes": "Kubernetes",
    "unknown": "Unknown",
}

# Per-provider name for the top-level isolation boundary ("scope").
PROVIDER_SCOPE_TERM = {
    "aws": "account",
    "azure": "subscription",
    "gcp": "project",
    "oci": "tenancy",
    "kubernetes": "cluster",
    "unknown": "scope",
}

# Provider CLI tool names (for prerequisites / re-assessment docs).
PROVIDER_CLI = {
    "aws": "aws",
    "azure": "az",
    "gcp": "gcloud",
    "oci": "oci",
}
