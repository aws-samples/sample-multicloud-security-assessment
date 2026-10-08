#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
safe_io.py — Symlink-safe output writing for generated deliverables.

The assessment tool writes customer-facing artifacts (analysis.json, dashboard
HTML, README, PDF, Terraform) into an output directory. These helpers:

  * use O_NOFOLLOW so a symlink planted at the FINAL output path makes the open
    fail instead of redirecting the write (symlink-redirect defense), and
  * when a ``root`` is supplied, refuse to write when the resolved parent directory
    is not under the resolved root (catches ``..`` traversal and gross escapes).

Scope note: benign symlinks higher in the path (e.g. macOS ``/tmp`` ->
``/private/tmp``) are tolerated because both sides are resolved before comparison.
Defending against a local attacker who can swap the output directory itself for a
symlink is out of scope — that requires write access to the output parent, which is
equivalent to being able to write the files directly.
"""

import os


class UnsafeOutputPathError(OSError):
    """Raised when an output path is (or traverses) a symlink or escapes its root."""


def assert_within_root(path: str, root: str) -> None:
    """Raise UnsafeOutputPathError unless the resolved path stays under resolved root.

    Guards against ``..`` traversal and symlinked parent directories that would place
    the real target outside the intended output root.
    """
    root_real = os.path.realpath(root)
    path_real = os.path.realpath(path)
    # Normalize to directory-boundary comparison so '/a/rootX' isn't treated as under '/a/root'.
    if path_real != root_real and not path_real.startswith(root_real + os.sep):
        raise UnsafeOutputPathError(
            f"refusing to write outside output root: {path_real} not under {root_real}")


def open_write_nofollow(path: str, binary: bool = False, root: str = None):
    """Open ``path`` for writing, refusing to follow a symlink at the final component
    AND refusing a parent directory that resolves outside ``root`` (when given).

    O_NOFOLLOW protects the final path component: a symlink planted at ``path`` makes
    the open fail instead of redirecting the write. Passing ``root`` additionally
    defends against a symlinked PARENT directory — the resolved parent must stay under
    the resolved output root, so a swapped-in parent symlink can't redirect the write
    (or a later Terraform cleanup) outside the intended tree.

    Parent directories are created if missing.
    """
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    if root is not None:
        # Defend against a symlink redirecting the write outside the intended tree. We
        # compare the FULLY RESOLVED parent against the FULLY RESOLVED root: both sides
        # canonicalize benign symlinks (e.g. macOS /tmp -> /private/tmp), so a legitimate
        # output dir is accepted, while a parent that resolves somewhere NOT under the
        # resolved root (an attacker-swapped symlink pointing elsewhere) is rejected.
        parent_real = os.path.realpath(parent)
        root_real = os.path.realpath(root)
        if parent_real != root_real and not parent_real.startswith(root_real + os.sep):
            raise UnsafeOutputPathError(
                f"refusing to write outside output root: parent {parent_real} "
                f"not under {root_real}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as e:
        raise UnsafeOutputPathError(
            f"refusing to write output at {path}: {e} "
            "(a symlink or unwritable path may be present)") from e
    mode = "wb" if binary else "w"
    kwargs = {} if binary else {"encoding": "utf-8"}
    return os.fdopen(fd, mode, **kwargs)


def write_text_safe(path: str, text: str, root: str = None) -> None:
    """Write ``text`` to ``path`` with no-follow + optional containment under ``root``."""
    with open_write_nofollow(path, root=root) as fh:
        fh.write(text)
