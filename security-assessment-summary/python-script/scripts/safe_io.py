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
    is not under the resolved root (catches ``..`` traversal and a symlinked
    SUBFOLDER such as ``reports/`` that points outside the output folder).

``root`` only protects anything if it is a real ANCESTOR of the output file — the
output folder the caller means to contain the write. Passing the file's own parent
makes the check a no-op for symlinked subfolders; use :func:`containment_root` to
derive a meaningful root.

Scope note: benign symlinks higher in the path (e.g. macOS ``/tmp`` ->
``/private/tmp``) are tolerated because both sides are resolved before comparison.
Defending against a local attacker who can swap the output directory itself for a
symlink is out of scope — that requires write access to the output parent, which is
equivalent to being able to write the files directly.
"""

import os
import stat


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


def containment_root(output_path: str, anchor_dir: str):
    """Return ``anchor_dir`` if ``output_path`` is LEXICALLY inside it, else None.

    Used by writers whose layout implies an output folder (e.g. the folder holding
    analysis.json, with the dashboard under ``reports/``). If the operator deliberately
    writes elsewhere, there is no implied root and containment is not enforced.
    """
    anchor = os.path.abspath(anchor_dir or ".")
    target = os.path.abspath(output_path)
    if target == anchor or target.startswith(anchor + os.sep):
        return anchor
    return None


def ensure_dir_within(directory: str, root: str, mode: int = 0o777) -> None:
    """Create ``directory`` (and parents) under ``root`` without following symlinks.

    Every existing component between ``root`` and ``directory`` is checked (no symlinks,
    must be a directory) BEFORE anything is created, so a planted symlinked subfolder
    can't make us create directories outside the root.
    """
    parent = os.path.abspath(directory)
    root_abs = os.path.abspath(root)
    if parent != root_abs and not parent.startswith(root_abs + os.sep):
        raise UnsafeOutputPathError(
            f"refusing to write outside output root: parent {parent} not under {root_abs}")
    if not os.path.lexists(root_abs):
        os.makedirs(root_abs, mode)  # the root itself is operator-chosen; create it if missing
    current = root_abs
    rel = os.path.relpath(parent, root_abs)
    for part in ([] if rel == "." else rel.split(os.sep)):
        current = os.path.join(current, part)
        if os.path.lexists(current):
            if os.path.islink(current) or not os.path.isdir(current):
                raise UnsafeOutputPathError(
                    f"refusing to write via symlinked/non-directory component: {current}")
        else:
            os.mkdir(current, mode)
    # Defense in depth: the fully resolved parent must stay under the resolved root
    # (both sides canonicalize benign symlinks such as macOS /tmp -> /private/tmp).
    parent_real = os.path.realpath(parent)
    root_real = os.path.realpath(root_abs)
    if parent_real != root_real and not parent_real.startswith(root_real + os.sep):
        raise UnsafeOutputPathError(
            f"refusing to write outside output root: parent {parent_real} "
            f"not under {root_real}")


def open_write_nofollow(path: str, binary: bool = False, root: str = None):
    """Open ``path`` for writing, refusing to follow a symlink at the final component
    AND refusing a parent directory that resolves outside ``root`` (when given).

    O_NOFOLLOW protects the final path component: a symlink planted at ``path`` makes
    the open fail instead of redirecting the write. Passing ``root`` (an ancestor
    folder of ``path``) additionally requires the resolved parent to stay under the
    resolved root, so a symlinked subfolder between ``root`` and the file can't
    redirect the write outside the intended tree. If ``root`` is the file's own parent,
    only ``..`` escapes are caught.

    Parent directories are created if missing — when ``root`` is given, via
    :func:`ensure_dir_within`, so nothing is created outside the root.

    The file is opened WITHOUT O_TRUNC and only truncated after ``fstat`` confirms it
    is a regular file with a single link owned by this user, so a planted HARD link
    can't make us truncate another file (O_NOFOLLOW does not cover hard links).
    """
    parent = os.path.abspath(os.path.dirname(path) or ".")
    if root is not None:
        ensure_dir_within(parent, root)
    else:
        os.makedirs(parent, exist_ok=True)
    # O_NONBLOCK: opening a planted FIFO for writing would otherwise block forever
    # waiting for a reader, before the regular-file check below ever runs.
    flags = (os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as e:
        raise UnsafeOutputPathError(
            f"refusing to write output at {path}: {e} "
            "(a symlink or unwritable path may be present)") from e
    try:
        st = os.fstat(fd)
        euid = os.geteuid() if hasattr(os, "geteuid") else st.st_uid
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != euid:
            raise UnsafeOutputPathError(
                f"refusing to write output at {path}: not a single-link regular file "
                "owned by this user (possible hard-link redirect)")
        if hasattr(os, "set_blocking"):
            os.set_blocking(fd, True)
        os.ftruncate(fd, 0)
    except BaseException:
        os.close(fd)
        raise
    mode = "wb" if binary else "w"
    kwargs = {} if binary else {"encoding": "utf-8"}
    return os.fdopen(fd, mode, **kwargs)


def write_text_safe(path: str, text: str, root: str = None) -> None:
    """Write ``text`` to ``path`` with no-follow + optional containment under ``root``."""
    with open_write_nofollow(path, root=root) as fh:
        fh.write(text)
