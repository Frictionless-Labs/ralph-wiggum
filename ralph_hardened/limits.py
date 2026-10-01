from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


MAX_NEW_ENTRIES = 2_048
MAX_FILE_GROWTH_BYTES = 64 * 1024 * 1024
MAX_TOTAL_GROWTH_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class WorkspaceBaseline:
    entries: frozenset[str]
    regular_sizes: Mapping[str, int]


def capture_workspace_baseline(root: Path) -> WorkspaceBaseline:
    entries: set[str] = set()
    regular_sizes: dict[str, int] = {}
    stack = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        with os.scandir(directory) as children:
            for child in children:
                relative = f"{prefix}/{child.name}" if prefix else child.name
                if relative == ".git":
                    continue
                entries.add(relative)
                metadata = child.stat(follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode):
                    regular_sizes[relative] = metadata.st_size
                elif stat.S_ISDIR(metadata.st_mode):
                    stack.append((Path(child.path), relative))
    return WorkspaceBaseline(frozenset(entries), regular_sizes)


def workspace_limit_violation(root: Path, baseline: WorkspaceBaseline) -> str | None:
    new_entries = 0
    total_growth = 0
    stack = [(root, "")]
    try:
        while stack:
            directory, prefix = stack.pop()
            with os.scandir(directory) as children:
                for child in children:
                    relative = f"{prefix}/{child.name}" if prefix else child.name
                    if relative == ".git":
                        continue
                    if relative not in baseline.entries:
                        new_entries += 1
                        if new_entries > MAX_NEW_ENTRIES:
                            return f"workspace entry limit exceeded ({MAX_NEW_ENTRIES})"
                    metadata = child.stat(follow_symlinks=False)
                    if stat.S_ISREG(metadata.st_mode):
                        growth = max(0, metadata.st_size - baseline.regular_sizes.get(relative, 0))
                        if growth > MAX_FILE_GROWTH_BYTES:
                            return (
                                f"file growth limit exceeded ({MAX_FILE_GROWTH_BYTES} bytes): "
                                f"{relative}"
                            )
                        total_growth += growth
                        if total_growth > MAX_TOTAL_GROWTH_BYTES:
                            return (
                                "aggregate workspace growth limit exceeded "
                                f"({MAX_TOTAL_GROWTH_BYTES} bytes)"
                            )
                    elif stat.S_ISDIR(metadata.st_mode):
                        stack.append((Path(child.path), relative))
    except OSError as exc:
        return f"workspace quota scan failed: {type(exc).__name__}"
    return None
