"""
Security Auditor with Async and Parallel Processing.

Optimized security scanning with:
- Async file system operations
- ProcessPoolExecutor for parallel regex scanning
- Streaming file reads (memory efficient)
- Pre-compiled regex patterns
- Progress tracking for large scans
"""

import asyncio
import os
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
import structlog

log = structlog.get_logger()

# Pre-compiled regex patterns for performance
SECURITY_PATTERNS = {
    "api_key": re.compile(
        r"(?i)(api_key|apikey|secret_key|access_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"
    ),
    "password": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{1,}['\"]"),
    "db_connection": re.compile(r"(?i)(postgres|mysql)://.*:.*@"),
    "private_key": re.compile(r"-----BEGIN PRIVATE KEY-----"),
}

# Default ignore patterns
IGNORE_DIRS = {".git", "__pycache__", "venv", "node_modules", ".trae", "node_modules"}
IGNORE_FILES = {"package-lock.json", "yarn.lock"}


@dataclass
class ScanProgress:
    """Progress tracking for security scans."""

    files_scanned: int = 0
    files_total: int = 0
    findings_found: int = 0
    current_file: Optional[str] = None
    percent_complete: float = 0.0

    def update(self, file_path: str, finding_count: int = 0):
        self.files_scanned += 1
        self.current_file = file_path
        if self.files_total > 0:
            self.percent_complete = (self.files_scanned / self.files_total) * 100
        self.findings_found += finding_count


@dataclass
class SecurityFinding:
    """A security finding from the scan."""

    file: str
    rule: str
    line: int
    match_snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "rule": self.rule,
            "line": self.line,
            "match_snippet": self.match_snippet,
        }


def _count_files_to_scan(root_path: str, ignore_dirs: set, ignore_files: set) -> int:
    """Synchronously count files to be scanned (for progress tracking)."""
    count = 0
    for root, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            if file not in ignore_files:
                count += 1
    return count


async def _scan_file_async(
    file_path: str,
    patterns: Dict[str, re.Pattern],
    progress_callback: Optional[Callable[[str, int], None]] = None,
) -> List[SecurityFinding]:
    """
    Scan a single file for security issues.

    Uses streaming read to be memory efficient on large files.
    """
    findings = []

    try:
        file_size = os.path.getsize(file_path)
        # For small files, read all at once
        if file_size < 1024 * 1024:  # 1MB threshold
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for rule_name, pattern in patterns.items():
                    for match in pattern.finditer(content):
                        line_num = content[: match.start()].count("\n") + 1
                        findings.append(
                            SecurityFinding(
                                file=file_path,
                                rule=rule_name,
                                line=line_num,
                                match_snippet=match.group(0)[:50] + "...",
                            )
                        )
        else:
            # For large files, stream line by line
            line_num = 0
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_num += 1
                    for rule_name, pattern in patterns.items():
                        if pattern.search(line):
                            findings.append(
                                SecurityFinding(
                                    file=file_path,
                                    rule=rule_name,
                                    line=line_num,
                                    match_snippet=line.strip()[:50],
                                )
                            )
    except Exception as e:
        log.warning("security.audit_file_error", file=file_path, error=str(e))

    if progress_callback:
        progress_callback(file_path, len(findings))

    return findings


def _scan_file_worker(args: tuple) -> List[SecurityFinding]:
    """
    Worker function for ProcessPoolExecutor.

    Separates CPU-bound regex work from async event loop.
    """
    (file_path,) = args
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for rule_name, pattern in SECURITY_PATTERNS.items():
                for match in pattern.finditer(content):
                    line_num = content[: match.start()].count("\n") + 1
                    findings.append(
                        SecurityFinding(
                            file=file_path,
                            rule=rule_name,
                            line=line_num,
                            match_snippet=match.group(0)[:50] + "...",
                        )
                    )
    except Exception:
        pass  # Silently skip files that can't be read

    return findings


async def _collect_files_async(
    root_path: str,
    ignore_dirs: set,
    ignore_files: set,
) -> List[str]:
    """
    Asynchronously collect all files to scan.

    Uses scandir for better performance than os.walk.
    """
    files = []

    async def scan_directory(path: Path):
        nonlocal files
        try:
            async for entry in _async_scandir(path):
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in ignore_dirs:
                        await scan_directory(entry.path)
                elif entry.is_file():
                    if entry.name not in ignore_files:
                        files.append(entry.path)
        except PermissionError:
            pass  # Skip directories we can't access

    await scan_directory(Path(root_path))
    return files


async def _async_scandir(path: Path):
    """Async wrapper for os.scandir."""
    for entry in os.scandir(path):
        yield entry


class SecurityAuditor:
    """
    Optimized security auditor with async and parallel processing.

    Features:
    - Async file system operations
    - ProcessPoolExecutor for parallel regex scanning
    - Streaming file reads for memory efficiency
    - Progress tracking
    - Pre-compiled regex patterns
    """

    def __init__(
        self,
        root_path: str,
        max_workers: Optional[int] = None,
        use_parallel: bool = True,
    ):
        self.root_path = root_path
        self.max_workers = max_workers or (os.cpu_count() or 4)
        self.use_parallel = use_parallel
        self.ignore_dirs = IGNORE_DIRS.copy()
        self.ignore_files = IGNORE_FILES.copy()
        self._progress = ScanProgress()

    def scan(self) -> List[Dict[str, Any]]:
        """Synchronous wrapper that runs the async scanner."""
        return asyncio.run(self.scan_async())

    async def scan_async(self) -> List[Dict[str, Any]]:
        """
        Perform security scan asynchronously.

        Uses ProcessPoolExecutor for parallel regex matching while
        keeping file I/O async.
        """
        findings: List[SecurityFinding] = []

        log.info("security.audit_start", path=self.root_path)

        # Count files for progress tracking
        self._progress.files_total = _count_files_to_scan(
            self.root_path, self.ignore_dirs, self.ignore_files
        )

        # Collect files asynchronously
        files = await _collect_files_async(
            self.root_path, self.ignore_dirs, self.ignore_files
        )

        if not files:
            return []

        if self.use_parallel and len(files) > 10:
            # Use ProcessPoolExecutor for parallel scanning
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all files for parallel processing
                futures = [executor.submit(_scan_file_worker, (f,)) for f in files]

                # Collect results as they complete
                for future in futures:
                    file_findings = future.result()
                    findings.extend(file_findings)
                    self._progress.files_scanned += 1

                    if self._progress.files_total > 0:
                        self._progress.percent_complete = (
                            self._progress.files_scanned
                            / self._progress.files_total
                            * 100
                        )

                    # Log progress every 100 files
                    if self._progress.files_scanned % 100 == 0:
                        log.debug(
                            "security.audit_progress",
                            files_scanned=self._progress.files_scanned,
                            percent_complete=self._progress.percent_complete,
                            findings_found=self._progress.findings_found,
                        )
        else:
            # Sequential scanning for small codebases
            for file_path in files:
                file_findings = await _scan_file_async(
                    file_path,
                    SECURITY_PATTERNS,
                )
                findings.extend(file_findings)
                self._progress.files_scanned += 1

        log.info(
            "security.audit_complete",
            path=self.root_path,
            files_scanned=self._progress.files_scanned,
            findings_found=len(findings),
        )

        return [f.to_dict() for f in findings]

    def scan_with_progress(self) -> tuple[List[Dict[str, Any]], ScanProgress]:
        """
        Perform security scan with detailed progress tracking.

        Returns findings and progress object.
        """
        findings = self.scan()
        return findings, self._progress
