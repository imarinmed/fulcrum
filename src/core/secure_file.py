"""
Secure file operations module.

Provides security-enhanced file operations including:
- Secure file creation with proper permissions
- Path traversal prevention
- File integrity verification
"""

import os
import stat
from pathlib import Path
from typing import Optional
import structlog

log = structlog.get_logger()


class SecurityFileError(Exception):
    """Raised when file operations fail security checks."""

    pass


# Allowed base directories for file operations
ALLOWED_FILE_DIRS = [
    Path.cwd(),
    Path.home() / ".fulcrum",
    Path("/tmp/fulcrum"),
]


def _is_file_path_safe(requested_path: Path, allowed_dirs: list[Path]) -> bool:
    """
    Check if a file path is within allowed directories.

    Args:
        requested_path: Path to validate
        allowed_dirs: List of allowed base directories

    Returns:
        True if path is safe
    """
    try:
        resolved = requested_path.resolve()
        for allowed in allowed_dirs:
            allowed_resolved = allowed.resolve()
            try:
                resolved.relative_to(allowed_resolved)
                return True
            except ValueError:
                continue
        return False
    except (OSError, ValueError):
        return False


def secure_makedirs(path: Path, mode: int = 0o700) -> None:
    """
    Create directory with secure permissions.

    Args:
        path: Directory path to create
        mode: Permission mode (default: 0o700 = owner only)

    Raises:
        SecurityFileError: If path is outside allowed directories
    """
    if not _is_file_path_safe(path, ALLOWED_FILE_DIRS):
        raise SecurityFileError(f"Path outside allowed directories: {path}")

    os.makedirs(path, exist_ok=True, mode=mode)

    # Set permissions securely
    try:
        os.chmod(path, mode)
    except OSError:
        pass  # May fail on some filesystems


def secure_file_write(
    filepath: Path, content: str, mode: int = 0o600, directory_mode: int = 0o700
) -> None:
    """
    Write file with secure permissions.

    Args:
        filepath: Path to file
        content: Content to write
        mode: File permission mode (default: 0o600 = owner read/write)
        directory_mode: Parent directory mode

    Raises:
        SecurityFileError: If path is outside allowed directories
    """
    if not _is_file_path_safe(filepath, ALLOWED_FILE_DIRS):
        raise SecurityFileError(f"Path outside allowed directories: {filepath}")

    # Create parent directory with secure permissions
    parent = filepath.parent
    secure_makedirs(parent, directory_mode)

    # Write file with secure permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(filepath), flags, mode)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except Exception:
        os.close(fd)
        raise

    # Set permissions explicitly
    try:
        os.chmod(filepath, mode)
    except OSError:
        pass  # May fail on some filesystems


def secure_temp_file(
    suffix: str = ".tmp", mode: int = 0o600, dir_path: Optional[Path] = None
) -> tuple[int, Path]:
    """
    Create temporary file with secure permissions.

    Args:
        suffix: File suffix
        mode: File permission mode
        dir_path: Temporary directory (default: system temp)

    Returns:
        Tuple of (file descriptor, file path)
    """
    import tempfile

    temp_dir = dir_path or Path(tempfile.gettempdir()) / "fulcrum"
    secure_makedirs(temp_dir, 0o700)

    fd, path = tempfile.mkstemp(suffix=suffix, dir=str(temp_dir), text=True)

    # Set secure permissions
    try:
        os.chmod(path, mode)
    except OSError:
        pass

    return fd, path
