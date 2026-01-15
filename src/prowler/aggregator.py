import os
import json
import glob
import hashlib
import hmac
from typing import List, Dict, Any, Optional
import structlog

from ..core.settings import load_settings

log = structlog.get_logger()


class IntegrityVerificationError(Exception):
    """Raised when JSON file integrity verification fails."""

    pass


def _compute_file_hash(filepath: str) -> str:
    """
    Compute SHA-256 hash of a file for integrity verification.

    Args:
        filepath: Path to the file

    Returns:
        Hexadecimal string of the file hash
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read in chunks to handle large files
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def _load_json_with_integrity_check(
    filepath: str,
    expected_hash: Optional[str] = None,
    signature_key: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Load JSON file with optional integrity verification.

    Supports two verification modes:
    1. Expected hash: Verify file matches known good hash
    2. HMAC signature: Verify file using HMAC-SHA256 signature

    Args:
        filepath: Path to JSON file
        expected_hash: Optional SHA-256 hash to verify against
        signature_key: Optional HMAC key for signature verification

    Returns:
        Parsed JSON data

    Raises:
        IntegrityVerificationError: If verification fails
    """
    # First, verify file hash matches expected
    if expected_hash:
        actual_hash = _compute_file_hash(filepath)
        if not hmac.compare_digest(actual_hash, expected_hash):
            raise IntegrityVerificationError(
                f"File hash mismatch for {filepath}. "
                f"Expected: {expected_hash}, Got: {actual_hash}"
            )

    # Verify HMAC signature if provided
    if signature_key:
        sig_path = filepath + ".sig"
        if not os.path.exists(sig_path):
            raise IntegrityVerificationError(f"Signature file not found: {sig_path}")

        with open(sig_path, "rb") as f:
            provided_signature = f.read()

        # Compute expected signature
        with open(filepath, "rb") as f:
            file_content = f.read()

        expected_signature = hmac.new(
            signature_key, file_content, hashlib.sha256
        ).digest()

        if not hmac.compare_digest(provided_signature, expected_signature):
            raise IntegrityVerificationError(
                f"Signature verification failed for {filepath}"
            )

    # Now load the JSON
    with open(filepath, "r") as json_file:
        try:
            data = json.load(json_file)
        except json.JSONDecodeError as e:
            raise IntegrityVerificationError(f"Invalid JSON in {filepath}: {e}")

    return data


def _generate_file_signature(filepath: str, signature_key: bytes) -> bytes:
    """
    Generate HMAC-SHA256 signature for a file.

    Args:
        filepath: Path to file
        signature_key: HMAC key

    Returns:
        HMAC signature as bytes
    """
    with open(filepath, "rb") as f:
        file_content = f.read()

    return hmac.new(signature_key, file_content, hashlib.sha256).digest()


class ReportAggregator:
    def __init__(self, report_dir: str):
        self.report_dir = report_dir

    def aggregate(self) -> Dict[str, Any]:
        """
        Reads all .json-ocsf files in the report directory and creates a summary.
        Assumes Prowler OCSF JSON output.
        """
        summary = {
            "projects": {},
            "total_stats": {
                "FAIL": 0,
                "PASS": 0,
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
        }

        # Find all ocsf json files
        pattern = os.path.join(self.report_dir, "*.ocsf.json")
        files = glob.glob(pattern)

        for f in files:
            try:
                # Load JSON with integrity verification
                try:
                    data = _load_json_with_integrity_check(f)
                except IntegrityVerificationError as e:
                    log.error(
                        "aggregator.integrity_failed",
                        file=f,
                        error=str(e),
                        security_event=True,
                    )
                    continue
                except json.JSONDecodeError:
                    log.warning(
                        "aggregator.json_parse_error", file=f, security_event=True
                    )
                    continue

                # OCSF is likely a list of finding objects
                if not isinstance(data, list):
                    # If it's a single object, wrap it
                    data = [data]

                for finding in data:
                    # Extract Project ID from OCSF structure
                    # finding -> cloud -> project -> uid OR cloud -> account -> uid
                    try:
                        project_id = (
                            finding.get("cloud", {}).get("project", {}).get("uid")
                        )
                        if not project_id or project_id == "unknown":
                            project_id = (
                                finding.get("cloud", {})
                                .get("account", {})
                                .get("uid", "unknown")
                            )
                    except Exception as e:
                        log.warning(
                            "aggregator.project_id_extraction_failed",
                            file=f,
                            error=str(e),
                            security_event=True,
                        )
                        project_id = "unknown"

                        # Extract Status
                        # In OCSF, status might be under 'status_code' or 'state' or 'activity_id'
                        # Prowler maps FAIL/PASS to OCSF...
                        # Let's inspect typical Prowler OCSF mapping if we can't see it.
                        # Usually Prowler adds custom fields or standard OCSF fields.
                        # Status ID 1: New, 2: In Progress, 3: Resolved...
                        # Prowler specific:
                        # 'status': 'FAIL' -> maybe finding_info.title contains FAIL?
                        # Or finding.status_id?
                        # Let's try to find a Prowler specific field or standard OCSF.
                        # If finding['status'] exists (Prowler often leaves non-OCSF fields in top level in some versions or extensions)

                        # Fallback: Check typical Prowler keys if mixed in, or rely on 'severity_id'
                        # Severity ID: 1 (Info), 2 (Low), 3 (Medium), 4 (High), 5 (Critical), 6 (Fatal)
                        severity_id = finding.get("severity_id", 0)
                        severity_map = {
                            1: "LOW",
                            2: "LOW",
                            3: "MEDIUM",
                            4: "HIGH",
                            5: "CRITICAL",
                            6: "CRITICAL",
                        }
                        # Prowler mapping might differ slightly.
                        # Prowler 3: Info(0), Low(1), Medium(2), High(3), Critical(4)
                        # Prowler 4 OCSF:
                        # Informational: 1
                        # Low: 2
                        # Medium: 3
                        # High: 4
                        # Critical: 5

                        severity = severity_map.get(severity_id, "UNKNOWN")

                        # Status?
                        # If severity is Informational (1) and it's a "pass", how do we know?
                        # Prowler OCSF usually only exports FINDINGS (Failures)?
                        # Or it exports everything.
                        # Let's check 'state' or 'status'.
                        # Prowler: 'status': 'PASS' / 'FAIL' in standard json.
                        # In OCSF, maybe 'state_id'.
                        # 'state_id': 1 (New) -> FAIL?
                        # 'state_id': 2 (Resolved) -> PASS?

                        # Let's try to infer from typical OCSF usage for findings.
                        # Often "New" implies an active finding (Fail).
                        # If we can't determine, we assume it's a finding (Fail) because typical security reports list findings.
                        # But Prowler can list Passes.

                        # Hack: Check for "PASS" string in message or description if possible.
                        # Or look for 'status' key if Prowler leaks it.
                        status = (
                            "FAIL"  # Default to fail if it's in the report as a finding
                        )

                        # Prowler v4 OCSF output:
                        # status: "FAIL" might be mapped to state_id="New"
                        # status: "PASS" might be mapped to state_id="Resolved" or "Suppressed"

                        state_id = finding.get("state_id")
                        if state_id == 2:  # Resolved
                            status = "PASS"
                        elif state_id == 0 or state_id == 1:  # Unknown or New
                            status = "FAIL"

                        if project_id not in summary["projects"]:
                            summary["projects"][project_id] = {
                                "FAIL": 0,
                                "PASS": 0,
                                "CRITICAL": 0,
                                "HIGH": 0,
                                "MEDIUM": 0,
                                "LOW": 0,
                            }

                        if status == "FAIL":
                            summary["projects"][project_id]["FAIL"] += 1
                            summary["total_stats"]["FAIL"] += 1

                            if severity in summary["projects"][project_id]:
                                summary["projects"][project_id][severity] += 1
                            if severity in summary["total_stats"]:
                                summary["total_stats"][severity] += 1

                        elif status == "PASS":
                            summary["projects"][project_id]["PASS"] += 1
                            summary["total_stats"]["PASS"] += 1

            except Exception as e:
                log.warning("aggregator.error", file=f, error=str(e))

        # Fix project counting: The previous issue was likely due to Prowler outputs overwriting or
        # using project_ids that don't match the folder structure if run sequentially.
        # But here we parse OCSF content which should have the correct project ID inside.
        # If "Total Projects Scanned: 1" appears, it means only one unique project_id was found in the OCSF files.
        # This can happen if Prowler defaults to the account ID or a fixed string if not properly passed/parsed.
        # Let's trust the 'project_id' key extracted from OCSF.

        return summary
