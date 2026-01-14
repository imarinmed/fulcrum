import asyncio
import os
import structlog
from typing import List, Optional
from datetime import datetime

log = structlog.get_logger()


class ScanResult:
    def __init__(
        self,
        project_id: str,
        success: bool,
        report_path: Optional[str] = None,
        error: Optional[str] = None,
    ):
        self.project_id = project_id
        self.success = success
        self.report_path = report_path
        self.error = error
        self.timestamp = datetime.now().isoformat()


class AsyncScanner:
    def __init__(
        self,
        output_dir: str = "prowler_reports",
        timeout_sec: int = 600,
        max_concurrency: int = 3,
    ):
        self.output_dir = output_dir
        self.timeout_sec = timeout_sec
        self.semaphore = asyncio.Semaphore(max_concurrency)

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    async def scan_project(self, project_id: str) -> ScanResult:
        async with self.semaphore:
            log.info("scanner.start", project=project_id)

            prowler_cmd = "prowler"
            if os.path.exists(os.path.expanduser("~/.local/bin/prowler")):
                prowler_cmd = os.path.expanduser("~/.local/bin/prowler")

            # Construct command
            # Using standard json for easier parsing in aggregator
            # Explicitly set output filename to avoid collisions and ensure traceability
            output_filename = f"prowler-{project_id}"
            cmd = [
                prowler_cmd,
                "gcp",
                "--project-ids",
                project_id,
                "--output-directory",
                self.output_dir,
                "--output-filename",
                output_filename,
                "--output-modes",
                "json-ocsf",
            ]

            try:
                # Create subprocess
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=self.timeout_sec
                    )

                    # Prowler returns 0 for success (no issues), 1 for error, and 3 for success (with issues found)
                    if process.returncode not in [0, 3]:
                        err_msg = stderr.decode().strip()
                        log.error(
                            "scanner.failed",
                            project=project_id,
                            error=err_msg,
                            code=process.returncode,
                        )
                        return ScanResult(
                            project_id,
                            False,
                            error=f"Exit {process.returncode}: {err_msg}",
                        )

                    # Success
                    log.info("scanner.success", project=project_id)
                    return ScanResult(project_id, True, report_path=self.output_dir)

                except asyncio.TimeoutError:
                    try:
                        process.kill()
                        # Wait briefly for process cleanup to avoid zombie processes/event loop issues
                        await asyncio.sleep(0.1)
                    except ProcessLookupError:
                        pass
                    log.error("scanner.timeout", project=project_id)
                    return ScanResult(project_id, False, error="Timeout exceeded")

            except Exception as e:
                log.error("scanner.exception", project=project_id, error=str(e))
                return ScanResult(project_id, False, error=str(e))

    async def scan_projects(self, project_ids: List[str]) -> List[ScanResult]:
        tasks = [self.scan_project(pid) for pid in project_ids]
        return await asyncio.gather(*tasks, return_exceptions=True)
