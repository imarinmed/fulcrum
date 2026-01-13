from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import structlog

log = structlog.get_logger()

class DiagnosticResult:
    def __init__(self, check_name: str, passed: bool, message: str, details: Optional[Dict] = None):
        self.check_name = check_name
        self.passed = passed
        self.message = message
        self.details = details or {}

class DiagnosticCheck(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def run(self) -> DiagnosticResult:
        pass

class DiagnosticsManager:
    def __init__(self):
        self.checks: List[DiagnosticCheck] = []

    def register_check(self, check: DiagnosticCheck):
        self.checks.append(check)

    def run_all(self) -> List[DiagnosticResult]:
        results = []
        for check in self.checks:
            try:
                result = check.run()
                results.append(result)
            except Exception as e:
                log.error("diagnostic.check_failed", check=check.name, error=str(e))
                results.append(DiagnosticResult(check.name, False, f"Exception: {str(e)}"))
        return results
