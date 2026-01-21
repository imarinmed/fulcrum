from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import structlog

log = structlog.get_logger()


class RemediationResult:
    def __init__(
        self,
        action_name: str,
        success: bool,
        message: str,
        changes: Optional[Dict] = None,
    ):
        self.action_name = action_name
        self.success = success
        self.message = message
        self.changes = changes or {}


class RemediationAction(ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier for this remediation action (e.g. prowler check ID)."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @abstractmethod
    def execute(self, target: Any, dry_run: bool = False) -> RemediationResult:
        """
        Executes the remediation.
        target: The target resource or context (e.g. project_id, cluster_name).
        """
        pass


class RemediationManager:
    def __init__(self):
        self.actions: Dict[str, RemediationAction] = {}

    def register_action(self, action: RemediationAction):
        self.actions[action.id] = action

    def get_action(self, action_id: str) -> Optional[RemediationAction]:
        return self.actions.get(action_id)

    def remediate(
        self, action_id: str, target: Any, dry_run: bool = False
    ) -> RemediationResult:
        action = self.get_action(action_id)
        if not action:
            return RemediationResult(
                action_id, False, f"No remediation action found for ID: {action_id}"
            )

        try:
            log.info(
                "remediation.start",
                action_id=action_id,
                target=str(target),
                dry_run=dry_run,
            )
            result = action.execute(target, dry_run=dry_run)
            log.info(
                "remediation.complete", action_id=action_id, success=result.success
            )
            return result
        except Exception as e:
            log.error("remediation.failed", action_id=action_id, error=str(e))
            return RemediationResult(action_id, False, f"Exception: {str(e)}")
