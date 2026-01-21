import pytest
from fulcrum.core.remediation import RemediationManager, RemediationAction, RemediationResult

class MockAction(RemediationAction):
    @property
    def id(self):
        return "mock_action"
    
    @property
    def description(self):
        return "Mock Action"
    
    def execute(self, target, dry_run=False):
        if dry_run:
            return RemediationResult(self.id, True, "Dry run success")
        if target == "fail":
            raise Exception("Failure")
        return RemediationResult(self.id, True, "Success", {"changed": True})

def test_remediation_manager_register():
    mgr = RemediationManager()
    action = MockAction()
    mgr.register_action(action)
    assert mgr.get_action("mock_action") == action

def test_remediation_execution_success():
    mgr = RemediationManager()
    mgr.register_action(MockAction())
    res = mgr.remediate("mock_action", "target")
    assert res.success
    assert res.message == "Success"

def test_remediation_execution_dry_run():
    mgr = RemediationManager()
    mgr.register_action(MockAction())
    res = mgr.remediate("mock_action", "target", dry_run=True)
    assert res.success
    assert "Dry run" in res.message

def test_remediation_execution_failure():
    mgr = RemediationManager()
    mgr.register_action(MockAction())
    res = mgr.remediate("mock_action", "fail")
    assert not res.success
    assert "Exception" in res.message

def test_remediation_not_found():
    mgr = RemediationManager()
    res = mgr.remediate("unknown", "target")
    assert not res.success
    assert "No remediation action found" in res.message
