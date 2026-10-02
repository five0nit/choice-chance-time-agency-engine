"""Platform prerequisites for actual generated-code sandbox integrations.

Never skip a supported interpreter just because bubblewrap execution fails.
All policy/fail-closed tests remain active on unsupported interpreters.
"""
import os
import fcntl
import pytest

_REAL_SANDBOX_TESTS = {
    "test_real_bubblewrap_upgrade_end_to_end",
    "test_discovery_real_sandbox_outcome_and_independent_child_no_promote",
    "test_real_local_and_service_driver_integration",
    "test_real_stdin_only_delivery_completes_and_survives_restart",
    "test_stdin_only_wrong_computation_cannot_pass_real_sandbox",
}

def pytest_collection_modifyitems(items):
    supported = (
        hasattr(os, "uname") and os.uname().machine == "x86_64"
        and all(hasattr(os, name) for name in ("memfd_create", "MFD_ALLOW_SEALING"))
        and hasattr(fcntl, "F_ADD_SEALS")
    )
    if supported:
        return
    marker = pytest.mark.skip(reason="real sandbox requires Linux x86-64 memfd/seals; fail-closed unit tests remain active")
    for item in items:
        if item.name in _REAL_SANDBOX_TESTS or "::IndependentBehaviorTests::" in item.nodeid:
            item.add_marker(marker)
