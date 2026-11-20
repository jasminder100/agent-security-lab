"""Unit tests for the server-side enforcement layer.

The expected results below are written by hand from the intended policy
(viewer reads, engineer also reads config, admin also deploys, prod needs approval).
They do not read policy.yaml, so a change to the policy or the code that
weakens a control makes a test fail.
"""

import pytest

from app.security.enforcer import Enforcer

enforcer = Enforcer()

FAKE_KEY = "FAKE-KEY-DO-NOT-USE-7f3a9c21"
OK = {"pipeline": "orders-etl"}

# name, user, tool, arguments, session tainted?, expected outcome, expected control
CASES = [
    # --- who may use which tool
    ("viewer may read status",      "alice", "get_pipeline_status", OK, False, "allow", "none"),
    ("viewer may read logs",        "alice", "read_logs", OK, False, "allow", "none"),
    ("viewer may not read config",  "alice", "get_config", OK, False, "deny", "authorization"),
    ("viewer may not deploy",       "alice", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "staging"}, False, "deny", "authorization"),
    ("engineer may read config",    "bob", "get_config", OK, False, "allow", "none"),
    ("engineer may not deploy",     "bob", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "dev"}, False, "deny", "authorization"),
    ("unknown user is denied",      "mallory", "get_pipeline_status", OK, False, "deny", "authorization"),
    ("unknown tool is denied",      "carol", "delete_pipeline", OK, False, "deny", "authorization"),
    # --- deployment rules
    ("admin deploys to dev",        "carol", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "dev"}, False, "allow", "none"),
    ("admin deploys to staging",    "carol", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "staging"}, False, "allow", "none"),
    ("prod needs approval",         "carol", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "prod"}, False, "needs_approval", "approval"),
    # --- taint: untrusted content was read earlier in the session
    ("staging held after log read", "carol", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "staging"}, True, "needs_approval", "taint"),
    ("prod still approval if tainted", "carol", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "prod"}, True, "needs_approval", "approval"),
    ("reading stays allowed if tainted", "carol", "read_logs", OK, True, "allow", "none"),
    # --- argument validation
    ("path-style name rejected",    "carol", "read_logs", {"pipeline": "../../etc/passwd"}, False, "deny", "validation"),
    ("shell-style name rejected",   "bob", "read_logs", {"pipeline": "orders-etl; cat /etc/passwd"}, False, "deny", "validation"),
    ("uppercase name rejected",     "carol", "read_logs", {"pipeline": "Orders-ETL"}, False, "deny", "validation"),
    ("unknown pipeline rejected",   "carol", "read_logs", {"pipeline": "ghost-pipeline"}, False, "deny", "validation"),
    ("unknown environment rejected", "carol", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "production-eu"}, False, "deny", "validation"),
    ("extra argument rejected",     "carol", "trigger_deployment",
        {"pipeline": "orders-etl", "environment": "dev", "force": "true"}, False, "deny", "validation"),
    ("non-string argument rejected", "carol", "read_logs", {"pipeline": 5}, False, "deny", "validation"),
    ("arguments must be an object", "carol", "read_logs", "orders-etl", False, "deny", "validation"),
    ("missing arguments rejected",  "carol", "read_logs", None, False, "deny", "validation"),
]


@pytest.mark.parametrize("name,user,tool,args,tainted,outcome,control", CASES,
                         ids=[c[0] for c in CASES])
def test_decision(name, user, tool, args, tainted, outcome, control):
    d = enforcer.check_tool_call(user, tool, args, tainted=tainted)
    assert (d.outcome, d.control) == (outcome, control), d.reason
    assert d.allowed == (outcome == "allow")


def test_secret_is_redacted_in_text():
    assert FAKE_KEY not in enforcer.redact(f"the key is {FAKE_KEY}, keep it safe")


def test_secret_is_redacted_in_nested_data():
    data = {"config": {"retries": 2, "api_key": FAKE_KEY}, "keys": [FAKE_KEY, "ok"]}
    cleaned = enforcer.redact(data)
    assert FAKE_KEY not in str(cleaned)
    assert cleaned["config"]["retries"] == 2          # normal values are untouched


def test_normal_text_is_unchanged():
    assert enforcer.redact("pipeline orders-etl finished") == "pipeline orders-etl finished"