"""Checks on the config files themselves, so mistakes show up in a second."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"

VALID_OUTCOMES = {
    "secret_exposed", "deployment_executed", "prod_deployment_executed",
    "unauthorized_tool_executed", "invalid_args_executed",
}
VALID_TOOLS = {"get_pipeline_status", "read_logs", "get_config", "trigger_deployment"}

# Each weakened policy must differ from the real one in exactly this section.
EXPECTED_DRILLS = {
    "no_taint": {"taint"},
    "narrow_taint": {"taint"},
    "no_redaction": {"redaction"},
}


def load(path):
    return yaml.safe_load(open(path))


def all_tests():
    return load(CONFIG / "tests.yaml")


def scripted():
    return load(CONFIG / "tricked_calls.yaml")


def test_test_ids_are_unique():
    ids = [t["id"] for t in all_tests()]
    assert len(ids) == len(set(ids)), "duplicate test IDs"


def test_every_attack_has_a_scripted_entry():
    missing = [t["id"] for t in all_tests() if t["type"] == "attack" and t["id"] not in scripted()]
    assert not missing, f"attacks with no scripted entry (they would be skipped): {missing}"


def test_scripted_entries_match_real_attack_tests():
    by_id = {t["id"]: t for t in all_tests()}
    for tid, calls in scripted().items():
        assert tid in by_id, f"scripted entry {tid} has no test"
        assert by_id[tid]["type"] == "attack", f"{tid} is scripted but is not an attack"
        for call in calls:
            assert call["tool"] in VALID_TOOLS, f"{tid}: unknown tool {call['tool']}"


def test_attack_tests_use_known_outcomes():
    for t in all_tests():
        if t["type"] == "attack":
            assert t["prohibited"], f"{t['id']} has no prohibited outcomes"
            assert set(t["prohibited"]) <= VALID_OUTCOMES, f"{t['id']}: unknown outcome"


def test_legitimate_tests_name_the_expected_tool():
    for t in all_tests():
        if t["type"] == "legitimate":
            assert t.get("expect_tool_executed") in VALID_TOOLS, f"{t['id']}: bad expect_tool_executed"


def test_test_users_exist_or_are_deliberately_unknown():
    users = set(load(CONFIG / "policy.yaml")["users"])
    unknown = {t["user"] for t in all_tests()} - users
    assert unknown <= {"mallory"}, f"unexpected users in tests: {unknown}"


def test_policy_has_required_sections():
    p = load(CONFIG / "policy.yaml")
    for section in ("users", "roles", "validation", "redaction", "taint"):
        assert section in p, f"policy.yaml is missing '{section}'"


def test_every_weakened_policy_differs_in_exactly_one_section():
    real = load(CONFIG / "policy.yaml")
    files = sorted((CONFIG / "regressions").glob("*.yaml"))
    assert {f.stem for f in files} == set(EXPECTED_DRILLS), "drill files changed, update EXPECTED_DRILLS"
    for f in files:
        drill = load(f)
        differs = {k for k in set(real) | set(drill) if real.get(k) != drill.get(k)}
        assert differs == EXPECTED_DRILLS[f.stem], f"{f.name} differs in {differs}, expected {EXPECTED_DRILLS[f.stem]}"