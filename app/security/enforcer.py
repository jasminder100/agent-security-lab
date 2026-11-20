"""Server-side enforcement layer. No LLM involved: plain, deterministic code."""

import re
from dataclasses import dataclass

from app.security.policy import load_policy

# The exact arguments each tool accepts. Anything else is rejected.
TOOL_ARGS = {
    "get_pipeline_status": {"pipeline"},
    "read_logs": {"pipeline"},
    "get_config": {"pipeline"},
    "trigger_deployment": {"pipeline", "environment"},
}


@dataclass
class Decision:
    allowed: bool    # may the tool run right now?
    outcome: str     # "allow" | "deny" | "needs_approval"
    control: str     # which control decided: authorization, validation, approval, none
    reason: str      # human-readable explanation, used as evidence in reports


class Enforcer:
    def __init__(self, policy: dict | None = None):
        self.policy = policy or load_policy()
        self._secret_res = [
            re.compile(p) for p in self.policy["redaction"]["secret_patterns"]
        ]

    # ---- Checks on tool calls -------------------------------------------------
    def check_tool_call(self, user: str, tool: str, args, tainted: bool = False) -> Decision:
        d = self._base_check(user, tool, args)
        cfg = self.policy.get("taint", {})
        if d.allowed and tainted and tool in cfg.get("high_impact_tools", []):
            return Decision(
                False, "needs_approval", "taint",
                f"'{tool}' held: this session has read untrusted content, human approval required",
            )
        return d


    def _base_check(self, user: str, tool: str, args) -> Decision:
        # 1. Authorization (deny by default)
        role = self.policy["users"].get(user)
        if role is None:
            return Decision(False, "deny", "authorization", f"Unknown user '{user}'")

        role_cfg = self.policy["roles"][role]
        if tool not in role_cfg["allowed_tools"]:
            return Decision(
                False, "deny", "authorization",
                f"Role '{role}' is not allowed to use '{tool}'",
            )

        # 2. Argument validation
        problem = self._validate_args(tool, args)
        if problem:
            return Decision(False, "deny", "validation", problem)

        # 3. Deployment rules
        if tool == "trigger_deployment":
            env = args["environment"]
            rules = role_cfg.get("deploy", {})
            if env in rules.get("allowed_environments", []):
                return Decision(True, "allow", "none", f"Deploy to '{env}' permitted")
            if env in rules.get("approval_required_environments", []):
                return Decision(
                    False, "needs_approval", "approval",
                    f"Deploy to '{env}' requires human approval",
                )
            return Decision(
                False, "deny", "authorization",
                f"Role '{role}' may not deploy to '{env}'",
            )

        return Decision(True, "allow", "none", "Permitted by role policy")

    def _validate_args(self, tool: str, args) -> str | None:
        """Return a problem description, or None if the arguments are fine."""
        v = self.policy["validation"]

        if not isinstance(args, dict):
            return "Arguments must be an object"
        if tool not in TOOL_ARGS:
            return f"Unknown tool '{tool}'"
        if set(args) != TOOL_ARGS[tool]:
            return f"Expected arguments {sorted(TOOL_ARGS[tool])}, got {sorted(args)}"
        if not all(isinstance(val, str) for val in args.values()):
            return "All arguments must be strings"

        pipeline = args["pipeline"]
        if not re.fullmatch(v["pipeline_name_pattern"], pipeline):
            return "Pipeline name has an invalid format"
        if pipeline not in v["known_pipelines"]:
            return f"Unknown pipeline '{pipeline}'"

        if "environment" in args and args["environment"] not in v["known_environments"]:
            return f"Unknown environment '{args['environment']}'"

        return None

    # ---- Redaction ------------------------------------------------------------

    def redact(self, data):
        """Scrub secrets from any string, dict or list, recursively."""
        replacement = self.policy["redaction"]["replacement"]
        if isinstance(data, str):
            for pattern in self._secret_res:
                data = pattern.sub(replacement, data)
            return data
        if isinstance(data, dict):
            return {k: self.redact(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.redact(v) for v in data]
        return data

    def validate_args(self, tool: str, args):
        """Public wrapper: returns a problem description, or None if the args are fine."""
        return self._validate_args(tool, args)
