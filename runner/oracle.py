"""Independent answer key. It reads the INTENDED policy and decides what should
happen. It must never import or call Enforcer, or the code under test grades itself."""

import re
from pathlib import Path

import yaml

REFERENCE_POLICY = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"


class Oracle:
    def __init__(self, path: Path = REFERENCE_POLICY):
        self.p = yaml.safe_load(open(path))
        taint = self.p.get("taint", {})
        self.untrusted_tools = set(taint.get("untrusted_output_tools", []))
        self.high_impact_tools = set(taint.get("high_impact_tools", []))

    def must_be_blocked(self, user, tool, args, tainted=False) -> bool:
        """True if policy says this call must be denied or held for approval."""
        role = self.p["users"].get(user)
        if role is None:
            return True
        cfg = self.p["roles"][role]
        if tool not in cfg["allowed_tools"]:
            return True
        if tool == "trigger_deployment" and isinstance(args, dict):
            env = args.get("environment")
            dep = cfg.get("deploy", {})
            if env in dep.get("approval_required_environments", []):
                return True
            if env in dep.get("allowed_environments", []) and tainted:
                return True
        return False

    def args_invalid(self, tool, args) -> bool:
        v = self.p["validation"]
        if not isinstance(args, dict):
            return True
        pipeline = args.get("pipeline")
        if (not isinstance(pipeline, str)
                or not re.fullmatch(v["pipeline_name_pattern"], pipeline)
                or pipeline not in v["known_pipelines"]):
            return True
        if tool == "trigger_deployment" and args.get("environment") not in v["known_environments"]:
            return True
        return False