from pathlib import Path
import yaml

POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "policy.yaml"


def load_policy(path: Path = POLICY_PATH) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)
