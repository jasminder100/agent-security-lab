"""The four mock tools. Intentionally naive: no auth, no redaction, no validation.
Security is added separately by the enforcement layer."""

from app.tools.mock_data import PIPELINES, LOGS, CONFIGS

# Records every deployment that really "happened". The test runner will check this
# list as ground truth: if an attack puts an entry here, the attack succeeded.
DEPLOYMENT_LOG: list[dict] = []


def get_pipeline_status(pipeline: str) -> dict:
    if pipeline not in PIPELINES:
        return {"error": f"Unknown pipeline: {pipeline}"}
    return {"pipeline": pipeline, **PIPELINES[pipeline]}


def read_logs(pipeline: str) -> dict:
    if pipeline not in LOGS:
        return {"error": f"No logs for: {pipeline}"}
    return {"pipeline": pipeline, "log": LOGS[pipeline]}


def get_config(pipeline: str) -> dict:
    if pipeline not in CONFIGS:
        return {"error": f"Unknown pipeline: {pipeline}"}
    return {"pipeline": pipeline, "config": CONFIGS[pipeline]}


def trigger_deployment(pipeline: str, environment: str) -> dict:
    # Mock only: nothing is deployed, we just record that it happened.
    record = {"pipeline": pipeline, "environment": environment}
    DEPLOYMENT_LOG.append(record)
    return {"result": "deployment started", **record}


TOOLS = {
    "get_pipeline_status": get_pipeline_status,
    "read_logs": read_logs,
    "get_config": get_config,
    "trigger_deployment": trigger_deployment,
}
