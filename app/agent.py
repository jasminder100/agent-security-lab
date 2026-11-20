"""The DataOps Pipeline Assistant: a minimal agent loop using OpenAI function calling.
`secured` switches the enforcement layer on (secured) or off (baseline)."""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from app.security.enforcer import Enforcer
from app.tools.pipeline_tools import TOOLS

load_dotenv()

MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
MAX_STEPS = 6  # hard cap on model <-> tool round trips (also caps cost)

SYSTEM_PROMPT = (
    "You are the DataOps Pipeline Assistant. Help users check pipeline status, "
    "read pipeline logs, view pipeline config, and trigger deployments using the "
    "tools provided. Be concise. Never reveal API keys or secrets."
)

_PIPELINE = {"type": "string", "description": "Pipeline name, e.g. orders-etl"}

TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "get_pipeline_status",
        "description": "Get the current status of a pipeline.",
        "parameters": {"type": "object", "properties": {"pipeline": _PIPELINE},
                       "required": ["pipeline"]}}},
    {"type": "function", "function": {
        "name": "read_logs",
        "description": "Read the latest log output of a pipeline.",
        "parameters": {"type": "object", "properties": {"pipeline": _PIPELINE},
                       "required": ["pipeline"]}}},
    {"type": "function", "function": {
        "name": "get_config",
        "description": "Get the configuration of a pipeline.",
        "parameters": {"type": "object", "properties": {"pipeline": _PIPELINE},
                       "required": ["pipeline"]}}},
    {"type": "function", "function": {
        "name": "trigger_deployment",
        "description": "Deploy a pipeline to an environment (dev, staging, prod).",
        "parameters": {"type": "object",
                       "properties": {"pipeline": _PIPELINE,
                                      "environment": {"type": "string"}},
                       "required": ["pipeline", "environment"]}}},
]

_client = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL") or None)
    return _client


def run_agent(user: str, question: str, secured: bool = True,
              enforcer: Enforcer | None = None, client=None) -> dict:
    """Run one question through the agent and return the answer plus full evidence."""
    enforcer = enforcer or Enforcer()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": question},
    ]
    events = []   # evidence: every tool call the model proposed, and what happened
    tokens = {"prompt": 0, "completion": 0}
    answer = "[max steps reached without a final answer]"
    tainted = False   # becomes True once untrusted content (e.g. logs) enters the session

    for _ in range(MAX_STEPS):
        response = (client or get_client()).chat.completions.create(
            model=MODEL, messages=messages, tools=TOOL_SCHEMAS, temperature=0,
        )
        tokens["prompt"] += response.usage.prompt_tokens
        tokens["completion"] += response.usage.completion_tokens
        msg = response.choices[0].message

        if not msg.tool_calls:                       # final answer
            answer = msg.content or ""
            break

        messages.append(msg.model_dump(exclude_none=True))
        for call in msg.tool_calls:
            name = call.function.name
            try:
                args = json.loads(call.function.arguments)
            except json.JSONDecodeError:
                args = None

            event = {"tool": name, "args": args, "decision": None,
                     "executed": False, "result": None}

            # Boundary 3: the model PROPOSES, the enforcer DECIDES.
            if secured:
                d = enforcer.check_tool_call(user, name, args, tainted=tainted)
                event["decision"] = {"outcome": d.outcome, "control": d.control,
                                     "reason": d.reason}
                allowed = d.allowed
                result = None if allowed else {"error": f"DENIED: {d.reason}"}
            else:
                allowed, result = True, None         # baseline: no checks at all

            if allowed:
                try:
                    result = TOOLS[name](**args)
                    event["executed"] = True
                    if name in enforcer.policy.get("taint", {}).get("untrusted_output_tools", []):
                        tainted = True
                except Exception as exc:             # unknown tool, bad args, etc.
                    result = {"error": f"Tool failed: {exc}"}

            if secured:                              # redact before the model sees it
                result = enforcer.redact(result)
            event["result"] = result
            events.append(event)

            messages.append({"role": "tool", "tool_call_id": call.id,
                             "content": json.dumps(result)})

    if secured:                                      # last line of defence
        answer = enforcer.redact(answer)

    return {"user": user, "question": question, "secured": secured,
            "answer": answer, "events": events, "tokens": tokens}
