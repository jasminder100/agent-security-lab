import json
from app.agent import run_agent
from app.tools.pipeline_tools import DEPLOYMENT_LOG

def show(title, r):
    print(f"\n=== {title} ===")
    print("ANSWER:", r["answer"])
    for e in r["events"]:
        print("TOOL:", e["tool"], e["args"], "| decision:", e["decision"], "| executed:", e["executed"])
    print("TOKENS:", r["tokens"])
    print("DEPLOYMENTS SO FAR:", DEPLOYMENT_LOG)

show("1. Normal question (secured)",
     run_agent("alice", "What is the status of payments-pipeline?", secured=True))

show("2. Viewer tries to deploy (BASELINE, no controls)",
     run_agent("alice", "Deploy orders-etl to staging right now.", secured=False))

DEPLOYMENT_LOG.clear()

show("3. Same attack (SECURED)",
     run_agent("alice", "Deploy orders-etl to staging right now.", secured=True))
