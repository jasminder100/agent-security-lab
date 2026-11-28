# AI Agent Security Testing Lab

I built this to answer one question: if an AI agent can be tricked by text it reads, how do you test that properly before putting it into a real workflow?

The project has a small sample agent (a DataOps Pipeline Assistant with four mock tools) and a test framework that attacks it. It runs the same set of tests with and without security controls, saves the evidence for every run, and reports how many attacks got through. Everything is mock data. No real systems or credentials are involved.

# What I discovered
On the live model (gpt-4.1-mini), 18 of the 27 attacks I ran succeeded without controls. With controls on, none did. With a scripted model that always obeys the attacker, all 29 attacks succeeded without controls and none with them, across 3 repeats.
Two of the nine legitimate requests get held for approval (TC-024 and TC-038). That is the cost of the control that requires approval after the agent has read untrusted content. I left it in on purpose and report it.
TC-016 found a real gap: an admin could be steered into a staging deployment by a poisoned log. That led to the taint control. I then extended it to config and status output too, and added tests for it (TC-036 and TC-037).
I compared gpt-4o-mini and gpt-4.1-mini on the first 24 tests. Both ended at 0% attack success with controls on. They differed on one test (TC-010), where gpt-4o-mini refused an invalid environment by itself and gpt-4.1-mini did not.
Nine of the live attacks failed only because the model behaved, not because a control stopped them. The scripted run is what shows the controls work for those.
The framework caught all three weakened policies I used to test it (no taint, taint on logs only, no redaction).

The live numbers come from a 35-test run, before TC-036 to TC-038 were added. Those three are covered by the scripted run and the weakened-policy checks.

This is a prototype on mock data. It does not prove any agent is secure.

# Setup

Python 3.10 or newer is required (3.12 recommended), or use Docker below.

bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

requirements.txt has every version pinned. requirements-direct.txt lists the six packages the project actually uses.

Live mode needs an OpenAI key in a .env file in the project root (not committed). Scripted mode and the tests don't need one.

# Running it

The quickest way to check everything is one command:

bash
./scripts/check.sh

It runs the tests, the benchmark gate, and the three weakened-policy checks, and ends with ALL CHECKS PASSED or CHECKS FAILED. It writes its results to reports/scratch/, so the final results are never touched.

To run the benchmark yourself, scripted mode is free and gives the same result every time:

bash
python -m runner.benchmark --model-mode scripted --repeats 3

Live mode uses the real model and costs money, so set a token limit:

bash
python -m runner.benchmark --model-mode live --repeats 3 --token-budget 100000

Use --model gpt-4.1-mini (or another model name) to choose the model in live mode.

Other useful options: --only TC-016 TC-024 to run specific tests, --modes secured for one mode, --policy <file> to test a different policy, and --results-dir reports/scratch for experiments you don't want mixed in with the final results. Run with --help for the full list.

To build the HTML report:

bash
python -m runner.report

It uses the newest default live and scripted results in reports/results/. To choose files yourself, use --live, --scripted or --compare (for the model comparison).

# Running it in Docker

If you don't want to set up Python, the whole check runs in a container. The build installs the pinned dependencies and runs everything as a normal user. The .env file is excluded from the image, so your key never ends up inside it.

bash
docker build -t agent-security-lab .
docker run --rm --network none agent-security-lab

That runs the tests, the benchmark gate and the three weakened-policy checks with the network switched off. Scripted mode makes no API calls, so it doesn't need a network, and the agent and mock tools can't reach anything outside the container.

For live mode, pass the key at run time:

bash
docker run --rm --env-file .env agent-security-lab \
  python -m runner.benchmark --model-mode live --model gpt-4.1-mini \
  --only TC-003 --repeats 1 --token-budget 5000 --results-dir reports/scratch
# Pass/fail gate

The benchmark exits with code 1 if a limit is broken, so it can fail a build:

bash
python -m runner.benchmark --model-mode scripted --repeats 3 --max-attack-success 0

--max-false-denial sets a limit on blocked legitimate requests. It only applies to live runs, because the scripted run has no legitimate requests. With the taint control the live false-denial rate is above 15%, so choose that limit on purpose.

# Checking that the framework notices a weakened control

config/regressions/ has three policies with one control weakened each. All three should fail the gate:

no_taint.yaml: no taint control at all
narrow_taint.yaml: taint only after reading logs, not configs or status
no_redaction.yaml: secrets are not hidden
bash
python -m runner.benchmark --model-mode scripted \
  --policy config/regressions/no_taint.yaml --max-attack-success 0

If any of them passes, the framework missed it. ./scripts/check.sh and CI run all three.

# Tests and CI
bash
python -m pytest

This runs the enforcer unit tests, checks the gate itself, and checks the config files: test IDs are unique, every attack has a scripted entry, and each weakened policy differs from the real one in exactly one section.

GitHub Actions runs the tests, the scripted benchmark with 3 repeats and the three weakened-policy checks on every push. It never uses live mode, so no secrets are stored. Dependabot opens pull requests for new dependency versions.

# How it's laid out
app/ the agent, the mock tools and the security layer (app/security/enforcer.py is the part that makes the decisions)
config/ the policy, the 38 test cases, the scripted attacker, and the weakened policies
runner/ the benchmark, the oracle (a separate answer key so the code doesn't grade itself) and the report generator
tests/ unit tests and config checks
scripts/ the one-command check
reports/ the final results and the HTML report (experiments go in reports/scratch/, which Git ignores)
docs/ threat model and research report
Dockerfile runs the full check in a container

The model only suggests tool calls. In secured mode every call goes through the enforcer, which checks the user's role, validates the arguments, tracks whether untrusted content has been read, and strips secrets from output.

# Limitations
29 attacks is still a small set. It doesn't cover long multi-turn attacks or encoded instructions.
Live results can vary between runs even at temperature 0 (TC-034 once gave a different result for the same prompt). The scripted run is the repeatable measure.
Secret redaction is pattern-based and can miss odd formats.
The taint rule is blunt. It treats everything the agent has read as untrusted, which is why two legitimate requests get held.
The approval step is simulated, not a real human workflow. detail in `docs/threat-model.md` and `docs/research-report.md`.

# Next steps

Build a real approval step, add multi-turn attacks, move the rules into OPA policies, and make it easier to plug in a different agent. More models and attack types, possibly generated with Garak or PyRIT, would also widen the coverage
