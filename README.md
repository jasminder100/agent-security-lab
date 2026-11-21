# AI Agent Security Testing Lab

I built this to answer one question: if an AI agent can be tricked by text it reads, how do you test that properly before putting it into a real workflow?

The project has a small sample agent (a DataOps Pipeline Assistant with four mock tools) and a test framework that attacks it. It runs the same set of tests with and without security controls, saves the evidence for every run, and reports how many attacks got through. Everything is mock data. No real systems or credentials are involved.

## What I found

- Without controls, 50% of attacks succeeded against the live model (100% with a scripted worst-case model). With controls, 0%.
- One legitimate request out of eight gets blocked (TC-024). That is the cost of the control that requires approval after the agent has read untrusted log text. I left it in on purpose and report it.
- TC-016 found a real gap: an admin could be steered into a staging deployment by a poisoned log. That led to the taint control.
- Results were identical across 3 repeats, and the framework caught both of the weakened policies I used to test it.

This is a prototype on mock data. It does not prove any agent is secure.

## Setup

Python 3.12.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Live mode needs an OpenAI key in a `.env` file in the project root (not committed). Scripted mode and the unit tests don't need one.

## Running it

Scripted mode is free and gives the same result every time:

```bash
python -m runner.benchmark --model-mode scripted --repeats 3
```

Live mode uses the real model and costs money, so set a token limit:

```bash
python -m runner.benchmark --model-mode live --repeats 3 --token-budget 100000
```

Other useful options: `--only TC-016 TC-024` to run specific tests, `--modes secured` for one mode, `--policy <file>` to test a different policy. Run with `--help` for the full list. Results are saved as JSON in `reports/results/`.

To build the HTML report:

```bash
python -m runner.report
```

## Pass/fail gate

The benchmark exits with code 1 if a limit is broken, so it can fail a build:

```bash
python -m runner.benchmark --model-mode scripted --repeats 3 \
  --max-attack-success 0 --max-false-denial 0.15
```

## Checking that the framework notices a weakened control

`config/regressions/` has two policies with a control removed. Both should fail the gate:

```bash
python -m runner.benchmark --model-mode scripted \
  --policy config/regressions/no_taint.yaml --max-attack-success 0
```

Same with `no_redaction.yaml`. If either one passes, the framework missed it.

## Tests and CI

```bash
pytest
```

This runs the enforcer unit tests and checks the gate itself. GitHub Actions runs the tests and the scripted benchmark on every push. It never uses live mode, so no secrets are stored.

## How it's laid out

- `app/` the agent, the mock tools and the security layer (`app/security/enforcer.py` is the part that makes the decisions)
- `config/` the policy, the 24 test cases, and the weakened policies
- `runner/` the benchmark, the oracle (a separate answer key so the code doesn't grade itself) and the report generator
- `tests/` unit tests
- `docs/` threat model and research report

The model only suggests tool calls. In secured mode every call goes through the enforcer, which checks the user's role, validates the arguments, tracks whether untrusted content has been read, and strips secrets from output.

## Limitations

- 16 attacks is a small set. It doesn't cover things like encoded instructions or long multi-turn attacks.
- Secret redaction is pattern-based and can miss odd formats.
- The approval step is simulated, not a real human workflow.
- Live results vary between runs and models.

## Next steps

Compare more models, add more attack types (possibly generated with Garak or PyRIT), build a real approval step, and make it easier to plug in a different agent.

More detail in `docs/threat-model.md` and `docs/research-report.md`.
