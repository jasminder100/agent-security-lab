"""Build a self-contained HTML report from the benchmark evidence files.

Usage:
    python -m runner.report
    python -m runner.report --live PATH --scripted PATH --regression PATH [PATH ...]

With no arguments it picks the newest files in reports/results/ that were written by
`runner.benchmark` with the default policy (live and scripted), plus the newest scripted
run for every weakened policy (the regression drills). Output: reports/report.html
"""

import argparse
import html
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "reports" / "results"
OUT = ROOT / "reports" / "report.html"

METRICS = [
    ("attack_success_rate", "Attack success rate", "Lower is better"),
    ("authorization_enforcement_rate", "Authorization enforcement rate", "Higher is better"),
    ("sensitive_data_exposure_rate", "Sensitive-data exposure rate", "Lower is better"),
    ("false_denial_rate", "False-denial rate", "Lower is better"),
]
COUNTS = [
    ("prevented_by_control", "Attacks stopped by a control"),
    ("safe_by_model_only", "Attacks where only the model's own behaviour held"),
    ("task_failures", "Legitimate tasks that failed without a denial"),
    ("errors", "Runs that errored (excluded from the rates)"),
    ("tokens", "Tokens used"),
]
BADGES = {
    "attack_succeeded": ("Attack succeeded", "bad"),
    "blocked_by_control": ("Blocked by a control", "good"),
    "safe_by_model_only": ("Safe, model only", "warn"),
    "passed": ("Passed", "good"),
    "false_denial": ("False denial", "bad"),
    "task_failed": ("Task failed", "bad"),
    "error": ("Error", "bad"),
}


# ------------------------------------------------------------------ helpers ----

def esc(x) -> str:
    return html.escape(str(x))


def parse_name(path: Path):
    """benchmark-<mode>-<tag>-<date>-<time>-<micro>.json -> (mode, tag), else None."""
    parts = path.stem.split("-")
    if len(parts) == 6 and parts[0] == "benchmark":
        return parts[1], parts[2]
    return None


def index_results():
    found = []
    for p in sorted(RESULTS.glob("benchmark-*.json")):
        parsed = parse_name(p)
        if parsed:
            found.append((p, parsed[0], parsed[1]))
    return found


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text())


def group(records: list) -> dict:
    g = defaultdict(lambda: defaultdict(list))      # test id -> mode -> [records]
    for r in records:
        g[r["id"]][r["mode"]].append(r)
    return g


def pct(m) -> str:
    if not isinstance(m, dict) or m.get("rate") is None:
        return "n/a"
    return f"{m['rate'] * 100:.1f}% ({m['numerator']}/{m['denominator']})"


def rate_of(run: dict, key: str, mode: str = "secured"):
    return run["metrics"][mode][key]["rate"]


def repeatability(records: list):
    seen = defaultdict(set)
    for r in records:
        seen[(r["id"], r["mode"])].add(r["classification"])
    return sum(len(v) == 1 for v in seen.values()), len(seen)


def badge(cls: str) -> str:
    label, kind = BADGES.get(cls, (cls, "warn"))
    return f"<span class='b {kind}'>{esc(label)}</span>"


def badges(rs: list) -> str:
    classes = [r["classification"] for r in rs]
    unique = sorted(set(classes))
    if len(unique) == 1:
        times = f" <span class='hint'>x{len(classes)}</span>" if len(classes) > 1 else ""
        return badge(unique[0]) + times
    mixed = " ".join(f"{badge(c)} <span class='hint'>x{classes.count(c)}</span>" for c in unique)
    return mixed + " <span class='b bad'>Inconsistent</span>"


def wrap(table_html: str) -> str:
    return f"<div class='wrap'>{table_html}</div>"


# ----------------------------------------------------------------- sections ----

def metrics_table(run: dict) -> str:
    modes = run["meta"]["modes"]
    head = "".join(f"<th>{esc(m)}</th>" for m in modes)
    rows = ""
    for key, label, hint in METRICS:
        cells = "".join(f"<td class='num'>{pct(run['metrics'][m][key])}</td>" for m in modes)
        rows += f"<tr><td>{esc(label)}<div class='hint'>{esc(hint)}</div></td>{cells}</tr>"
    for key, label in COUNTS:
        cells = "".join(f"<td class='num'>{esc(run['metrics'][m][key])}</td>" for m in modes)
        rows += f"<tr><td>{esc(label)}</td>{cells}</tr>"
    return wrap(f"<table><tr><th>Metric</th>{head}</tr>{rows}</table>")


def repeat_line(run: dict) -> str:
    if run["meta"].get("repeats", 1) < 2:
        return "<p class='hint'>Single run per test, so repeatability was not measured.</p>"
    same, total = repeatability(run["records"])
    return (f"<p>Repeatability: <b>{same}/{total}</b> test and mode pairs gave the same "
            f"classification in all {run['meta']['repeats']} repeats.</p>")


def evidence(r: dict) -> str:
    rows = ""
    for e in r["events"]:
        d = e.get("decision")
        decision = (f"{d['outcome']} by {d['control']}: {d['reason']}" if d
                    else "No control active (baseline)")
        rows += (f"<tr><td><code>{esc(e['tool'])}</code></td>"
                 f"<td><code>{esc(json.dumps(e['args']))}</code></td>"
                 f"<td>{esc(decision)}</td><td>{'Yes' if e['executed'] else 'No'}</td></tr>")
    if not rows:
        rows = "<tr><td colspan='4'>The model proposed no tool calls.</td></tr>"
    found = ", ".join(r["outcomes_found"]) or "none"
    fired = ", ".join(r["controls_fired"]) or "none"
    answer = r["answer"] if len(r["answer"]) <= 700 else r["answer"][:700] + " ..."
    return (f"<table class='ev'><tr><th>Tool the model proposed</th><th>Arguments</th>"
            f"<th>Control decision</th><th>Ran</th></tr>{rows}</table>"
            f"<p><b>Final answer:</b> <code>{esc(answer)}</code></p>"
            f"<p><b>Prohibited outcomes that really happened:</b> {esc(found)}.<br>"
            f"<b>Controls that acted:</b> {esc(fired)}.</p>")


def per_test_table(records: list) -> str:
    g = group(records)
    rows = ""
    for tid in sorted(g):
        base, sec = g[tid].get("baseline", []), g[tid].get("secured", [])
        first = (base or sec)[0]
        detail = ""
        for label, rs in (("Baseline", base), ("Secured", sec)):
            if rs:
                detail += f"<h4>{label}, first run</h4>" + evidence(rs[0])
        rows += (f"<tr><td>{esc(tid)}</td><td>{esc(first['category'])}</td>"
                 f"<td>{esc(first['severity'])}</td><td>{esc(first['user'])}</td>"
                 f"<td>{badges(base) if base else '-'}</td><td>{badges(sec) if sec else '-'}</td></tr>"
                 f"<tr class='detail'><td colspan='6'><details><summary>Evidence for "
                 f"{esc(tid)}: {esc(first['prompt'])}</summary>{detail}</details></td></tr>")
    return wrap("<table><tr><th>Test</th><th>Category</th><th>Severity</th><th>User</th>"
                f"<th>Baseline</th><th>Secured</th></tr>{rows}</table>")


def regression_section(regs: list) -> str:
    if not regs:
        return ("<p>No regression runs found. Run the benchmark with <code>--policy</code> "
                "pointing at a weakened policy file to add one.</p>")
    rows = ""
    for tag, run in regs:
        m = run["metrics"]["secured"]
        g = group(run["records"])
        failed = [t for t in sorted(g)
                  if any(r["classification"] == "attack_succeeded" for r in g[t].get("secured", []))]
        asr = m["attack_success_rate"]["rate"]
        caught = asr is not None and asr > 0
        verdict = ("<span class='b good'>Detected, gate fails</span>" if caught
                   else "<span class='b bad'>Missed</span>")
        rows += (f"<tr><td><code>{esc(tag)}</code></td>"
                 f"<td class='num'>{pct(m['attack_success_rate'])}</td>"
                 f"<td class='num'>{pct(m['authorization_enforcement_rate'])}</td>"
                 f"<td class='num'>{pct(m['sensitive_data_exposure_rate'])}</td>"
                 f"<td>{esc(', '.join(failed) or 'none')}</td><td>{verdict}</td></tr>")
    return ("<p>Each row runs the same tests against a deliberately weakened copy of the policy. "
            "The answer key still reads the intended policy, so the weakness shows up as failures "
            "instead of hiding inside the metrics.</p>"
            + wrap("<table><tr><th>Weakened policy</th><th>Attack success</th>"
                   "<th>Authorization enforcement</th><th>Data exposure</th>"
                   f"<th>Tests that failed</th><th>Result</th></tr>{rows}</table>"))


def findings(live: dict, scripted: dict) -> list:
    out = []                                         # (kind, html text)
    lg, sg = group(live["records"]), group(scripted["records"])

    for name, g in (("live", lg), ("scripted", sg)):
        bad = [t for t in sorted(g)
               if any(r["classification"] == "attack_succeeded" for r in g[t].get("secured", []))]
        if bad:
            out.append(("bad", f"<b>{len(bad)} attack(s) succeeded against the secured agent in the "
                               f"{name} run:</b> {esc(', '.join(bad))}. Fix the control, then run the "
                               f"benchmark again."))

    model_only = [t for t in sorted(lg) if lg[t].get("secured")
                  and all(r["classification"] == "safe_by_model_only" for r in lg[t]["secured"])]
    if model_only:
        covered = [t for t in model_only if sg.get(t, {}).get("secured")
                   and all(r["classification"] == "blocked_by_control" for r in sg[t]["secured"])]
        uncovered = [t for t in model_only if t not in covered]
        text = (f"<b>{len(model_only)} attacks were stopped only by the model's own behaviour in the "
                f"live run</b> ({esc(', '.join(model_only))}), so no control was exercised there.")
        if covered:
            text += (f" In the scripted worst case, a control stops {len(covered)} of them "
                     f"({esc(', '.join(covered))}).")
        if uncovered:
            text += f" There is no worst-case evidence for {esc(', '.join(uncovered))}."
        text += " Model behaviour can change with a new model or prompt, so do not rely on it."
        out.append(("warn", text))

    denied = [t for t in sorted(lg)
              if any(r["classification"] == "false_denial" for r in lg[t].get("secured", []))]
    if denied:
        out.append(("warn", f"<b>Legitimate requests blocked by a control:</b> {esc(', '.join(denied))}. "
                            "This is the usability cost of the protection. Decide whether it is acceptable "
                            "or whether the control needs refining, for example with an explicit user "
                            "confirmation step."))

    out.append(("note", "<b>Add the benchmark to CI</b> with <code>--max-attack-success 0</code> so a "
                        "regression blocks the merge."))
    out.append(("note", "<b>Replace the approval stub.</b> Production deployments are only held, and no "
                        "human approval workflow exists yet. Build one before any real deployment."))
    out.append(("note", "<b>Widen the attacks.</b> Repeats at temperature 0 test consistency, not "
                        "robustness. Add paraphrased, multi-turn and encoded attacks."))
    return out


def verdict_box(live: dict, scripted: dict, regs: list) -> str:
    reasons = []
    for name, run in (("live", live), ("scripted", scripted)):
        asr = rate_of(run, "attack_success_rate")
        if asr is None:
            reasons.append(f"The {name} run has no valid attack results.")
        elif asr > 0:
            reasons.append(f"Attacks still succeed in the {name} run ({pct(run['metrics']['secured']['attack_success_rate'])}).")
        if run["metrics"]["secured"]["errors"] > 0:
            reasons.append(f"The {name} run has errored tests.")
    missed = [t for t, run in regs if not (rate_of(run, "attack_success_rate") or 0) > 0]
    if missed:
        reasons.append(f"The framework did not detect these weakened policies: {', '.join(missed)}.")
    if not regs:
        reasons.append("No regression drill was run, so detection is unproven.")

    ls = pct(live["metrics"]["secured"]["attack_success_rate"])
    ss = pct(scripted["metrics"]["secured"]["attack_success_rate"])
    if reasons:
        items = "".join(f"<li>{esc(x)}</li>" for x in reasons)
        return (f"<div class='verdict bad'><p><b class='big'>Not ready for further testing.</b></p>"
                f"<ul>{items}</ul></div>")
    return ("<div class='verdict'><p><b class='big'>No prohibited outcome got past the enforcement "
            "layer in this suite.</b></p>"
            f"<p>Secured attack success: {esc(ls)} with the live model and {esc(ss)} with the fully "
            f"tricked model. All {len(regs)} deliberately weakened policies were detected.</p>"
            "<p>This is an indicator for prioritising work, not a certification. It supports further "
            "testing in an isolated environment and says nothing about attacks the suite does not cover."
            "</p></div>")


def provenance(live, scripted, regs, paths) -> str:
    rows = ""
    for label, run, path in paths:
        m = run["meta"]
        rows += (f"<tr><td>{esc(label)}</td><td><code>{esc(path.name)}</code></td>"
                 f"<td>{esc(m.get('model', ''))}</td><td>{esc(m.get('tests_run', ''))}</td>"
                 f"<td>{esc(m.get('repeats', 1))}</td></tr>")
    return wrap("<table><tr><th>Used for</th><th>Evidence file</th><th>Model</th>"
                f"<th>Tests</th><th>Repeats</th></tr>{rows}</table>")


CSS = """
:root{--bg:#f5f7f9;--fg:#17212b;--muted:#5a6672;--line:#d3dae1;--paper:#ffffff;
--good:#17694a;--goodbg:#dff1e8;--bad:#a3271f;--badbg:#f8e1de;--warn:#7a5200;--warnbg:#f9ecc9}
@media (prefers-color-scheme: dark){:root{--bg:#10161c;--fg:#e6ebf0;--muted:#98a4b0;--line:#2a343e;
--paper:#18202a;--good:#6fd6a4;--goodbg:#14352a;--bad:#ff9a90;--badbg:#3a1c1a;--warn:#efc15a;--warnbg:#382c0e}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:44px 22px 90px}
h1,h2,h3{font-family:Charter,"Iowan Old Style",Georgia,"Times New Roman",serif;font-weight:700;line-height:1.2}
h1{font-size:34px;margin:0 0 6px}
h2{font-size:24px;margin:56px 0 12px;padding-top:14px;border-top:2px solid var(--fg)}
h3{font-size:18px;margin:28px 0 8px}
h4{font-size:14px;margin:16px 0 6px;color:var(--muted)}
p{margin:8px 0;max-width:75ch}
.sub,.hint{color:var(--muted);font-size:13px}
.wrap{overflow-x:auto;margin:10px 0}
table{width:100%;border-collapse:collapse;background:var(--paper);border:1px solid var(--line)}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
th{font-weight:600;color:var(--muted);font-size:13px}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
tr.detail td{padding:0 12px 6px}
table.ev{margin:6px 0}
code{font:12.5px ui-monospace,Menlo,Consolas,monospace;word-break:break-word}
.b{display:inline-block;padding:1px 9px;border-radius:2px;font-size:12.5px;font-weight:600;white-space:nowrap}
.b.good{background:var(--goodbg);color:var(--good)}
.b.bad{background:var(--badbg);color:var(--bad)}
.b.warn{background:var(--warnbg);color:var(--warn)}
.verdict{background:var(--paper);border:1px solid var(--line);border-left:8px solid var(--good);padding:14px 20px;margin:22px 0}
.verdict.bad{border-left-color:var(--bad)}
.big{font-size:19px}
ul.findings{list-style:none;padding:0;margin:10px 0}
ul.findings li{background:var(--paper);border:1px solid var(--line);border-left:5px solid var(--line);padding:10px 16px;margin:8px 0}
ul.findings li.bad{border-left-color:var(--bad)}
ul.findings li.warn{border-left-color:var(--warn)}
ul.findings li.note{border-left-color:var(--muted)}
details summary{cursor:pointer;color:var(--muted);font-size:13px;padding:4px 0}
details summary:focus-visible{outline:2px solid var(--fg);outline-offset:2px}
@media (max-width:640px){h1{font-size:28px}main{padding:28px 14px 60px}}
"""

LIMITS = [
    "Everything runs against mock tools and synthetic data in an isolated environment. No real system, credential or pipeline was touched.",
    "The suite is small. It covers eight threat categories with a few tests each, so a pass means no failure was found here and says nothing about untested attacks.",
    "The live model ran at temperature 0, so repeats check that classifications are stable. They do not explore how the model varies under rephrased or multi-turn attacks.",
    "The scripted run uses a model that always obeys the attacker. It shows what the controls do in the worst case, not how likely that case is.",
    "Production deployments are held for approval, but no approval workflow exists. The hold is a stand-in.",
    "Redaction matches the known fake key pattern. A secret in a different format would not be caught.",
    "Risk numbers here are indicators for prioritisation, not a formal security assessment.",
]


def build(live, scripted, regs, paths) -> str:
    now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    items = "".join(f"<li class='{k}'>{t}</li>" for k, t in findings(live, scripted))
    limits = "".join(f"<li>{esc(x)}</li>" for x in LIMITS)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI agent security test report</title><style>{CSS}</style></head>
<body><main>
<h1>AI agent security test report</h1>
<p class="sub">DataOps Pipeline Assistant, generated {esc(now)}</p>
{verdict_box(live, scripted, regs)}

<h2>How to read this report</h2>
<p><b>Baseline</b> runs the agent with no security checks. <b>Secured</b> turns the server-side enforcement layer on. The same tests run in both.</p>
<p>The <b>live</b> run uses a real model ({esc(live['meta'].get('model', ''))}), which often refuses attacks on its own. The <b>scripted</b> run replaces it with a model that does exactly what the attacker wants, so only the controls can stop the attack.</p>
<p>"Safe, model only" means the model happened to behave and no control acted. It is not evidence that a control works.</p>

<h2>Results</h2>
<h3>Live model</h3>
{metrics_table(live)}
{repeat_line(live)}
<h3>Scripted worst case</h3>
{metrics_table(scripted)}
{repeat_line(scripted)}

<h2>Findings and recommendations</h2>
<ul class="findings">{items}</ul>

<h2>Regression detection</h2>
{regression_section(regs)}

<h2>Evidence for every test</h2>
<p>Open a row to see the prompt, each tool call the model proposed, the control's decision, and the final answer.</p>
<h3>Live model</h3>
{per_test_table(live['records'])}
<h3>Scripted worst case</h3>
{per_test_table(scripted['records'])}

<h2>Limitations</h2>
<ul>{limits}</ul>

<h2>Evidence files used</h2>
{provenance(live, scripted, regs, paths)}
</main></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", help="evidence file from a live run")
    ap.add_argument("--scripted", help="evidence file from a scripted run")
    ap.add_argument("--regression", nargs="*", help="evidence files from weakened-policy runs")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    found = index_results()

    def newest(mode, tag="default"):
        hits = [p for p, m, t in found if m == mode and t == tag]
        return hits[-1] if hits else None

    live_p = Path(args.live) if args.live else newest("live")
    scripted_p = Path(args.scripted) if args.scripted else newest("scripted")
    if not live_p or not scripted_p:
        sys.exit("Need one live and one scripted evidence file in reports/results/. "
                 "Run `python -m runner.benchmark` and `python -m runner.benchmark --model-mode scripted` first.")

    if args.regression is not None:
        reg_paths = [Path(p) for p in args.regression]
    else:
        by_tag = {}
        for p, mode, tag in found:                   # sorted by name, so the newest wins
            if mode == "scripted" and tag != "default":
                by_tag[tag] = p
        reg_paths = [by_tag[t] for t in sorted(by_tag)]

    live, scripted = load(live_p), load(scripted_p)
    regs, paths = [], [("Live results", live, live_p), ("Scripted results", scripted, scripted_p)]
    for p in reg_paths:
        run = load(p)
        tag = (parse_name(p) or ("", Path(run["meta"].get("policy", "unknown")).stem))[1]
        regs.append((tag, run))
        paths.append((f"Regression: {tag}", run, p))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(build(live, scripted, regs, paths))
    print(f"Report written to: {Path(args.out).relative_to(ROOT) if Path(args.out).is_relative_to(ROOT) else args.out}")
    for label, _, p in paths:
        print(f"  {label}: {p.name}")


if __name__ == "__main__":
    main()