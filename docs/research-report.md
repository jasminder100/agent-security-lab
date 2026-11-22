# Research Report: AI Agent Security Testing Approaches

Project: AI Agent Security Testing Lab
Document status: Draft for review

## 1. Purpose

This report reviews the main existing approaches to testing the security of AI systems and explains why this project builds a purpose-made test framework for tool-using agents. It covers four references named in the project brief: the OWASP Top 10 for LLM Applications, Garak, PyRIT and the NIST AI Risk Management Framework. It ends with the gaps these approaches leave and how this project addresses them.

## 2. Summary

- The four references do different jobs. OWASP lists the risks, NIST describes how to manage them, and Garak and PyRIT are tools that probe models.
- Garak and PyRIT mainly test the model's responses. They are less suited to checking whether a specific agent, with specific tools and user roles, is protected by server-side controls.
- No single reference gives a repeatable way to compare an agent before and after security controls, using the same tests and an independent pass/fail judgement.
- This project fills that gap with a small framework built around a DataOps Pipeline Assistant. It measures attack success, authorization enforcement, data exposure and false denials, and it can be re-run to catch regressions.
- Garak and PyRIT remain useful as complements. They are good at broad model-level probing, which this framework does not attempt.

## 3. Approaches reviewed

### 3.1 OWASP Top 10 for LLM Applications (2025)

OWASP publishes a ranked list of the most critical security risks for applications built on large language models. The 2025 edition was released in November 2024. The ten entries are:

1. Prompt Injection
2. Sensitive Information Disclosure
3. Supply Chain
4. Data and Model Poisoning
5. Improper Output Handling
6. Excessive Agency
7. System Prompt Leakage
8. Vector and Embedding Weaknesses
9. Misinformation
10. Unbounded Consumption

The 2025 update added system prompt leakage and vector and embedding weaknesses as new entries, and expanded its coverage of excessive agency, which is the risk of giving an LLM too much autonomy or too many permissions. Its mitigation advice includes limiting the model's access to essential operations, requiring human oversight for critical actions, and enforcing security controls independently of the model.

Type: risk catalogue and guidance. It does not execute tests.

Relevance to this project: entries 1, 2, 5 and 6 map directly to the test categories used here. The advice to enforce controls independently of the model is the main design principle of the enforcement layer.

### 3.2 Garak

Garak is an open-source LLM vulnerability scanner maintained by NVIDIA. Its name stands for Generative AI Red-teaming and Assessment Kit. It is a command-line tool that probes a model for problems such as prompt injection, data leakage, jailbreaks, hallucination and toxic output. Its documentation compares it to tools like nmap or Metasploit, but for language models.

It is built from four parts. Generators represent the target model or dialogue system. Probes carry out the attacks. Detectors decide whether an output shows a successful attack. Buffs modify prompts to widen coverage. Each probe sends many prompts and collects several responses per prompt, because model output varies from run to run.

Type: automated model-level scanner.

Strengths: large library of ready-made probes, easy to run against many model types, active development, probes tagged to OWASP categories.

Limits for this project: it is built to examine the model and its dialogue behaviour. It has no built-in concept of a particular agent's user roles, tool permissions or server-side authorization decisions, so it cannot on its own say whether a deployment was blocked by a control or merely declined by the model.

### 3.3 PyRIT

PyRIT (Python Risk Identification Tool) is an open-source framework from Microsoft for red teaming generative AI systems. It was released in February 2024 and grew out of Microsoft's own AI red team work. Its main building blocks are targets (the system under test), converters (transformations such as encoding or translation applied to prompts), scorers (rule-based or LLM-based judges of whether an attack worked) and orchestrators or attack strategies (which run single-turn or multi-turn attacks, including gradual escalation). It also keeps a memory store of results and supports human-led testing through a web interface.

Type: configurable red-teaming framework with adaptive, multi-turn attacks.

Strengths: flexible, supports many target types including custom HTTP endpoints, and supports multi-turn attacks where an attacking model adapts to the responses. It also includes strategies aimed at attacks through external content.

Limits for this project: it needs more setup and coding to use well. Adaptive attacks and LLM-based scoring add model calls and cost, and the quality of the results depends on how well the scorer is tuned. The project brief asks for costs to stay within an agreed budget.

### 3.4 NIST AI Risk Management Framework

The NIST AI RMF 1.0 was published in January 2023 as voluntary guidance. It organises AI risk work into four functions: Govern, Map, Measure and Manage. In July 2024 NIST added a Generative AI Profile (NIST AI 600-1), which lists twelve risks that are unique to or made worse by generative AI and suggests actions for each, tied back to the four functions. NIST has said it is revising the framework, so the content should be checked again before final submission.

Type: governance and risk management framework.

Relevance to this project: this project sits mostly in the Measure function (testing and metrics) and supports Manage (acting on findings). The framework does not prescribe any particular test or tool.

## 4. Comparison

| | OWASP LLM Top 10 | Garak | PyRIT | NIST AI RMF |
|---|---|---|---|---|
| What it is | Risk list | Scanner | Red-teaming framework | Risk management framework |
| Runs tests | No | Yes | Yes | No |
| Main focus | Application risks | Model behaviour | Model and system behaviour | Organisational process |
| Multi-turn / adaptive attacks | Not applicable | Some adaptive probes | Yes | Not applicable |
| Understands user roles and tool permissions | Describes the risk only | No | Only if built by the user | No |
| Separates model refusal from control enforcement | No | No | Only if built by the user | No |
| Baseline vs secured comparison | No | Not built in | Not built in | Not applicable |
| Effort to adopt | Low | Low to medium | Medium to high | Medium |
| Cost of running | None | Model calls | Model calls, often several per turn | None |

## 5. Gaps

1. **Model testing is not agent testing.** The main risk with a tool-using agent is what it does, not only what it says. A deployment triggered by the wrong role matters more than an offensive sentence.
2. **Refusal and enforcement look the same.** If an attack fails, the tools above generally cannot tell whether the model chose to refuse or a server-side control stopped it. The first is unreliable. The second can be audited.
3. **No standard before-and-after comparison.** Teams need to show that a control made a measurable difference, using identical tests.
4. **Self-grading risk.** If the code under test also decides whether a test passed, errors can hide. An independent answer key is needed.
5. **Regression detection.** After any change, teams need a pass/fail gate that fails the build when a control has been weakened.
6. **Cost and repeatability.** LLM output varies and live testing costs money. A deterministic scripted mode is needed alongside live runs.

## 6. How this project responds

| Gap | What the project does |
|---|---|
| Agent behaviour | Tests a sample DataOps Pipeline Assistant with mock tools and three roles (viewer, engineer, admin) |
| Refusal vs enforcement | Records the enforcer's decision for each tool call, separate from the model's reply |
| Before and after | Runs the same 38 test cases in baseline and secured modes |
| Self-grading | Uses a separate oracle module as the answer key |
| Regression | Command-line thresholds that exit with a failure code, plus a drill with deliberately weakened policies that the framework caught |
| Cost and repeatability | Scripted mode is deterministic and free, live mode uses the model, and results are repeated three times |

## 7. Selection rationale

The project uses OWASP as its threat vocabulary and NIST as its framing for measurement and management. It builds its own runner because the questions it needs to answer, such as whether a given role could trigger a given tool and whether the control or the model prevented it, are specific to one agent's design.

Garak and PyRIT were not adopted as the core engine, for three reasons: their scoring is centred on model output rather than on tool and authorization outcomes, they would add setup effort and model cost within a fixed budget, and a small custom runner is easier to explain, reproduce and run in CI.

They are good candidates for future work. A sensible next step would be to use Garak probes or PyRIT attack strategies to generate a wider set of attack prompts, then feed them through this framework's enforcement and scoring.

## 8. Limitations of this review

- The review is based on public documentation and project pages and was not a hands-on evaluation of Garak or PyRIT.
- Both tools and the NIST framework are changing. Details such as version numbers and the list of probes should be rechecked before submission.
- Capability comparisons are generalisations. Either tool could be extended to cover agent-level checks with enough custom work.

## 9. Sources

- OWASP Top 10 for LLM Applications 2025, OWASP GenAI Security Project: genai.owasp.org
- Garak, NVIDIA: github.com/NVIDIA/garak
- Derczynski et al., "garak: A Framework for Security Probing Large Language Models": arxiv.org/abs/2406.11036
- PyRIT, Microsoft: microsoft.github.io/PyRIT
- Microsoft Security Blog, "Announcing Microsoft's open automation framework to red team generative AI systems," February 2024
- NIST AI Risk Management Framework 1.0 (NIST AI 100-1), January 2023
- NIST AI 600-1, Generative AI Profile, July 2024: doi.org/10.6028/NIST.AI.600-1
