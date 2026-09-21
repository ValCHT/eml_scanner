# TICKET-19E — Architectural and Model Benchmark

## STATUS / GATE

G8-E

## OBJECTIVE

Mesurer les architectures T19 sans retoucher leur comportement, tester l’utilité du complexity gate, puis comparer un nombre borné de moteurs compatibles une fois l’architecture agentique gelée.

PASS signifie que le protocole a été exécuté correctement, pas que l’architecture agentique gagne.

## ARCHITECTURAL AUTHORITY / OVERRIDES

Aucun changement runtime après création du lock expérimental et début des mesures, sauf BUG FIX formellement enregistré, corrigé avant re-freeze et rerun des variantes concernées.

Aucune variante n’est retunée après lecture des résultats.

T18 est une baseline historique gelée ; gold_test n’est pas utilisé pour sélectionner architecture, modèle, prompt, budget, outil ou seuil T19.

## PRECONDITIONS / DEPENDENCIES

- G8-D PASS and receipt verifies.
- TICKET-19D DONE.
- T14 evaluator and metrics implementation present and compliant with its ticket.
- T13 Gold loader present.
- T18 result/artifacts present and frozen.
- Visual-79 present and integrity-checked if vision was KEEP.
- T15/T16 KEEP/NO decisions recorded.
- No runtime T19A–D file has uncommitted modification at benchmark lock creation.

## REUSE FROM PREVIOUS TICKETS

Reuse:

- T13 Gold loader and family/hash protections.
- T14 metrics/evaluator/cost/latency accounting.
- T15 RAG implementation if KEEP.
- T16 vision/QR implementation if KEEP.
- T17 failure-mode taxonomy.
- T18 historical baseline artifacts.
- T19A–D runtime exactly as frozen.

Do not create a second classification metric engine.

## MUST NOT MODIFY

After `configs/t19_experiment_lock.json` is created for the first live architecture run:

- all runtime source from T19A–D ;
- `src/graph.py` ;
- `src/gate.py` ;
- `src/policy.py` ;
- `src/verify.py` ;
- all V1/T19 prompts ;
- all tool adapters ;
- `configs/gate.yaml` ;
- `configs/policy.yaml` ;
- `configs/investigation.yaml` ;
- Gold labels ;
- `gold_test` ;
- T18 artifacts.

A separately documented BUG FIX requires invalidating the current experiment lock, fixing the bug, rerunning deterministic validation, producing a new lock, and rerunning every affected live variant. It must not be justified by score improvement.

## IN SCOPE

- Architecture benchmark on gold_dev.
- Fixed vs agentic.
- Agentic Core vs Context vs OSINT+.
- RAG/vision ablations when their capabilities are KEEP.
- Gate vs gate bypass.
- Agent-specific metrics.
- Architecture selection using pre-registered deterministic criteria.
- Small post-selection model benchmark.
- Final T19 decision report.

## OUT OF SCOPE

- Runtime redesign.
- Prompt retuning.
- Gate threshold retuning.
- Policy retuning.
- New tool/provider.
- New dataset acquisition.
- gold_test-based selection.
- Full Cartesian model × architecture × dataset search.
- Jev in the agentic model-selection phase.
- gpt-oss-20b quality selection.

## FILES ALLOWED

Existing:

- `src/metrics.py`
- `scripts/evaluate.py`
- `docs/evaluation.md`
- `configs/experiment_lock.json`

New files listed below.

No T19A–D runtime source file is allowed unless a BUG FIX process is explicitly invoked before re-freezing.

## NEW FILES

- `src/agentic_metrics.py`
- `scripts/evaluate_agentic.py`
- `scripts/validate_agentic_eval.py`
- `tests/test_agentic_metrics.py`
- `tests/test_agentic_evaluation.py`
- `configs/t19_experiment_lock.json`
- `docs/t19_results.md`

## EXISTING INTERFACES REUSED

From T14:

```python
evaluate(
    rows: list[GoldRecord],
    reports: list[TriageReport],
) -> Metrics
```

and the actual implemented paired-comparison interface corresponding to contracted `compare_internal_final(...)`.

If T14 does not expose the contracted evaluation behavior required here, T19E is BLOCKED until T14 compliance is restored. T19E must not create a second replacement metric engine.

## NEW INTERFACES / EXACT SIGNATURES

In `src/agentic_metrics.py`:

```python
def evaluate_agentic(
    rows: list[GoldRecord],
    reports: list[TriageReport],
    investigations: list[InvestigationAudit],
) -> AgenticMetrics:
    ...


def compare_agentic_runs(
    baseline: Sequence[EvaluationRow],
    candidate: Sequence[EvaluationRow],
) -> AgenticComparison:
    ...


def compute_missed_investigation(
    normal: Sequence[EvaluationRow],
    bypass: Sequence[EvaluationRow],
) -> MissedInvestigationMetrics:
    ...
```

Define strict models:

```python
class AgenticMetrics(_Strict):
    sample_count: int
    complex_count: int
    investigation_turns: int
    executed_tool_calls: int
    denied_calls: int
    duplicate_proposals: int
    calls_per_email: FiniteNumber | None
    calls_per_complex_email: FiniteNumber | None
    evidence_generated_per_call: FiniteNumber | None
    useful_tool_calls: int
    useful_tool_call_rate: FiniteNumber | None
    decision_changing_tool_calls: int
    decision_changing_tool_call_rate: FiniteNumber | None
    stopping_reason_counts: dict[str, int]
    investigator_llm_latency_ms_total: FiniteNumber
    external_tool_latency_ms_total: FiniteNumber
    investigation_cost_usd: FiniteNumber | None


class AgenticComparison(_Strict):
    baseline_variant: str
    candidate_variant: str
    paired_sample_count: int
    wrong_to_right: int
    right_to_wrong: int
    right_to_right: int
    wrong_to_wrong: int
    net_corrections: int
    supported_macro_f1_baseline: FiniteNumber | None
    supported_macro_f1_candidate: FiniteNumber | None
    supported_macro_f1_delta: FiniteNumber | None
    malicious_auto_baseline: int
    malicious_auto_candidate: int
    mean_variable_cost_ratio: FiniteNumber | None
    p95_latency_ratio: FiniteNumber | None
    decision: Literal["KEEP", "RETAIN_BASELINE", "INCONCLUSIVE"]


class MissedInvestigationMetrics(_Strict):
    simple_total: int
    corrected_by_forced_investigation: int
    degraded_by_forced_investigation: int
    unchanged: int
    critical_gate_miss: int
    missed_investigation_rate: FiniteNumber | None
    gate_decision: Literal["KEEP", "BYPASS", "INCONCLUSIVE"]
```

Use the repository’s existing strict-model base and finite-number type rather than duplicating them.

In `scripts/evaluate_agentic.py`, CLI subcommands are exactly:

```text
lock
run
select-architecture
run-model
```

No fifth subcommand.

## STATE / DATA CONTRACTS

Metric definitions are exact.

### investigation_turns

Number of investigator LLM responses for included evaluation samples.

### executed_tool_calls

Count of allowed actions actually passed to a tool executor.

`finish_investigation` excluded.

### denied_calls

Number of validator denial events.

A multiple-call model response counts as one denial event.

### duplicate_proposals

Number of denials with `DENY_DUPLICATE`.

### calls_per_email

```text
sum(executed_tool_calls) / N
```

Null if `N == 0`.

### calls_per_complex_email

```text
executed calls on gate=COMPLEX / N_complex
```

Null if `N_complex == 0`.

### evidence_generated_per_call

```text
new accepted Evidence IDs / executed external tool calls
```

RAG/vision are excluded from this denominator because they do not necessarily create Evidence.

Null if denominator is zero.

### useful_tool_call

An executed action is useful if at least one of the following deterministic conditions is true:

1. it adds at least one new accepted Evidence ID ;
2. it adds at least one new accepted derived Observable ID ;
3. RAG returns at least one allowed RagCase ;
4. a vision action successfully supplies the selected visual to the next investigator request.

No human judgment field.

### useful_tool_call_rate

```text
useful executed actions / all executed actions
```

Null if no executed actions.

### decision_changing_call

An executed external action qualifies only if:

1. it generated an Evidence ID later cited by FINAL as decisive/cited evidence under the existing FINAL/evidence audit contract ; and
2. FINAL verdict OR policy action differs from the INTERNAL/simple reference.

This is explicitly an attribution proxy, not causal proof.

RAG/vision calls that create no Evidence are therefore not counted by this metric; their value is measured through variant-level ablations.

### decision_changing_tool_call_rate

```text
decision_changing_calls / executed calls
```

Null if no executed calls.

### stopping_reason_counts

Exact count by `InvestigationStopReason`.

## CONTROL FLOW

Architecture phase uses only `gold_dev`.

Exact order:

```text
V0 fixed V1 dev rerun
↓
V1 agentic-core
↓
V2 agentic-context
↓
V3 agentic-osint-plus
↓
deterministic architecture selection
↓
V4 best selected agentic architecture with gate bypass
↓
deterministic gate decision
↓
model comparison on frozen selected architecture/gate mode
```

T18/gold_test is never consulted to make these choices.

Variant definitions:

### V0 — fixed

Frozen V1 graph/runtime.

### V1 — agentic-core

T19B graph, actions:

- VirusTotal
- OpenCTI
- urlscan
- finish

No RAG/vision/OSINT+.

### V2 — agentic-context

T19C graph/action set:

- V1 actions
- retained RAG
- retained vision
- QR remains deterministic pre-gate

No OSINT+.

If both RAG and vision outcomes are NO, V2 is recorded as `NOT_APPLICABLE` and is not treated as a separate candidate; V1 remains comparator for V3.

### V3 — agentic-osint-plus

T19D full retained action set.

### V4 — gate-bypass

Exactly the selected best agentic architecture, but evaluator forces every dev email through investigator.

The bypass exists only in the evaluation harness and MUST NOT mutate `decide_gate()`.

## CONFIGURATION / DEFAULT VALUES

Before first live architecture run, create `configs/t19_experiment_lock.json`.

It must contain/hash at minimum:

- repository commit ;
- `prompts/internal_assessment.txt` SHA-256 ;
- `prompts/final_assessment.txt` SHA-256 ;
- `prompts/investigator.txt` SHA-256 ;
- assessment schema SHA-256 ;
- investigation schema SHA-256 ;
- gate config SHA-256 ;
- policy config SHA-256 ;
- investigation config SHA-256 ;
- exact tool-schema SHA-256 ;
- gold_dev SHA-256 ;
- model ID ;
- provider/base endpoint identity without secret ;
- variant definitions ;
- metric-definition version ;
- architecture-selection rules ;
- gate-selection rules ;
- run seed if the existing evaluator requires one.

Lock is immutable after first live run.

### Architecture selection rules

Apply sequentially:

```text
V1 vs V0
V2 vs current winner, if V2 applicable
V3 vs current winner
```

A candidate may replace comparator only if all applicable conditions pass.

#### Hard safety

```text
candidate_malicious_AUTO - comparator_malicious_AUTO <= 0
```

Equivalent requirement: no new malicious AUTO case.

#### Material quality gain

At least one:

```text
net_corrections = wrong_to_right - right_to_wrong >= 3
```

OR:

```text
supported-class Macro-F1 delta >= +0.02
```

Supported-class Macro-F1 means macro average over reference classes with support > 0 in the paired evaluation set.

Six-class Macro-F1 remains `NON_CONCLUSIVE` whenever any class has support 0.

#### Critical non-regression

For each class:

```text
phishing
spear_phishing
fraude
```

candidate correct-count drop relative to comparator must be <= 1.

If a listed class has zero support in the paired set, mark that class `NON_ESTIMABLE` and do not treat the absent support as passing evidence.

#### Efficiency guard

Both required:

```text
mean variable cost <= 2.0 × comparator
p95 latency <= 2.0 × comparator
```

Unknown/incomplete cost or latency → replacement decision `INCONCLUSIVE`.

#### Efficiency-only KEEP

If material quality gain is absent, a candidate may still replace comparator only if:

- net corrections is between -2 and +2 inclusive ;
- hard safety passes ;
- critical non-regression passes ;
- either mean variable cost decreases by at least 20% OR p95 latency decreases by at least 20% ;
- the non-improved efficiency dimension does not exceed comparator by more than 10% ;
- all compared fields are known.

Otherwise retain comparator.

These rules are applied by code, not prose judgment.

## SECURITY INVARIANTS

- gold_test not accepted as a development/selection split.
- No sample removed after seeing outcome.
- Null/provider failures remain denominator.
- No hidden retry refresh after failure.
- Shared captured observations must preserve provenance.
- Experiment-lock mismatch refuses run/resume.
- Runtime code hash mismatch refuses run.
- No post-hoc threshold/prompt/tool/budget modification.

## IMPLEMENTATION REQUIREMENTS

### Gate metric

For samples routed SIMPLE under normal selected architecture:

Reference correctness:

```text
correct = predicted_label == reference_label
```

Null/failure prediction is incorrect.

Policy utility:

For reference in malicious classes:

```text
AUTO = 0
REVIEW = 1
ESCALATE = 2
```

For reference in `spam|legitime`:

```text
ESCALATE = 0
REVIEW = 1
AUTO = 2
```

Classification delta normal→bypass:

```text
+1 = wrong/null → correct
-1 = correct → wrong/null
 0 = otherwise
```

Materially improved if:

```text
classification_delta == +1
```

OR:

```text
classification_delta == 0
AND normal correctness did not decrease
AND policy_utility_bypass > policy_utility_normal
```

Materially degraded is the symmetric inverse:

```text
classification_delta == -1
```

OR:

```text
classification_delta == 0
AND bypass correctness did not increase
AND policy_utility_bypass < policy_utility_normal
```

Then:

```text
missed_investigation_rate =
    materially_improved_SIMPLE / total_SIMPLE
```

If `total_SIMPLE == 0`:

- rate = null ;
- decision = `INCONCLUSIVE`.

Critical gate miss:

```text
reference malicious
AND normal action == AUTO
AND bypass action in {REVIEW, ESCALATE}
```

Gate decision:

```text
KEEP
iff missed_investigation_rate <= 0.02
and critical_gate_miss == 0
and run complete

BYPASS
iff missed_investigation_rate > 0.02
or critical_gate_miss > 0

INCONCLUSIVE
if total_SIMPLE == 0
or run incomplete
or required paired data missing
```

Also report measured variable cost and latency deltas, but they do not override the safety rule above.

### Shared live observations

Within one architecture-comparison batch, the first real result for the key:

```text
(tool, normalized observable, provider-relevant request semantics)
```

is archived.

If another variant requests exactly the same key, reuse that authentic capture for **decision-quality comparison** instead of re-querying the provider.

Do not reuse a capture when provider-relevant semantics differ.

Keep two timing concepts:

- `collection_wall_clock_ms`
- `effective_tool_latency_ms`

For a reused observation:

- collection wall-clock for the reuse = 0 ;
- effective tool latency = the original live observation latency.

No failed result is silently refreshed inside the same comparison batch.

The run manifest must identify capture reuse explicitly.

### RAG/Vision ablations

If RAG KEEP:

- compare selected agentic architecture with RAG disabled vs enabled on identical eligible dev cases ;
- no other capability changes.

If vision KEEP:

- use Visual-79 only ;
- compare:
  - text ;
  - text + QR ;
  - text + QR + vision ;
- report Visual-79 and visual-essential slice separately ;
- do not use gold_test.

These are supporting ablations and do not override the pre-registered architecture selection criteria unless already represented by V2.

## ERROR HANDLING

Every partial run remains visible.

A run may resume only missing samples and only when the complete experiment-lock hash and runtime code commit/hash are unchanged.

If a mandatory variant is incomplete:

- preserve completed sample rows ;
- keep failures in denominators ;
- architecture replacement decision becomes `INCONCLUSIVE` if comparison completeness is insufficient.

A BUG FIX process is:

1. stop live measurements ;
2. document defect and why results are invalid ;
3. invalidate lock ;
4. fix only the defect ;
5. rerun deterministic tests ;
6. create new lock ;
7. rerun every affected variant from scratch or according to the existing evaluator’s verified clean-resume semantics.

An EXPERIMENT CHANGE is any change motivated by desired performance/cost behavior. It requires a new explicitly named experiment variant outside the frozen T19 comparison; it cannot overwrite V0–V4.

## AUDIT / PERSISTENCE

Directories exactly:

```text
runs/eval/t19/v0_fixed_dev/
runs/eval/t19/v1_agentic_core/
runs/eval/t19/v2_agentic_context/
runs/eval/t19/v3_agentic_osint_plus/
runs/eval/t19/v4_gate_bypass/
runs/eval/t19/models/
```

Each executed architecture variant directory contains:

- `metrics.json`
- `predictions.jsonl`
- `investigations.jsonl`
- `tool_calls.jsonl`
- `costs.json`
- `latency.json`
- `run_manifest.json`

V0 may use empty agent-specific JSONL files with explicit `not_applicable` metadata rather than fabricated investigation rows.

Create comparison/decision outputs under:

```text
runs/eval/t19/architecture_selection.json
runs/eval/t19/gate_decision.json
runs/eval/t19/model_comparison.json
```

Final human-readable report:

`docs/t19_results.md`.

No raw secrets, raw chain-of-thought, raw email bodies or unapproved provider payloads enter these benchmark files.

## TESTS REQUIRED

Implement deterministic tests asserting:

1. manual small AgenticMetrics fixture.
2. zero denominator → null rate.
3. wrong→right.
4. right→wrong.
5. right→right.
6. wrong→wrong.
7. malicious policy utility mapping.
8. benign/spam policy utility mapping.
9. materially improved classification path.
10. materially improved policy-only path.
11. materially degraded inverse path.
12. missed-investigation rate exact arithmetic.
13. critical gate miss exact condition.
14. total_SIMPLE=0 → INCONCLUSIVE.
15. useful call via new Evidence.
16. useful call via derived Observable.
17. useful RAG call via non-empty RagCase.
18. useful vision call only when image is actually supplied.
19. empty/no-op call not useful.
20. decision-changing call requires cited Evidence plus verdict/action change.
21. paired sample IDs must match.
22. missing/null sample remains failure/denominator.
23. experiment-lock mismatch refuses run.
24. runtime code/hash mismatch refuses resume.
25. dev selection command rejects gold_test path.
26. gate-bypass path does not mutate/call a bypass mode inside `decide_gate()`.
27. V0 uses frozen V1 graph.
28. V1/V2/V3/V4 use correct V2 graph/action sets.
29. V2 NOT_APPLICABLE behavior when RAG+vision both NO.
30. architecture selection deterministic on synthetic metrics.
31. hard-safety violation rejects candidate.
32. net corrections threshold boundary 2/3.
33. Macro-F1 delta threshold boundary.
34. critical-class drop boundary 1/2.
35. cost ratio boundary.
36. p95 ratio boundary.
37. efficiency-only 20% threshold.
38. incomplete cost/latency → INCONCLUSIVE.
39. shared live observation reuse requires exact cache key.
40. failed capture is not refreshed inside same batch.

## LIVE VALIDATION REQUIRED

Mandatory architecture benchmark on `gold_dev`.

Model benchmark is attempted only after architecture and gate selection are frozen.

No gold_test run is required by T19E for selection.

### Model benchmark

Required official runtime comparator:

`Qwen/Qwen3.8-27B`

Additional Akash candidate:

`openai/gpt-oss-120b`

Before running its benchmark, execute the same native tool-calling transport smoke contract from T19A.

If native tool calling fails:

```text
UNSUPPORTED_TOOL_TRANSPORT
```

and do not emulate it.

Conditional external comparator:

`gpt-5.6-luna`

Run only if the operator has supplied valid OpenAI credentials and the actual official model/tool contract is available at execution time.

It must pass a native tool-calling smoke before benchmark.

Missing credentials/capability are recorded, not simulated.

`openai/gpt-oss-20b` remains smoke/debug only.

Jev is outside T19.

The model comparison uses exactly the selected architecture and selected gate mode. No model-specific prompt or tool-schema changes.

## VALIDATION COMMANDS

Deterministic tests first:

```bash
python -m pytest tests/test_agentic_metrics.py tests/test_agentic_evaluation.py -q
```

Pre-register:

```bash
python scripts/evaluate_agentic.py lock   --split dev   --out configs/t19_experiment_lock.json
```

Run architecture variants in exact order:

```bash
python scripts/evaluate_agentic.py run   --split dev   --variant fixed   --experiment-lock configs/t19_experiment_lock.json   --out runs/eval/t19/v0_fixed_dev

python scripts/evaluate_agentic.py run   --split dev   --variant agentic-core   --experiment-lock configs/t19_experiment_lock.json   --out runs/eval/t19/v1_agentic_core

python scripts/evaluate_agentic.py run   --split dev   --variant agentic-context   --experiment-lock configs/t19_experiment_lock.json   --out runs/eval/t19/v2_agentic_context

python scripts/evaluate_agentic.py run   --split dev   --variant agentic-osint-plus   --experiment-lock configs/t19_experiment_lock.json   --out runs/eval/t19/v3_agentic_osint_plus

python scripts/evaluate_agentic.py select-architecture   --experiment-lock configs/t19_experiment_lock.json   --root runs/eval/t19

python scripts/evaluate_agentic.py run   --split dev   --variant gate-bypass   --experiment-lock configs/t19_experiment_lock.json   --out runs/eval/t19/v4_gate_bypass
```

After architecture/gate selection, model attempts use:

```bash
python scripts/evaluate_agentic.py run-model   --split dev   --model Qwen/Qwen3.8-27B   --experiment-lock configs/t19_experiment_lock.json   --out runs/eval/t19/models/qwen38

python scripts/evaluate_agentic.py run-model   --split dev   --model openai/gpt-oss-120b   --experiment-lock configs/t19_experiment_lock.json   --out runs/eval/t19/models/gpt_oss_120b
```

Run `gpt-5.6-luna` only if its preconditions are satisfied:

```bash
python scripts/evaluate_agentic.py run-model   --split dev   --model gpt-5.6-luna   --experiment-lock configs/t19_experiment_lock.json   --out runs/eval/t19/models/gpt_5_6_luna
```

Final validation:

```bash
python scripts/validate_agentic_eval.py   --experiment-lock configs/t19_experiment_lock.json   --root runs/eval/t19

python scripts/check_gate.py G8-E --complete-ticket TICKET-19E
python scripts/check_gate.py G8-E --record
python scripts/check_gate.py G8-E
python -m pytest -q
python -m pip check
git diff --check
```

If V2 is mechanically `NOT_APPLICABLE`, `evaluate_agentic.py run --variant agentic-context` must write a deterministic manifest recording that state and perform zero live sample calls; the selector then skips V2.

## EXPECTED RESULTS

Exactly one architectural decision:

- `KEEP_FIXED_PIPELINE`
- `KEEP_AGENTIC_CORE`
- `KEEP_AGENTIC_CONTEXT`
- `KEEP_AGENTIC_OSINT_PLUS`
- `INCONCLUSIVE`

Separately:

- `GATE=KEEP`
- `GATE=BYPASS`
- `GATE=INCONCLUSIVE`

Model comparison is reported independently and does not retroactively alter architecture selection criteria.

`NO MATERIAL GAIN` is a valid scientific result, not FAIL.

## ACCEPTANCE CRITERIA

G8-E PASS means:

- experiment lock created before live architecture measurements ;
- all mandatory applicable variants executed or honestly represented as incomplete/not-applicable ;
- paired denominators validated ;
- architecture-selection rules applied mechanically ;
- gate metric computed ;
- model smokes enforced ;
- all failures retained ;
- final report generated from actual artifacts ;
- no post-hoc retuning.

## FAIL CONDITIONS

- Post-hoc retuning.
- gold_test used for selection.
- Hidden sample exclusion.
- Runtime variant changed after reading results without lock invalidation.
- Missing failures removed from denominator.
- Model-specific prompt/tool changes in the comparison.
- Tool-call emulation for a model that fails native smoke.
- Architecture selection not reproducible from saved metrics.
- Gate decision not reproducible from paired rows.

## BLOCKED CONDITIONS

- G8-D not PASS.
- T14 evaluator contract unavailable/non-compliant.
- Mandatory dev corpus incomplete/corrupt.
- Mandatory run infrastructure failure preventing valid paired measurement.
- Frozen runtime hashes cannot be reproduced.
- Qwen official runtime unavailable for the mandatory architecture phase.

Missing optional comparator credentials do not block G8-E; they produce an explicit unavailable/unsupported model-comparison entry.

## ARTEFACTS PRODUCED

- `configs/t19_experiment_lock.json`
- all `runs/eval/t19/**` variant/model artifacts
- architecture selection JSON
- gate decision JSON
- model comparison JSON
- `docs/t19_results.md`
- G8-E receipt

## REGRESSION REQUIREMENTS

- Full V1 suite passes at end.
- T19A–D runtime hashes match experiment lock.
- No modification to frozen V1/T19 runtime behavior during measurement.
- `src/graph.py` remains unchanged.
- Gold labels/test unchanged.

## CODE AGENT EXECUTION PROMPT

Execute only TICKET-19E.

Read AGENTS.md, TICKET-19.md, TICKET-19A/B/C/D, this ticket, the actual T14 evaluator implementation and the completed T18 artifacts before editing.

Do not modify runtime architecture, prompts, gates, policy, tools, verifier or labels.

Create the experiment lock before any live architecture benchmark.

Use gold_dev only for architecture/model selection.

Run the architecture variants in the exact specified order. Retain every failure/null in denominators.

Do not read gold_test for any development decision.

Apply the architecture and gate decisions mechanically from the pre-registered rules in this ticket.

After architecture/gate selection, attempt only the explicitly listed additional models and require the same native tool-calling protocol. Do not emulate unsupported tool calling.

Generate docs/t19_results.md from actual artifacts.

Run every validation command.

Do not tune the system after seeing results. Do not push or merge.
