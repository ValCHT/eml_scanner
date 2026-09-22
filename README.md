# SOC Email Triage POC

Implementation repository prepared from the frozen V1.2 specification dated 18/09/2026.

**Scope.** This is an independent suspicious-email / phishing analysis tool.
It analyses individual messages only: there is no mailbox history, no
organizational relationship model and no BusinessContext. AUTO/REVIEW/ESCALATE
are recommendations only — the runtime never acts on a mailbox.

**Implementation status (updated 22/09/2026):** TICKET-01 through TICKET-14 are
implemented; gate receipts G0–G6 are recorded under `runs/gates/` (G6 PASS,
re-recorded 22/09/2026 on clean main `c0273d61689ee7df55d25d33106b652d36c88d47`
with `Qwen/Qwen3.8-27B`; bounded 5-email HARNESS validation only). TICKET-14
(G6 harness-validation gate) implements the bounded real dev smoke and its
exact offline recompute: `src/metrics.py`, `scripts/evaluate.py`,
`configs/evaluation.yaml`, `configs/experiment_lock.json`, documented in
`docs/evaluation.md` §8.6. The three post-T14 tracks are merged: TICKET-15
(public-only local RAG) in PR #16 — its G7-A experimental closure remains
deferred/optional; TICKET-16 (vision/QR) in PR #18 — its **live Vision
capability smoke PASSED** (`runs/gates/G7-B/smoke_vision/smoke_result.json`,
`status=live_ok`, real pixels, `Qwen/Qwen3.8-27B`; capability only, no
performance claim) and its G7-B experimental closure remains deferred/optional;
TICKET-19A (native tool calling) and TICKET-19B (bounded minimum agentic core)
in PR #17 — their ticket files are materialized under
`docs/tickets/TICKET-19A.md`/`TICKET-19B.md` and the real smokes are archived
under `runs/agentic/`. TICKET-19C (agentic convergence with T15 RAG and
T16 QR/Vision) is **merged in PR #19** and remains
`IMPLEMENTED_SMOKE_VALIDATED`. Operator trajectory (2026-09-21, accelerated
agentic path): after T14, three parallel development tracks — T15 (RAG),
T16 (vision/QR), T19A→T19B (agentic chain, independent of RAG and Vision) —
converged in T19C; **T19D is next** (ticket file not yet materialized), then
**T19E**, the first **full benchmark** (complete dev, sealed test, Visual-79)
with a simultaneous rerun of the fixed V1 in the same experiment window;
`gold_test` is never opened before it. G7-A/G7-B experimental closures remain
deferred/optional before T19E; T17 is optional after T19E; T18 is SUPERSEDED
BY T19E.

## Real dev baseline (TICKET-14)

```bash
# bounded real harness smoke on gold_dev (requires LITELLM_* runtime configuration)
# — 5 deterministic representative records; DIAGNOSTIC ONLY, not a performance baseline
python scripts/evaluate.py --split dev --mode live --variant baseline \
  --sample-profile smoke --out runs/eval/dev_smoke

# exact offline recompute from the archived authentic artifacts (no network)
python scripts/evaluate.py --mode recompute --from-run runs/eval/dev_smoke \
  --out runs/eval/dev_smoke_recomputed

# G6 receipt (re-runnable: existing smoke outputs are archived first,
# never deleted/overwritten)
python scripts/check_gate.py G6 --record
```

The current receipt `runs/gates/G6/gate.json` is PASS on the clean current-main
merge commit `c0273d61689ee7df55d25d33106b652d36c88d47` (PR #19), re-recorded
22/09/2026 with `Qwen/Qwen3.8-27B`: 109 targeted tests, 5/5 live smoke records,
exact offline recompute equal. This stays a bounded harness validation, not a
performance baseline.

Per the operator amendment (2026-09-21), **G6 is a harness-validation gate, not a
performance benchmark**: the full 83-record dev benchmark is executed for the
first time in **T19E** (`--sample-profile full`; the complete evaluation
capability is implemented and tested here but NOT run as T14–T18 validation).
The smoke validates plumbing only (offline Gold/raw integrity over all 83
records, then live calls for exactly one lexicographically first record per
dev label with support>0 — menace has zero support and is never fabricated).
The evaluation refuses a live run without an explicit `--sample-profile`.

The evaluation validates every GoldRecord (closed schema, no content keys,
`raw_path` resolved under `corpus/raw/**`, recomputed SHA-256) BEFORE any
LLM call, runs the frozen BASELINE V0 pipeline with the official
`Qwen/Qwen3.8-27B` runtime, executes the A/B/C control on the same COMPLEX
smoke emails (A = shared INTERNAL medium, B = XHIGH internal-only ablation
control, C = nominal FINAL with the real external bundle), and archives
exactly one evaluation row per `sample_id` plus metrics/manifest/matrix.
Provider failures and abstentions stay in every denominator; unknown costs
are never turned into zero. Development decisions use `gold_dev` only —
`gold_test.jsonl` is an internal POC validation partition that this
workflow refuses to open.

## Running the pipeline

The runtime uses the real OpenAI-compatible endpoint configured through
`LITELLM_*`; there is no mock or recorded mode. A missing `LITELLM_API_KEY`
refuses the LLM phase with an explicit error instead of simulating it.

```bash
# one email -> RUNS_DIR/<run_id>/{report.json,summary.txt,events.jsonl}
python run.py tests/fixtures/malicious_url_redirect.eml --source-profile fixture

# sequential live batch -> results.jsonl, metrics.json, run_manifest.json
python run_batch.py --input tests/fixtures --mode live --output runs/gates/G5/batch

# strict validation of a batch directory (schema + invariants + row/report match)
python scripts/validate_reports.py --run-dir runs/gates/G5/batch

# single-email runs can also be validated through the frozen report schema
python scripts/validate_reports.py runs/<run_id>/report.json \
  --schema schemas/triage_report.schema.json
```

`--source-profile` is **required** on the single-email CLI and is never guessed
from the email content: allowed values are exactly `fixture`, `public_corpus`
and `private_authorized`. Only `fixture` may persist the complete LLM request
body (docs/contracts.md §2.6.1), so `python run.py customer.eml` fails at
argument parsing (exit 2) before any pipeline execution or network call.

`run.py` and `run_batch.py` never act on a mailbox: AUTO/REVIEW/ESCALATE are
recommendations only. The batch is sequential, sorted by input path, continues
after a failing email by writing its explicit error line, and exits non-zero
if any input produced no archived report.

## Runtime LLM decision

- **Current POC provider:** AkashML at
  `https://api.akashml.com/v1/chat/completions`.
- **Official POC model:** `Qwen/Qwen3.8-27B` for G2 evidence and all future
  quantitative POC assessments.
- **Cheap technical model:** `openai/gpt-oss-20b` for connectivity, transport,
  parsing, schema and smoke checks only. Its output is never an official result.
- **Non-official development model:** `Qwen3.6-35B-A3B` is operator-approved for
  cheap non-official development loops, functional/debug live tests that
  genuinely need an LLM, and pre-validation before an official run. Its outputs
  must never be presented as official Qwen3.8 gate evidence or baseline
  measurements. No AkashML model ID is claimed for it: the exact ID must be
  taken from the configured endpoint's model list when it is used.
- **Future Orange demo target:** the same generic `LITELLM_CHAT_URL`,
  `LITELLM_API_KEY` and `LITELLM_MODEL` settings switch provider without code edits.
- **Historical evidence:** G2 was previously run through Genspark with
  `claude-haiku-4-5`. Those receipts remain historical and are not relabeled as Qwen.

Only explicit `LITELLM_*` configuration controls the runtime. Akash credentials are
opaque Bearer values; an `akml-*` key is neither converted nor required to resemble
an `sk-*` key. No provider-specific credential mapping exists.

## Repository map

- `AGENTS.md` — canonical instructions for Codex and OpenCode.
- `CLAUDE.md` — Claude Code entry point importing `AGENTS.md`.
- `opencode.jsonc` — project permissions for OpenCode V2; no model is hard-coded.
- `docs/` — active normative architecture/contracts/gates and domain documents.
- `docs/tickets/` — TICKET-01 … TICKET-18 plus TICKET-19A/TICKET-19B (materialized; native tool calling and bounded agentic core implemented and merged); TICKET-19C (agentic convergence) is implemented and merged, tracked by `runs/tickets/TICKET-19C/{status.json,report.md}`. **T19D is next** (ticket file not yet materialized) and T19E remains the terminal full benchmark (graph in `docs/gates.md`). T18 is superseded by T19E. Execute one ticket per agent session.
- `docs/spec/` — frozen V1.2 audit snapshot, changelog, QA, matrix and research inspections.
- `prompts/` — runtime INTERNAL / FINAL prompts.
- `schemas/` — runtime JSON schemas.
- `ops/` — human/agent runbooks and repository setup helpers. Not runtime code.
- `ops/ci/cross-platform.yml.disabled` — non-live Python 3.11 test matrix for Linux/macOS/Windows; kept out of `.github/workflows/` because the publishing token lacks the `workflows` permission, so no GitHub status check runs on PR heads until it is restored.

## Recommended implementation workflow

Use one Git branch per implementation gate and one commit per ticket:

- `gate/g0`: TICKET-01, then TICKET-02
- `gate/g1`: TICKET-03
- `gate/g2`: TICKET-04
- `gate/g3`: TICKET-05
- `gate/g4`: TICKET-06 → 08
- `gate/g5`: TICKET-09 → 11
- `gate/g6`: TICKET-12 → 14
- after T14, three parallel tracks, all merged: T15 (RAG; PR #16, G7-A closure deferred/optional), T16 (vision/QR; PR #18, live Vision capability smoke PASS, G7-B closure deferred/optional), T19A → T19B (agentic; PR #17, independent of RAG and Vision — see `docs/tickets/TICKET-19A.md`, `docs/tickets/TICKET-19B.md`)
- post-G6 convergence: T19C (PR #19, merged, `IMPLEMENTED_SMOKE_VALIDATED`) → **T19D (next; ticket file not yet materialized)** → T19E (terminal)
- T19E: terminal sealed evaluation — first full benchmark with a simultaneous rerun of the fixed V1; only after the experiment is frozen and the holdout is released by the evaluator
- G7-A/G7-B experimental closures remain deferred/optional before T19E; TICKET-17 is optional after T19E
- TICKET-18: SUPERSEDED BY T19E (not executed as a standalone ticket)

Start a fresh OpenCode session for every ticket. Do not reuse the previous ticket's conversational context as a source of truth; the filesystem, Git history and ticket are the state.

## OpenCode Go

1. Start OpenCode at repository root.
2. Connect the **OpenCode Go** provider with `/connect`.
3. Use `/models` and select the current Go model you intend to use (GLM-5.3-Flash is available in the Go catalogue as of 18/09/2026).
4. Do **not** run `/init`: this repository already contains the reviewed `AGENTS.md`.
5. In a fresh session, execute the next pending ticket — see
   [Next implementation step](#next-implementation-step); never re-run an
   already-DONE ticket.
6. Review the diff and validation output before committing.

See `ops/OPENCODE_GO_RUNBOOK.md` for the full sequence.

## Cross-platform rule

Application/runtime behavior must not depend on the user's shell. After activating a Python 3.11 virtual environment, commands should use `python -m ...` and work on Windows, macOS and Linux. CI runs non-live tests on all three operating systems.

RFC822 `.eml` files are byte-sensitive. `.gitattributes` deliberately disables Git text normalization for them.

## Next implementation step

**TICKET-19D is next** (ticket file not yet materialized; dependency graph in
`docs/gates.md`); it starts only when the operator materializes the ticket and
explicitly launches it. TICKET-19E follows and remains the first full benchmark
(complete dev, sealed test, Visual-79, simultaneous rerun of the fixed V1);
`gold_test` stays closed until then. The current G6 receipt
(`runs/gates/G6/gate.json`) is PASS on clean main
`c0273d61689ee7df55d25d33106b652d36c88d47`.
