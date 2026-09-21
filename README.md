# SOC Email Triage POC

Implementation repository prepared from the frozen V1.2 specification dated 18/09/2026.

**Implementation status (updated 21/09/2026):** TICKET-01 through TICKET-13 are
implemented; gate receipts G0–G5 are recorded under `runs/gates/`. TICKET-14
(G6 closure) implements the real dev baseline evaluation:
`src/metrics.py`, `scripts/evaluate.py`, `configs/evaluation.yaml`,
`configs/experiment_lock.json` with the workflow documented in
`docs/evaluation.md` §8.6 (frozen A/B/C control on COMPLEX dev emails,
exact offline recompute, gold_test never opened during development).

## Real dev baseline (TICKET-14)

```bash
# bounded real harness smoke on gold_dev (requires LITELLM_* runtime configuration)
# — 5 deterministic representative records; DIAGNOSTIC ONLY, not a performance baseline
python scripts/evaluate.py --split dev --mode live --variant baseline \
  --sample-profile smoke --out runs/eval/dev_smoke

# exact offline recompute from the archived authentic artifacts (no network)
python scripts/evaluate.py --mode recompute --from-run runs/eval/dev_smoke \
  --out runs/eval/dev_smoke_recomputed

# G6 receipt
python scripts/check_gate.py G6 --record
```

Per the operator amendment (2026-09-21), **G6 is a harness-validation gate, not a
performance benchmark**: the full 83-record dev benchmark is executed for the
first time in **TICKET-19** (`--sample-profile full`; the complete evaluation
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
- `docs/tickets/` — TICKET-01 … TICKET-18. Execute one ticket per agent session.
- `docs/spec/` — frozen V1.2 audit snapshot, changelog, QA, matrix and research inspections.
- `prompts/` — runtime INTERNAL / FINAL prompts.
- `schemas/` — runtime JSON schemas.
- `ops/` — human/agent runbooks and repository setup helpers. Not runtime code.
- `.github/workflows/cross-platform.yml` — non-live test matrix for Python 3.11 on Linux/macOS/Windows once G0 creates the package.

## Recommended implementation workflow

Use one Git branch per implementation gate and one commit per ticket:

- `gate/g0`: TICKET-01, then TICKET-02
- `gate/g1`: TICKET-03
- `gate/g2`: TICKET-04
- `gate/g3`: TICKET-05
- `gate/g4`: TICKET-06 → 08
- `gate/g5`: TICKET-09 → 11
- `gate/g6`: TICKET-12 → 14
- optional G7 branches only if selected
- TICKET-18 only after the experiment is frozen and the holdout is released by the evaluator

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

Review the G5 receipt (`runs/gates/G5/`), the TICKET-11 report
(`runs/tickets/TICKET-11/report.md`) and the batch evidence
(`runs/gates/G5/batch/`). TICKET-12–14 (G6 corpus, metrics and evaluation)
start only after that review; TICKET-11 must not be re-run.
