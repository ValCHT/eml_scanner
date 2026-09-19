# SOC Email Triage POC

Implementation repository prepared from the frozen V1.2 specification dated 18/09/2026.

**Implementation status (updated 19/09/2026):** TICKET-01 through TICKET-11 are
implemented in the working tree. Gate receipts G0–G4 are recorded under
`runs/gates/` (G4 was re-recorded live after the architecture-mandated
LangGraph dependency alignment); the G5 closing receipt is produced by
TICKET-11 (`python scripts/check_gate.py G5 --record`). TICKET-12 (G6) must
not start before the G5 receipt and the human review of the diff.

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
