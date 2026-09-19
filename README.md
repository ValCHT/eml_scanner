# SOC Email Triage POC

Implementation repository prepared from the frozen V1.2 specification dated 18/09/2026.

**Implementation status (updated 19/09/2026):** TICKET-01 through TICKET-04 are
merged on `main` (HEAD `6635ee4182a4497ecdac889b37fc7ed2f7afed14`). The
current maintenance task migrates the runtime and revalidates G2. TICKET-05 must
not start until this change and the refreshed G1/G2 receipts receive human review.

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

Complete and review the AkashML/Qwen runtime migration and refreshed G1/G2
evidence. Do not start TICKET-05 in this maintenance session.
