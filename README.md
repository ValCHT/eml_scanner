# SOC Email Triage POC

Implementation repository prepared from the frozen V1.2 specification dated 18/09/2026.

**Implementation status (updated 18/09/2026):** TICKET-01 (G0 skeleton, settings and
contract models) is implemented and validated — 38 non-live tests pass, `pip check`
clean, gate controller recorded. Do **not** re-execute TICKET-01; the next product
ticket is TICKET-02 (minimal Luna client), in a fresh session. See the open pull
request #1 for the full diff and validation receipts.

## Runtime LLM decision (environment-scoped)

- **Universal defaults (canonical V1.2):** `openai/gpt-5.6-luna` on the Orange proxy
  (`https://management.llmproxy.ai.orange/chat/completions`), per docs/contracts.md §2.7.
- **Genspark sandbox derogation (explicit project decision, stable for POC
  measurements):** inside the Genspark sandbox, the runtime LLM is `claude-haiku-4-5`
  on the injected OpenAI-compatible endpoint. The mapping in `src/config.py`
  `load_settings` is **atomic**: it applies (URL + model + key) only when no canonical
  `LITELLM_*` field is provided (env or env_file) and `OPENAI_BASE_URL` points at an
  authorized Genspark host (`_GENSPARK_LLM_HOSTS`). It never becomes a global default
  and never silently alters macOS/Linux/Windows behavior or the G2/G6 experiments.
- Orange Luna endpoint was unreachable from this sandbox (403 HTML edge block, before
  the API layer); retest from an Orange-network machine before switching G2 to live.

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

TICKET-01 is DONE (validated, pending review-merge on PR #1).
The next product ticket is `docs/tickets/TICKET-02.md`, in a fresh agent session.
Do not start TICKET-03 until TICKET-02 is DONE and its changes are reviewed/committed.
