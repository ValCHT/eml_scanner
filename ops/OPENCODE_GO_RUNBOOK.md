# OpenCode Go implementation runbook

## 1. Connect OpenCode Go

From the repository root:

```text
opencode
```

In the TUI:

```text
/connect
/models
```

Select **OpenCode Go** as provider, then select the current model you want to use. For this project the intended initial implementation model is **GLM-5.3-Flash**. Do not hard-code the provider/model ID in the repository because the Go catalogue can change; `/models` is the source of truth for the exact current ID.

Do not run `/init`. The root `AGENTS.md` is already reviewed and committed.

## 2. Git cadence

Use one branch per gate and one commit per ticket.

Example G0:

```text
git switch -c gate/g0
```

Then run TICKET-01 in a fresh OpenCode session. When DONE, review and commit it. Start a new OpenCode session for TICKET-02 on the same gate branch. After G0 PASS, push/open the gate PR manually.

Recommended branches:

```text
gate/g0
gate/g1
gate/g2
gate/g3
gate/g4
gate/g5
gate/g6
experiment/g7-rag
experiment/g7-vision
experiment/g7-specialization
```

## 3. Execute a ticket

Interactive, recommended:

```text
opencode
/ticket 01
```

The custom `/ticket` command tells OpenCode to read `docs/tickets/TICKET-01.md` and obey the active ticket exactly.

Alternative non-interactive form:

```text
opencode run "Read docs/tickets/TICKET-01.md completely and execute exactly that ticket. Follow AGENTS.md. Do not start any other ticket."
```

For automation with an explicit model, first obtain the exact current provider/model string with:

```text
opencode models --refresh
```

then use `opencode run --model provider/model ...`.

## 4. Human review after each ticket

Before committing:

```text
git status --short
git diff --check
git diff
```

Confirm:

- only FILES ALLOWED changed;
- all ticket validation commands were actually run;
- no secret/data/holdout entered Git;
- no tests or thresholds were weakened to obtain PASS;
- the agent stopped after one ticket.

Then commit manually, for example:

```text
git add -A
git commit -m "G0 TICKET-01: bootstrap contracts and config"
```

OpenCode project permissions deliberately deny `git push`. Push manually only when the gate is ready for PR/review.

## 5. Gate review

At the end of a gate:

1. run the gate validation commands from `docs/gates.md`;
2. inspect the complete gate diff;
3. push the branch manually;
4. open a GitHub PR;
5. use Codex/Sol for review if desired;
6. merge only after blockers are resolved.

Do not expose `gold_test` to the build agent. TICKET-18 is a separate terminal evaluation step after the experiment is frozen.
