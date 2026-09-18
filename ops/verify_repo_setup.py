from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "AGENTS.md",
    "CLAUDE.md",
    "opencode.jsonc",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    "README.md",
    "docs/architecture.md",
    "docs/contracts.md",
    "docs/corpus.md",
    "docs/decisions.md",
    "docs/evaluation.md",
    "docs/fixtures.md",
    "docs/gates.md",
    "docs/prompt_integration.md",
    "docs/threat_model.md",
    "prompts/internal_assessment.txt",
    "prompts/final_assessment.txt",
    "schemas/assessment.schema.json",
    "schemas/triage_report.schema.json",
    "docs/spec/CHANGELOG_V1_TO_V1.1.md",
    "docs/spec/TICKET_MATRIX_V1_TO_V1.1.md",
    "docs/spec/CHANGELOG_V1.1_TO_V1.2.md",
    "docs/spec/TICKET_MATRIX_V1.1_TO_V1.2.md",
    "docs/spec/QA.md",
    "docs/spec/SOC_Email_Triage_POC_Plan_17092026.md",
    "docs/spec/SOURCE_SHA256SUMS.json",
]

errors: list[str] = []

for rel in REQUIRED:
    if not (ROOT / rel).is_file():
        errors.append(f"missing required file: {rel}")

for number in range(1, 19):
    rel = Path("docs/tickets") / f"TICKET-{number:02d}.md"
    if not (ROOT / rel).is_file():
        errors.append(f"missing ticket: {rel.as_posix()}")

for rel in ["schemas/assessment.schema.json", "schemas/triage_report.schema.json"]:
    path = ROOT / rel
    if path.is_file():
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # setup checker: report exact parse failure
            errors.append(f"invalid JSON in {rel}: {exc}")

gitattributes = ROOT / ".gitattributes"
if gitattributes.is_file() and "*.eml -text" not in gitattributes.read_text(encoding="utf-8"):
    errors.append(".gitattributes must contain '*.eml -text'")

claude = ROOT / "CLAUDE.md"
if claude.is_file() and "@AGENTS.md" not in claude.read_text(encoding="utf-8"):
    errors.append("CLAUDE.md must import @AGENTS.md")

if errors:
    print("REPO_SETUP=FAIL")
    for error in errors:
        print(f"- {error}")
    raise SystemExit(1)

print("REPO_SETUP=PASS")
print("tickets=18")
print("schemas=2 valid JSON files")
print("runtime_prompts=2")
print("product_code_implemented=no")
