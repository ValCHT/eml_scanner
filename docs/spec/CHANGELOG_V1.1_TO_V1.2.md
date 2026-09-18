# CHANGELOG V1.1 → V1.2

18/09/2026 — micro-patch ciblé après contre-revue ; aucune implémentation produit exécutée.

Principe : corriger uniquement deux blockers méthodologiques confirmés. Prompts, schemas, taxonomie, graphe, R1–R3, V01–V16, policy, 18 tickets et configuration OpenCode restent structurellement inchangés.

FILE: `docs/decisions.md`; `docs/gates.md`; `tickets/TICKET-05.md`; `tickets/TICKET-11.md`
SECTION: G3 / branch coverage / G5 graph tests
CHANGE: La présence d'un SIMPLE live n'est plus une condition de PASS avant G6. SIMPLE et COMPLEX sont démontrés par tests déterministes du gate/plumbing ; toutes les sorties Luna réelles restent évaluées et leur distribution archivée. Si aucun SIMPLE live : `simple_path_live_observed=false` + limitation, sans modifier les seuils.
WHY: Éviter un deadlock où BASELINE V0 interdit le tuning avant G6 mais une sortie stochastique Luna conditionnait l'accès à G4–G6.
IMPACT ON TICKETS: 05 et 11 modifiés ; aucun nouveau ticket.

FILE: `docs/contracts.md`; `docs/architecture.md`; `docs/prompt_integration.md`; `docs/gates.md`; `docs/evaluation.md`; `tickets/TICKET-09.md`; `tickets/TICKET-14.md`
SECTION: audit des appels FINAL / A-B-C
CHANGE: L'audit d'entrée couvre INTERNAL et FINAL. FINAL ajoute compteurs de provenance interne/externe, digest TOOL_STATUS, nombre de cas RAG et nombre de visuels réellement envoyés. B et C ont des invariants d'audit explicites ; mismatch = comparaison expérimentale invalide.
WHY: Un hash de payload différent ne prouve pas que B était réellement sans enrichissement ni que C contenait le bundle externe ; C−B doit être auditable.
IMPACT ON TICKETS: 09 et 14 modifiés ; interfaces Assessment/TriageReport inchangées.

FILE: `docs/spec/SOC_Email_Triage_POC_Plan_17092026.md`; `docs/spec/README_SPEC.md`; `docs/spec/QA.md`; `README.md`; `AGENTS.md`; `ops/CODEX_REPO_SETUP_PROMPT.txt`
SECTION: version / gel
CHANGE: Freeze passe de V1.1 à V1.2 ; historique V1→V1.1 conservé et présent changelog ajouté.
WHY: Tracer le micro-patch sans effacer la provenance V1.1.
IMPACT ON TICKETS: TICKET-01 reste la prochaine étape.

Non-changements explicites :
- aucun `build_wire_schema` ajouté ;
- aucun changement `opencode.jsonc` ;
- aucun prompt/schema modifié ;
- aucun seuil R1/R2/R3 modifié ;
- aucun mock/faux résultat ajouté ;
- aucun ticket ajouté ou supprimé.

**V1.2 READY FOR IMPLEMENTATION: YES**
