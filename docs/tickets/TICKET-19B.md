# TICKET-19B — Minimum agentic core (implemented contract)

## Statut

Implémenté sur `feature/t19ab-agentic-core` (base `gate/g6-ticket-14`).
Périmètre : plus petit vertical agentique réel (parser existant → agent LLM →
outils typés existants → finalize → vérificateur/policy existants).

## Runtime

`src/agent/runner.py` — `run_agentic_email(...)` : boucle Python bornée
simple, sans StateGraph, sans second LangGraph, sans multi-agents, sans
broker/DB. `src/graph.py` reste inchangé.

```text
parse_email (src.parsing)
  ↓
LLM tour (outils natifs)
  ↓  appels d'outils : validation → exécution séquentielle → ToolResult normalisé (role=tool)
  ↓ ... jusqu'à finalize_assessment ou une limite gelée
merge_evidence (src.evidence) → verify_assessment (src.verify) → decide_policy (src.policy)
  ↓
runs/agentic/<run_id>/{manifest.json,trace.jsonl,final.json,summary.txt}
```

## Limites gelées (§15)

```text
MAX_LLM_TURNS = 5
MAX_TOOL_CALLS = 4
MAX_URLSCAN_CALLS = 1
MAX_AGENT_SECONDS = 300
MAX_SINGLE_LLM_SECONDS = 90
MAX_TOOL_RESULT_CHARS = 12000
```

## Restrictions exécuteur

- Le modèle ne fournit QUE `observable_id` ; la valeur est résolue dans le
  registre du parser de l'email courant.
- Refus typés à zéro requête fournisseur : outil inconnu, arguments
  malformés/champs supplémentaires, observable manquant/invalide/inconnu,
  destinataire, doublon `(outil, observable)`, budget outil épuisé, budget
  urlscan épuisé (1).
- Aucun pivot récursif : un observable découvert par un outil reste evidence
  only ; `runs/agentic/` n'ajoute jamais ces IDs au registre requêtable.
- Les adaptateurs existants assurent profil de source, egress, credentials,
  visibilité urlscan, deadlines et statuts typés (`ok`, `not_found`,
  `unavailable`, `skipped`). `unavailable` ne fait jamais planter la boucle.
- Retour modèle : `ToolResult` normalisé si ≤ 12 000 caractères, sinon
  projection déterministe (identité/statut + 20 premières preuves puis 20
  premiers observables triés par id, `truncated=true`) sans couper un champ.

## Finalisation et sécurité

- `finalize_assessment.assessment` est validé exactement comme
  `src.state.Assessment` ; un assessment invalide est refusé et ne devient
  jamais un verdict.
- Vérificateur déterministe V01–V16 existant et policy AUTO/REVIEW/ESCALATE
  existante réutilisés tels quels (aucun second moteur).
- Sans assessment valide : `status=incomplete`, `action=REVIEW`, verdict nul.
- Exclus : RAG, Vision, QR, OSINT+ récursif, benchmark complet (T19C/D/E).

## Artefacts

Chaque run contient `manifest.json` (`architecture=agentic_core_v1`,
`measurement_scope=smoke`, `performance_claims_allowed=false`, commit,
modèles demandé/retourné, hash du prompt effectif, limites, compteurs
tours/appels/refus, statuts par fournisseur, latence, usage/coût),
`trace.jsonl` chronologique (llm_turn, tool_request, tool_validation,
provider_execution, tool_result, finalization), `final.json` et
`summary.txt`.

## Smoke réel

`python scripts/smoke_agentic.py smoke` : exactement les cinq échantillons
T14 (`nazario_phishing_2025_00116`, `nazario_phishing_2025_00020`,
`nazario_phishing_2025_00112`, `spamassassin_hard_ham_00192`,
`nazario_phishing_2025_00404`), sélection déterministe re-vérifiée, intégrité
des 83 GoldRecords/raw validée avant tout appel, chaque échantillon exécuté
une seule fois. Les indisponibilités fournisseur restent des résultats
honnêtes ; aucune conclusion de performance n'est publiée (T19E).

## Preuves

- `tests/test_agent_tools.py`, `tests/test_agent_runner.py` (déterministes).
- `runs/agentic/<run_id>/` (réels) et
  `runs/agentic/smoke_<horodatage>/index.json`.
