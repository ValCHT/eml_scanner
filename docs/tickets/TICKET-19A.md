# TICKET-19A — Native tool calling (implemented contract)

## Statut

Implémenté sur `feature/t19ab-agentic-core` (resynchronisée sur `main` ;
base finale `38b642c`, qui inclut le merge T15 — T19A/B n'utilisent ni RAG
ni Vision).
Autorisation opérateur 2026-09-21 : T19A démarre avant G6 PASS ; T15 et T16
sont développés en parallèle, sans dépendance RAG/Vision.

## Objet

Démontrer que le runtime OpenAI-compatible configuré (`LITELLM_*`) produit de
VRAIS appels d'outils natifs. Preuve de capacité uniquement : aucun benchmark
de performance, aucune conclusion de qualité.

## Contrat implémenté

- Client : `src/agent/client.py` (`AgentChatClient`).
  - Payload réel : `model`, `messages`, `tools`, `tool_choice="auto"`,
    `reasoning_effort`, `max_completion_tokens`. Aucun `response_format`,
    aucun paramètre legacy, aucun fallback modèle/fournisseur/transport.
  - Parsing strict de `message.tool_calls[].id`,
    `function.name`, `function.arguments` (chaîne JSON, objet toléré comme
    même structure native ; argument invalide => erreur typée locale).
  - Erreurs explicites : `finish_reason` anormal, absence de `tool_calls`
    avec `finish_reason="tool_calls"`, refus du modèle, modèle retourné
    absent ou différent du modèle demandé.
  - Capture : hashes requête/réponse, usage, modèle ; jamais d'entête HTTP
    ni de clé ; le body exact n'est persisté que pour `source_profile=fixture`.
- Alertes d'état : API key absente ou deadline expirée => zéro requête.
- Outils exposés : exactement `lookup_virustotal`, `lookup_opencti`,
  `scan_urlscan`, `finalize_assessment` (`src/agent/tools.py`). Les schémas
  ne portent aucun nombre configurable ; la limite urlscan est
  structurellement gelée à 1, cohérente avec la description du schéma
  (« at most one submission »).
- Prompt agent : `src/agent/prompt.py` — prompt FINAL existant (taxonomie et
  règles métier) + politique agentique explicite en 10 points ; le prompt
  effectif et son SHA-256 sont construits à partir des `AgentLimits`
  exactement appliquées par le run (`effective_prompt_sha256`), y compris
  pour la sonde capacitaire.
- Smoke réel : `python scripts/smoke_agentic.py capability`.
  - Fixture contrôlée avec observable URL issu du parser
    (`tests/fixtures/malicious_url_redirect.eml` par défaut) ; le prompt
    exige UN appel `lookup_virustotal` pour l'observable connu, puis stop.
    L'instruction de sonde est une instruction **système** de confiance et
    l'enveloppe utilisateur contient le registre réel : un premier essai a
    montré que placer l'instruction dans la charge non fiable la fait (à
    raison) traiter comme une injection.
  - Le lookup fournisseur n'est PAS exécuté : la sonde mesure uniquement la
    structure `tool_calls` native.
  - Archive : `requested_model`, `returned_model`, nom de l'outil,
    JSON d'arguments, `tool_call_id`, horodatage, hash requête, hash réponse.
  - Statuts : `DONE` si la structure native est observée ;
    `IMPLEMENTED_WAITING_FOR_LIVE_TOOLCALL_SMOKE` (exit 2) si la clé LLM est
    absente ou le transport échoue sans réponse ;
    `BLOCKED_PROVIDER_NATIVE_TOOL_CALLING` (exit 1) si le fournisseur répond
    sans la structure native. Aucun planner JSON/XML de repli.

## Preuves

- `tests/test_agent_client.py` (déterministe, hors ligne).
- Sonde réelle : artefact `runs/agentic/<run_id>/` (ou reçu bloqué
  `runs/agentic/blocked_<horodatage>/t19a_status.json`).
