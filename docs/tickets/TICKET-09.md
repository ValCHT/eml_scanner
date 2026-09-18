# TICKET-09 — Evidence merge et Final Assessment

## GATE

G5

## OBJECTIF

Combiner les preuves réelles et obtenir une réévaluation xhigh.

## PRECONDITIONS / DÉPENDANCES

PASS G4 et captures réelles ; contrats Assessment stables.

## IN SCOPE

Merge déterministe, registre des découvertes outil, prompt final, final_source et fallback.

## OUT OF SCOPE

Vérification sémantique par autre LLM, chaîne d’agents, pivot récursif, RAG actif, vision active.

## FILES ALLOWED

src/evidence.py; src/prompts.py; src/llm.py; prompts/final_assessment.txt; tests/test_evidence.py; tests/test_final.py; docs/contracts.md. Artefacts de validation sous runs/tickets/TICKET-09/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

merge_evidence(parsed, tool_results) -> (dict[str,Evidence], dict[str,Observable], list[VisualEvidence]); assess_final(parsed, internal, evidence, rag_context, client) -> (Assessment | None, CallRecord).

## IMPLEMENTATION REQUIREMENTS

Conserver provenance du hash interne ; créer evidence OSINT séparée. Collisions refusées ; sort stable. Exclure données de raw provider non normalisées. Final xhigh, budget90 s global phase, tous résultats unavailable transmis comme statuts. Pour chaque tentative FINAL réellement émise, produire l'audit docs/contracts.md §2.6.1 sur les bytes effectivement transmis : compteurs INTERNE/externe, digest TOOL_STATUS, nombre RAG et visuels ; request body exact persisté uniquement pour fixtures. Si appel échoue, copie internal valide avec final_source=internal_fallback et avertissement ; pas de résultat fictif.

## TESTS REQUIRED

Merge de captures live G4 ; même ID/contenu idempotent, collision rejetée ; preuve absente refusée ; vrai final sur fixtures ; audit FINAL recalculable sur fixture et minimisé hors fixture ; `external_evidence_count_sent` correspond aux evidences OSINT/SANDBOX réellement jointes ; absence de résultat renvoyée honnêtement ; gain sans evidence signalé pour G5 verifier.

## VALIDATION COMMANDS

```bash
python scripts/check_gate.py G4
python -m pytest tests/test_evidence.py tests/test_final.py --live -q
```

## EXPECTED RESULTS

Exit 0 ; outputs Luna réels, references limitées aux entrées ; aucune nouvelle URL non sourcée ; fallback documenté.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Evidence ledger stable et final réel ; les facts libres ne sont pas utilisés pour créer des rapports.

## FAIL CONDITIONS

Confiance ou classement de remplacement fabriqués, retour externe inventé, provenance écrasée, appels d’outils par Luna.

## ARTEFACTS PRODUCED

Merge, prompt final complet, captures G5/final/ et audits FINAL par tentative.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-09 — Evidence merge et Final Assessment, gate G5. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
