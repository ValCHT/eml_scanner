# TICKET-11 — StateGraph, CLI, rapport et clôture pipeline

## GATE

G5

## OBJECTIF

Exécuter et persister tout le flux depuis un `.eml`.

## PRECONDITIONS / DÉPENDANCES

Tickets 09–10 DONE ; PASS G4.

## IN SCOPE

Graphe complet, run.py, batch séquentiel, résumé, JSONL, délais et erreurs.

## OUT OF SCOPE

UI web, serveur, base, Docker, actions email réelles, parallélisme.

## FILES ALLOWED

src/graph.py; src/reporting.py; run.py; run_batch.py; tests/test_graph.py; tests/test_reporting.py; scripts/validate_reports.py; README.md; docs/architecture.md; docs/threat_model.md. Artefacts de validation sous runs/tickets/TICKET-11/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

build_graph(services)->CompiledStateGraph ; run_email(path,settings)->TriageReport ; write_report(report,directory)->Path. État et edges exacts docs/architecture.md. InMemorySaver/thread_id par run ; clients hors état.

## IMPLEMENTATION REQUIREMENTS

Un seul add_conditional_edges. Simple copie internal et un appel nominal ; complex VT→CTI→urlscan→RAG no-op→merge→final. Deux appels nominaux maximum, retries comptés séparément. Exceptions prévues→état, erreur d’écriture→exit non nul. Rapport strict, résumé≤100 mots rendu par templates. Batch trié par chemin, séquentiel, continue après un email défaillant en écrivant sa ligne d’erreur.

## TESTS REQUIRED

Introspection edges ; routage SIMPLE/COMPLEX démontré avec état contrôlé uniquement pour le plumbing du graphe, jamais comme résultat métier ; batch live sur fixtures suivant les décisions réelles du gate, avec SIMPLE live observé si disponible mais non requis avant G6 ; interruption réseau réelle sur service avec délai borné ; parser malformed ; écriture refusée ; fichier déjà existant pas écrasé silencieusement ; JSON schema ; aucun secret/content actif ; total timings et provenance ; pas de rétention illimitée des savers.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_graph.py tests/test_reporting.py --live -q
python run_batch.py --input tests/fixtures --mode live --output runs/gates/G5/batch
python scripts/validate_reports.py --run-dir runs/gates/G5/batch
python scripts/check_gate.py G5 --record
```

## EXPECTED RESULTS

Exit 0 ; une sortie par fixture ; cas invalides ont verdict nullable/statut honnête ; branches du graphe conformes. Si aucun fixture live n'emprunte SIMPLE, l'absence est tracée sans bloquer G5 ; toutes les violations structurées détectées ; G5 PASS.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Pipeline complet mesurable sans RAG/vision ; aucune réponse artificielle ; erreurs de fournisseur non fatales.

## FAIL CONDITIONS

Nouvelle branche conditionnelle, service obligatoire pour terminer un mail, action réelle, skipped obligatoire masqué, faux schema PASS.

## ARTEFACTS PRODUCED

CLI et batch utilisables, rapports réels, documentation et receipt G5.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-11 — StateGraph, CLI, rapport et clôture pipeline, gate G5. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
