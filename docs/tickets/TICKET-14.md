# TICKET-14 — Évaluation baseline réelle et fermeture G6

## GATE

G6

## OBJECTIF

Mesurer la baseline et rendre les métriques auditables.

## PRECONDITIONS / DÉPENDANCES

Tickets12–13 DONE ; PASS G5 ; dev validé ; Luna et accès CTI/urlscan validés selon G4, VT indisponible admis et signalé ; test scellé et non ouvert.

## IN SCOPE

Scripts evaluate/recompute, métriques, confusion, coûts, latence, internal/final, contrôle deuxième raisonnement sur dev.

## OUT OF SCOPE

Lecture test, RAG actif, vision active, fine-tuning, métriques issues de réponses inventées.

## FILES ALLOWED

src/metrics.py; scripts/evaluate.py; tests/test_metrics.py; tests/test_evaluation.py; configs/evaluation.yaml; configs/experiment_lock.json; docs/evaluation.md; README.md; pyproject.toml; requirements.lock. Artefacts de validation sous runs/tickets/TICKET-14/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

evaluate(rows: list[GoldRecord], reports: list[TriageReport])->Metrics ; compare_internal_final(...) ; CLI options exactes docs/evaluation.md. null prediction compte comme échec ; labels ordre fixe, abstentions explicites.

## IMPLEMENTATION REQUIREMENTS

Valider les gold sans contenu et charger raw_path avec vérification raw_sha256 conformément à docs/contracts.md §2.8 avant tout appel ; mismatch ou champ interdit fait échouer G6. Implémenter toutes métriques obligatoires et supports, dont % SIMPLE/COMPLEX, qualité et coût par chemin. Première mesure avec gate BASELINE V0 et prompts V1 ; réglages dev seulement ensuite. Reprendre séparément les désaccords de fixtures G2, sans les incorporer aux scores Gold. Un run produit une ligne par sample_id ; réponses/authentiques/empreintes gelées. recompute lit les réponses capturées sans réseau et ne remplace pas le test live. Les échecs/outages restent dans dénominateurs. Exposer FPR strict/malveillant, validité première tentative, coût inconnu, couverture AUTO. La commande --variant baseline réalise aussi A/B/C sur les mêmes complexes gold_dev : A=MEDIUM email seul partagé, B=XHIGH avec preuves internes seules, C=XHIGH avec enrichissements réels. Archiver et recalculer B−A et C−B selon docs/evaluation.md §8.3 ; A−C seul ne prouve pas un gain externe. Valider les audits FINAL avant calcul : B doit avoir `external_evidence_count_sent=0`, `evidence_count_sent=internal_evidence_count_sent`, `rag_case_count_sent=0`, `visual_count_sent=0`; C doit transmettre les evidences externes admissibles lorsque le bundle en a produit et conserver `tool_status_digest`. Mismatch d'audit = comparaison B/C invalide et G6 FAIL, sans réparation silencieuse. VT unavailable reste dans les résultats/couverture/limites et ne bloque pas G6. G7-D facultatif hors baseline/PASS G6, sans ticket supplémentaire.

## TESTS REQUIRED

Calcul manuel sur un petit tableau de labels/prédictions pour l’arithmétique, hors benchmark : Macro-F1, abstention, classe jamais prédite, wrong→right/right→wrong/wrong→wrong ; reasoning non compté deux fois ; rejet gold avec contenu, fichier absent ou hash divergent avant appel ; vraie évaluation dev avec A/B/C, dénominateurs appariés et audits FINAL conformes ; cas négatifs où B contient une evidence externe ou C perd une evidence disponible doivent invalider la comparaison ; recalcul identique hors métadonnées de recalcul ; refus d’ouvrir le test avant gel.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_metrics.py tests/test_evaluation.py -q
python scripts/evaluate.py --split dev --mode live --variant baseline --out runs/eval/dev_baseline
python scripts/evaluate.py --mode recompute --from-run runs/eval/dev_baseline --out runs/eval/dev_recomputed
python scripts/check_gate.py G6 --record
```

## EXPECTED RESULTS

Exit 0 ; rapports complets avec métriques/support/couverture et preuve d'audit A/B/C ; recompute identique. Si support SIMPLE gold_dev=0, qualité SIMPLE est non estimable et la limitation est publiée sans faire échouer G6. Performance insuffisante n’annule pas la validité de mesure : conclusion NO/INCONCLUSIVE possible. Test non ouvert.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

G6 PASS sur protocole et baseline mesurée ; corpus/labels insuffisants explicités ; aucune promesse statistique excessive.

## FAIL CONDITIONS

Erreurs omises du dénominateur, prédictions simulées, confusion des coûts/temps offline-live, sélection des seuls outils disponibles, tuning sur test.

## ARTEFACTS PRODUCED

Résultats dev réels, matrice/deltas/coûts, manifest, baseline figée et reçuG6.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-14 — Évaluation baseline réelle et fermeture G6, gate G6. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
