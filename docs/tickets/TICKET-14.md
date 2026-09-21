# TICKET-14 — Évaluation baseline réelle et fermeture G6

## GATE

G6

## OBJECTIF

**Amendement opérateur (2026-09-21) : G6 est une gate de validation du HARNESS, pas un benchmark de performance.** Mesurer que le harness est exécutable et auditable sur un smoke live borné (5 Gold dev représentatifs) et rendre les métriques auditables ; aucun benchmark complet avant TICKET-19 (T14–T18 utilisent uniquement des samples/smokes bornés).

## PRECONDITIONS / DÉPENDANCES

Tickets12–13 DONE ; PASS G5 ; dev validé ; Luna et accès CTI/urlscan validés selon G4, VT indisponible admis et signalé ; test scellé et non ouvert.

## IN SCOPE

Scripts evaluate/recompute, métriques, confusion, coûts, latence, internal/final, contrôle deuxième raisonnement sur un smoke dev borné. Validation offline d'intégrité des 83 GoldRecords/raw AVANT tout appel ; smoke live `--sample-profile smoke` (un `sample_id` lexicographiquement premier par label à support>0 ; menace=0 non fabriqué) ; métriques diagnostiques uniquement (`measurement_scope="smoke"`, `performance_claims_allowed=false`).

## OUT OF SCOPE

Lecture test, RAG actif, vision active, fine-tuning, métriques issues de réponses inventées, **benchmark complet des 83 emails (réservé à T19)**, toute présentation du smoke comme baseline performance/Macro-F1 représentatif/validation statistique.

## FILES ALLOWED

src/metrics.py; scripts/evaluate.py; tests/test_metrics.py; tests/test_evaluation.py; configs/evaluation.yaml; configs/experiment_lock.json; docs/evaluation.md; README.md; pyproject.toml; requirements.lock; scripts/check_gate.py (commande G6 uniquement — amendement opérateur 2026-09-21). Artefacts de validation sous runs/tickets/TICKET-14/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

evaluate(rows: list[GoldRecord], reports: list[TriageReport])->Metrics ; compare_internal_final(...) ; CLI options exactes docs/evaluation.md (`--split`, `--mode live|recompute`, `--variant`, `--sample-profile {smoke,full}` requis en live, `--out`, `--from-run`, `--evaluation-config`, `--experiment-lock`). null prediction compte comme échec ; labels ordre fixe, abstentions explicites. Le manifest/report enregistre `measurement_scope`, `performance_claims_allowed`, `sample_selection_rule`, `selected_sample_ids` et `full_dev_label_support`.

## IMPLEMENTATION REQUIREMENTS

Valider les gold sans contenu et charger raw_path avec vérification raw_sha256 conformément à docs/contracts.md §2.8 avant tout appel : l'intégrité des **83** records/raw est vérifiée hors ligne, puis seuls les records sélectionnés reçoivent des appels live ; mismatch ou champ interdit fait échouer G6. Implémenter toutes métriques obligatoires et supports, dont % SIMPLE/COMPLEX, qualité et coût par chemin. Le smoke utilise le gate BASELINE V0 et les prompts V1 ; réglages dev seulement ensuite ; aucun benchmark complet avant T19. Un run produit une ligne par sample_id ; réponses authentiques/empreintes gelées. recompute lit les réponses capturées sans réseau, reproduit exactement les lignes archivées, vérifie leur identité contre la sélection déterministe (pas d'exigence len==83 pour un run smoke) et ne remplace pas le run live. Les échecs/outages/timeout restent dans dénominateurs et ne bloquent pas G6 par eux-mêmes. Exposer FPR strict/malveillant, validité première tentative, coût inconnu, couverture AUTO. La commande `--variant baseline --sample-profile smoke` réalise aussi A/B/C sur les complexes du smoke : A=MEDIUM email seul partagé, B=XHIGH avec preuves internes seules, C=XHIGH avec enrichissements réels. Archiver et recalculer B−A et C−B selon docs/evaluation.md §8.3 ; A−C seul ne prouve pas un gain externe. Valider les audits FINAL avant calcul : B doit avoir `external_evidence_count_sent=0`, `evidence_count_sent=internal_evidence_count_sent`, `rag_case_count_sent=0`, `visual_count_sent=0`; C doit transmettre les evidences externes admissibles lorsque le bundle en a produit et conserver `tool_status_digest`. Mismatch d'audit = comparaison B/C invalide et G6 FAIL, sans réparation silencieuse. VT unavailable reste dans les résultats/couverture/limites et ne bloque pas G6. Les métriques du smoke sont diagnostiques uniquement : jamais présentées comme baseline performance, Macro-F1 représentatif ou validation statistique ; aucun tuning à partir d'elles. G7-D facultatif hors baseline/PASS G6, sans ticket supplémentaire.

## TESTS REQUIRED

Calcul manuel sur un petit tableau de labels/prédictions pour l'arithmétique, hors benchmark : Macro-F1, abstention, classe jamais prédite, wrong→right/right→wrong/wrong→wrong ; reasoning non compté deux fois ; rejet gold avec contenu, fichier absent ou hash divergent avant appel ; vraie évaluation du smoke avec A/B/C, dénominateurs appariés et audits FINAL conformes ; cas négatifs où B contient une evidence externe ou C perd une evidence disponible doivent invalider la comparaison ; recalcul identique hors métadonnées de recalcul ; identité du smoke contre la sélection déterministe (ligne manquante ou surnuméraire = FAIL) ; refus d'ouvrir le test avant gel ; refus d'un run live sans `--sample-profile` explicite.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_corpus.py tests/test_metrics.py tests/test_evaluation.py -q
python scripts/evaluate.py --split dev --mode live --variant baseline --sample-profile smoke --out runs/eval/dev_smoke
python scripts/evaluate.py --mode recompute --from-run runs/eval/dev_smoke --out runs/eval/dev_smoke_recomputed
python scripts/check_gate.py G6 --record
```

## EXPECTED RESULTS

Exit 0 ; rapports complets avec métriques diagnostiques/support/couverture et preuve d'audit A/B/C ; recompute identique ; aucun benchmark complet exécuté (T19). PASS G6 signifie : harness réel exécuté sur le smoke, aucune simulation, Gold/raw intègres, audit A/B/C valide lorsqu'applicable, sorties/reports valides, recompute exact, tests déterministes verts. PASS G6 NE signifie PAS que la qualité du modèle est démontrée. Performance insuffisante n'annule pas la validité de mesure. Test non ouvert.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d'entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

G6 PASS sur protocole et harness validé par smoke réel borné ; corpus/labels insuffisants explicités ; aucune promesse statistique excessive ; premier benchmark complet = T19.

## FAIL CONDITIONS

Erreurs omises du dénominateur, prédictions simulées, confusion des coûts/temps offline-live, sélection des seuls outils disponibles, tuning sur test ou sur le smoke, présentation du smoke comme performance, lancement du benchmark 83 emails avant T19.

## ARTEFACTS PRODUCED

Résultats smoke réels (5 cas), matrice/deltas/coûts, manifest avec scope, sélection figée et reçu G6.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-14 — Évaluation baseline réelle et fermeture G6, gate G6 (amendement opérateur 2026-09-21 : validation du harness par smoke borné, aucun benchmark complet avant T19). Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s'il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l'utilisateur n'est nécessaire.
