# TICKET-15 — RAG embarqué exclusivement public

## GATE

G7-A

## AMENDEMENT OPÉRATEUR (2026-09-21, trajectoire accélérée) — développement parallèle, sample borné

Aucun benchmark complet avant T19E : T15 exécute l'ablation RAG **uniquement sur le sample/smoke dev borné** (le smoke T14 de `runs/eval/dev_smoke`, ou un sample borné équivalent documenté dans le manifest), jamais sur les 83 emails. Le développement de T15 est **parallèle à T16 et à la chaîne T19A→T19B** (indépendant de la vision et de l'agentique) ; la fermeture expérimentale G7-A peut être enregistrée plus tard. Statut de fin de phase d'implémentation parallèle : **`IMPLEMENTED_WAITING_FOR_G6_SYNC`** (voir VALIDATION COMMANDS). `--paired-with runs/eval/dev_smoke` ; sortie sous `runs/eval/dev_rag_smoke`. Les métriques restent diagnostiques (`measurement_scope` archivé, `performance_claims_allowed=false`) ; INCONCLUSIVE est un résultat valide. Les résultats alimentent T19C ; le premier benchmark complet (avec et sans RAG, rerun simultané de la V1 fixe) est T19E.

## OBJECTIF

Tester si des précédents publics améliorent le classement.

## PRECONDITIONS / DÉPENDANCES

Développement autorisé en parallèle de T16 et T19A/B ; la fermeture expérimentale G7-A peut attendre l'état G6/synchronisation approprié ; public_cases.jsonl validé/hors gold ; embedding local disponible avec empreinte ; décision explicite de lancer l'expérience optionnelle.

## IN SCOPE

Chroma local, add/search/clear, exclusion des familles, ablation live.

## OUT OF SCOPE

Indexation privé/SOC, gold_dev/gold_test, prédictions automatiques, sync CTI, GraphRAG, autre base ou serveur.

## FILES ALLOWED

src/tools/rag.py; src/graph.py pour remplacement du no-op existant; scripts/manage_rag.py; scripts/evaluate.py; src/metrics.py; tests/test_rag.py; tests/test_metrics.py; tests/test_evaluation.py; configs/tools.yaml; configs/experiment_lock.json; docs/corpus.md; docs/evaluation.md; pyproject.toml; requirements.lock. Artefacts de validation sous runs/tickets/TICKET-15/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

add(cases: list[RagCase]) -> int ; search(query: str, exclusions: set[str], k: int = 3) -> list[RagCase] ; clear() -> None. Collection unique, distance cosine, modèle ONNX all-MiniLM-L6-v2 avec version et empreinte gelées. Chaque cas impose is_public=true et split=rag_reference.

**Interface évaluateur appariée (review PR #15, 2026-09-21) — implémentée par ce ticket.** `scripts/evaluate.py` doit accepter `--variant rag` et `--paired-with <run-dir>` pour un run `--sample-profile smoke` :
- le run apparié est un run baseline archivé (`runs/eval/dev_smoke`) : il est LU seul, jamais rejoué, et ses lignes/reports ne sont jamais modifiés ;
- la comparaison apparie exactement les mêmes `sample_id` (identité de sélection vérifiée) et exige des dénominateurs identiques ; une ligne manquante ou surnuméraire = FAIL ;
- `measurement_scope=smoke` et `performance_claims_allowed=false` restent archivés ; les métriques restent diagnostiques, INCONCLUSIVE valide ;
- aucun tuning sur les résultats ; les résultats alimentent T19C ; le premier benchmark complet avec/sans RAG est T19E.

## IMPLEMENTATION REQUIREMENTS

Indexer sujet et corps utile, sans label ni justification dans le texte d’embedding. Source publique et validation humaine obligatoires. Au plus 3 cas de 1 200 caractères chacun, un par family_group ; exclure toutes les familles des gold. Seuil initial de distance 0,40, réglé seulement sur dev. Aucun voisin forcé. Les cas entrent comme contexte d’inférence, sans ajouter leurs IOC au registre courant. Flag désactivé : ne pas importer Chroma ni charger les poids.

## TESTS REQUIRED

Refus d’un cas privé, gold ou non confirmé ; clear ; add idempotent ; exclusions de groupes/campagnes ; retrieval sur un cas identique hors évaluation puis vérification de son exclusion. Véritables ablations baseline/RAG avec mêmes snapshots externes. Revue de pertinence sur 20 requêtes dev par analyste ; application des critères KEEP/NO/INCONCLUSIVE.

## VALIDATION COMMANDS

### IMPLEMENTATION VALIDATION (exécutable maintenant — phase parallèle)

```bash
python -m pip install -e ".[dev,rag]"
python -m pytest tests/test_rag.py tests/test_metrics.py tests/test_evaluation.py -q
python scripts/manage_rag.py add --input corpus/rag/public_cases.jsonl
```

Fin de phase : statut **`IMPLEMENTED_WAITING_FOR_G6_SYNC`**. C'est un succès de la phase d'implémentation parallèle, pas un BLOCKED/FAIL. L'agent s'arrête ici.

### DEFERRED EXPERIMENTAL CLOSURE (plus tard, après le point de synchronisation/G6 choisi par l'opérateur)

Ablation live appariée puis fermeture G7-A — à n'exécuter que sur décision/synchronisation opérateur :

```bash
python scripts/evaluate.py --split dev --mode live --variant rag --sample-profile smoke --paired-with runs/eval/dev_smoke --out runs/eval/dev_rag_smoke
python scripts/check_gate.py G7-A --record
```

## EXPECTED RESULTS

**Implémentation (maintenant)** : Exit 0 ; index exclusivement public ; tests déterministes verts ; statut `IMPLEMENTED_WAITING_FOR_G6_SYNC` ; aucune évaluation live appariée, aucun reçu de gate.

**Fermeture différée (plus tard)** : Exit 0 ; comparaison réelle sans fuite ; rapport de décision même sans gain ; baseline fonctionnelle avec RAG désactivé.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Ticket PASS signifie : implémentation complète et validée dans la phase parallèle, statut `IMPLEMENTED_WAITING_FOR_G6_SYNC` — la fermeture expérimentale différée (ablation live + G7-A) est jugée séparément. Garder RAG uniquement selon les critères préenregistrés ; le test reste fermé.

## FAIL CONDITIONS

Cas privé ou gold indexé ; verdict Luna non confirmé utilisé comme vérité ; gain dû à un doublon ; nouvelle infrastructure ; absence de mesure.

## ARTEFACTS PRODUCED

Adaptateur RAG facultatif, index local gitignored ; évaluation live appariée et décision G7-A produites lors de la fermeture différée.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-15 — RAG embarqué exclusivement public, gate G7-A, en **phase d'implémentation parallèle**. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s'il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance uniquement les commandes de la section **IMPLEMENTATION VALIDATION** et arrête-toi au statut `IMPLEMENTED_WAITING_FOR_G6_SYNC` : c'est un succès de la phase parallèle, pas un BLOCKED/FAIL. Ne lance PAS la fermeture expérimentale différée (évaluation live appariée et `check_gate.py G7-A --record`) sans le point de synchronisation/G6 choisi par l'opérateur. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket (`IMPLEMENTED_WAITING_FOR_G6_SYNC`) et statut de la gate (G7-A non fermée, différée). Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l'utilisateur n'est nécessaire.
