# TICKET-15 — RAG embarqué exclusivement public

## GATE

G7-A

## OBJECTIF

Tester si des précédents publics améliorent le classement.

## PRECONDITIONS / DÉPENDANCES

PASS G6 ; public_cases.jsonl validé/hors gold ; embedding local disponible avec empreinte ; décision explicite de lancer expérience optionnelle.

## IN SCOPE

Chroma local, add/search/clear, exclusion des familles, ablation live.

## OUT OF SCOPE

Indexation privé/SOC, gold_dev/gold_test, prédictions automatiques, sync CTI, GraphRAG, autre base ou serveur.

## FILES ALLOWED

src/tools/rag.py; src/graph.py pour remplacement du no-op existant; scripts/manage_rag.py; tests/test_rag.py; configs/tools.yaml; configs/experiment_lock.json; docs/corpus.md; docs/evaluation.md; pyproject.toml; requirements.lock. Artefacts de validation sous runs/tickets/TICKET-15/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

add(cases: list[RagCase]) -> int ; search(query: str, exclusions: set[str], k: int = 3) -> list[RagCase] ; clear() -> None. Collection unique, distance cosine, modèle ONNX all-MiniLM-L6-v2 avec version et empreinte gelées. Chaque cas impose is_public=true et split=rag_reference.

## IMPLEMENTATION REQUIREMENTS

Indexer sujet et corps utile, sans label ni justification dans le texte d’embedding. Source publique et validation humaine obligatoires. Au plus 3 cas de 1 200 caractères chacun, un par family_group ; exclure toutes les familles des gold. Seuil initial de distance 0,40, réglé seulement sur dev. Aucun voisin forcé. Les cas entrent comme contexte d’inférence, sans ajouter leurs IOC au registre courant. Flag désactivé : ne pas importer Chroma ni charger les poids.

## TESTS REQUIRED

Refus d’un cas privé, gold ou non confirmé ; clear ; add idempotent ; exclusions de groupes/campagnes ; retrieval sur un cas identique hors évaluation puis vérification de son exclusion. Véritables ablations baseline/RAG avec mêmes snapshots externes. Revue de pertinence sur 20 requêtes dev par analyste ; application des critères KEEP/NO/INCONCLUSIVE.

## VALIDATION COMMANDS

```bash
python -m pip install -e ".[dev,rag]"
python -m pytest tests/test_rag.py -q
python scripts/manage_rag.py add --input corpus/rag/public_cases.jsonl
python scripts/evaluate.py --split dev --mode live --variant rag --paired-with runs/eval/dev_baseline --out runs/eval/dev_rag
python scripts/check_gate.py G7-A --record
```

## EXPECTED RESULTS

Exit 0 ; index exclusivement public ; comparaison réelle sans fuite ; rapport de décision même sans gain ; baseline fonctionnelle avec RAG désactivé.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Ticket PASS signifie expérience menée correctement. Garder RAG uniquement selon les critères préenregistrés ; le test reste fermé.

## FAIL CONDITIONS

Cas privé ou gold indexé ; verdict Luna non confirmé utilisé comme vérité ; gain dû à un doublon ; nouvelle infrastructure ; absence de mesure.

## ARTEFACTS PRODUCED

Adaptateur RAG facultatif, index local gitignored, évaluation et décision G7-A.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-15 — RAG embarqué exclusivement public, gate G7-A. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
