# TICKET-13 — Labels validés, familles et gel du Golden

## GATE

G6

## OBJECTIF

Séparer références publiques RAG, dev et test sans fuite.

## PRECONDITIONS / DÉPENDANCES

TICKET-12 DONE ; labels humains confirmés dans corpus/review/labels.jsonl ; responsable évaluation désigné avec emplacement de holdout hors poste de build.

## IN SCOPE

Validation des annotations, sélection indicative 200, groupes disjoints, scellement et reçu agrégé.

## OUT OF SCOPE

Produire soi-même des labels supposés analyste, afficher le holdout aux agents, index RAG effectif, retuning.

## FILES ALLOWED

scripts/build_corpus.py; tests/test_corpus.py; corpus/manifest.parquet; corpus/gold/gold_dev.jsonl; corpus/gold/test_seal.json; corpus/rag/public_cases.jsonl; docs/corpus.md; docs/evaluation.md. gold_test.jsonl et ses raw sont écrits seulement par le responsable évaluation dans son espace distinct, jamais dans le checkout de build. Artefacts de validation sous runs/tickets/TICKET-13/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

select_gold(manifest, reviewed_labels, seed=42)->SplitPlan ; freeze_test(split, destination)->Seal. Partition par family_group, aucun groupe dans deux splits. RAG cases public_source=true et label_status=confirmed uniquement, split=rag_reference.

## IMPLEMENTATION REQUIREMENTS

GoldRecord strict de docs/contracts.md §2.8 : métadonnées/labels uniquement dans gold_dev/gold_test, raw_path et raw_sha256 obligatoires ; email_sha256 V1 conservé et égal. Aucun contenu email/HTML/headers/MIME/pièce/image/extrait privé, y compris dans label_rationale. Les bytes restent dans corpus/raw/** git-ignoré. Valider ce contrat et les hashes avant sélection ; loader résout raw_path et refuse le sample en cas de mismatch avant analyse. Objectifs 50/30/30/20/30/40, sans remplir les déficits avec de faux labels. Réserver les familles des 150 références publiques RAG, puis dev/test. Vérifier collisions de source, seed, fingerprint et campagne. Le responsable garde le test dans son espace ; l’agent reçoit uniquement un reçu agrégé et une empreinte. Annotations ou espace distinct manquants : BLOCKED. Le gold reste utilisable pour mesurer un résultat non concluant si certaines classes manquent, avec cette limite explicite.

## TESTS REQUIRED

Champs body/html/headers/raw/raw_email/mime_content et autres contenus interdits rejetés même vides/nichés ; chemin absent/hors raw et hash divergent refusés ; contrôle sur dev et objets locaux de contrat sans accès au holdout. Intersection des groupes vide ; seeds PhishFuzzer inséparables ; privé refusé au RAG ; annotations non confirmées/ambiguës exclues ; split reproductible ; seal sensible à un byte changé ; aucune donnée test montée dans l’environnement d’agent.

## VALIDATION COMMANDS

```bash
python scripts/build_corpus.py select --manifest corpus/manifest.parquet --labels corpus/review/labels.jsonl --seed 42
python scripts/build_corpus.py verify-splits --manifest corpus/manifest.parquet
python -m pytest tests/test_corpus.py -q
```

## EXPECTED RESULTS

Exit 0 ; splits sans collision ; nombre/support réel rapporté ; responsable fournit corpus/gold/test_seal.json. Sinon statut BLOCKED/FAIL, pas de holdout inventé.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Gold dev exploitable, test scellé et inaccessible au build ; références RAG exclusivement publiques et séparées de tous les gold.

## FAIL CONDITIONS

Contenu email dans un fichier gold, raw_sha256 incohérent ou raw_path hors périmètre, validation humaine fabriquée, groupes qui traversent splits, consultation test par coding agent, import privé dans public_cases.

## ARTEFACTS PRODUCED

Dev, manifest des partitions, index-source public non vectorisé, reçu de gel ; jalon humain explicite.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-13 — Labels validés, familles et gel du Golden, gate G6. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
