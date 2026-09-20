# TICKET-13 — Labels validés, familles et gel du Golden

## GATE

G6

## AMENDEMENT OPÉRATEUR (2026-09-20, approuvé explicitement)

Le précondition historique « labels humains confirmés » est remplacé, pour ce
POC exploratoire uniquement, par le protocole Gold-AI approuvé par l'opérateur :
l'annotation ChatGPT (Silver) suivie d'une annotation/adjuration indépendante
GPT-6 Astra accomplit l'étape de revue fonctionnelle. Une référence est
éligible si (A) confirmation humaine réelle, OU (B) le protocole Gold-AI :
`final_status == "ai_adjudicated"`, `final_label` valide, `reviewer_ref ==
"astra_gold_ai_v1"`, `review_method == "independent_dual_model_ai_adjudication"`,
`human_validated == false`. Ces faits de provenance RESTENT VRAIS et ne sont
jamais réécrits : jamais `human_validated=true`, jamais de `reviewer_ref`
humain inventé, jamais « human-confirmed », « analyst-validated » ou « ground
truth » humain. Terminologie admise : *AI-adjudicated reference labels*,
*Gold-AI*, *reference-confirmed*. La conversion de l'artefact d'adjuration
externe vers le schéma canonique (`corpus/review/labels.jsonl`) est une
conversion de format déterministe, PAS un nouveau labeling sémantique par
l'agent. La condition d'échec « validation humaine fabriquée » reste
totalement active.

**Simplification POC (second amendement opérateur, 2026-09-20).** L'exigence de
holdout externe hors poste de build est levée pour ce POC exploratoire. Le
split dev/test déterministe (seed 42, familles disjointes) est conservé tel
quel (83 dev / 83 test), tous les invariants raw/hash/contenu restent en
vigueur, et `test_seal.json` reste produit/vérifié pour la reproductibilité.
`corpus/gold/gold_test.jsonl` peut désormais exister dans le dépôt/workspace de
build comme fichier de **métadonnées/labels uniquement** (GoldRecord fermé,
aucun contenu). Il n'y a plus de responsable évaluation externe ni de statut
intermédiaire obligatoire `WAITING_FOR_HOLDOUT_SEAL`. Divulgation explicite :
**`gold_test` est une partition de validation interne du POC, pas un holdout
indépendant, isolé ou aveuglé.** Interdits maintenus : tout tuning, changement
de prompt, de seuil ou sélection de modèle fondé sur `gold_test` ; les
décisions de développement utilisent `gold_dev` uniquement.

## OBJECTIF

Séparer références publiques RAG, dev et test sans fuite.

## PRECONDITIONS / DÉPENDANCES

TICKET-12 DONE ; labels humains confirmés dans corpus/review/labels.jsonl OU
(opérateur, amendement ci-dessus) référence Gold-AI `astra_gold_ai_v1`
convertie dans le schéma canonique. Plus de responsable évaluation externe
requis pour ce POC : la partition de validation interne est matérialisée dans
le workspace de build (métadonnées/labels seulement) avec son sceau.

## IN SCOPE

Validation des annotations, sélection indicative 200, groupes disjoints, scellement et reçu agrégé.

## OUT OF SCOPE

Produire soi-même des labels supposés analyste, afficher le contenu email du gold aux agents, index RAG effectif, retuning. La conversion déterministe de l'artefact Gold-AI externe en labels canoniques est en périmètre ; toute nouvelle décision sémantique de label par l'agent reste hors périmètre. Tout tuning, changement de prompt/seuil/variante ou sélection de modèle fondé sur gold_test reste hors périmètre et interdit.

## FILES ALLOWED

scripts/build_corpus.py; tests/test_corpus.py; corpus/manifest.parquet; corpus/review/labels.jsonl (conversion canonique déterministe de l'artefact Gold-AI approuvé, conservé comme audit source); corpus/gold/gold_dev.jsonl; corpus/gold/gold_test.jsonl (partition de validation interne, métadonnées/labels uniquement); corpus/gold/test_seal.json (reçu agrégé de reproductibilité); corpus/rag/public_cases.jsonl; docs/corpus.md; docs/evaluation.md; docs/contracts.md; docs/tickets/TICKET-13.md (amendements opérateur); .gitignore et AGENTS.md (amendement opérateur : suivi des artefacts métadonnées approuvés et clarification de l'invariant holdout). Les bytes raw restent dans corpus/raw/** git-ignoré, jamais dupliqués dans les gold. Artefacts de validation sous runs/tickets/TICKET-13/ (dont inputs/ copies immuables) et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

select_gold(manifest, reviewed_labels, seed=42)->SplitPlan ; freeze_test(split, destination)->Seal. Extension Gold-AI : pool candidat opérateur protégé (--gold-candidates), familles uniques, jamais ré-ordonnées ni substituées. Partition par family_group, aucun groupe dans deux splits. RAG cases public_source=true et label_status=confirmed uniquement, split=rag_reference ; familles Gold protégées exclues du RAG ; ambiguës exclues de Gold et RAG ; seed 42 ; aucune valeur de confiance n'est filtre de sélection ou de cas facile. POC simplifié : `freeze` matérialise `gold_test.jsonl` (métadonnées/labels seulement) et `test_seal.json` dans le workspace de build ; `verify-splits` re-dérive le plan, compare les trois fichiers au recalcul, valide le sceau (schema + agrégats + gold_test_sha256 vs bytes réels).

## IMPLEMENTATION REQUIREMENTS

GoldRecord strict de docs/contracts.md §2.8 : métadonnées/labels uniquement dans gold_dev/gold_test, raw_path et raw_sha256 obligatoires ; email_sha256 V1 conservé et égal. Aucun contenu email/HTML/headers/MIME/pièce/image/extrait privé, y compris dans label_rationale. Les bytes restent dans corpus/raw/** git-ignoré. Valider ce contrat et les hashes avant sélection ; loader résout raw_path et refuse le sample en cas de mismatch avant analyse. Objectifs 50/30/30/20/30/40, sans remplir les déficits avec de faux labels. Réserver les familles des 150 références publiques RAG, puis dev/test. Vérifier collisions de source, seed, fingerprint et campagne. POC simplifié (amendement 2) : `gold_test.jsonl` est matérialisé dans le workspace de build comme fichier de **métadonnées/labels uniquement** — ce n'est PAS un holdout indépendant ; `test_seal.json` (reçu agrégé + empreinte) reste obligatoire et validé contre les bytes réels. `gold_test` ne doit JAMAIS servir au tuning, à un changement de prompt, de seuil, de variante ou de modèle ; les décisions de développement utilisent `gold_dev` uniquement. Aucune validation humaine n'est revendiquée. Annotations ou artefacts manquants : BLOCKED. Le gold reste utilisable pour mesurer un résultat non concluant si certaines classes manquent, avec cette limite explicite.

## TESTS REQUIRED

Champs body/html/headers/raw/raw_email/mime_content et autres contenus interdits rejetés même vides/nichés ; chemin absent/hors raw et hash divergent refusés ; contrôle sur dev, test (métadonnées/labels uniquement) et objets locaux de contrat. Intersection des groupes vide (dev/test/RAG) ; seeds PhishFuzzer inséparables ; privé refusé au RAG ; annotations non confirmées/ambiguës exclues ; split reproductible (seed 42) ; seal sensible à un byte changé de l'objet test ; candidate Gold absent de l'adjuration complète ou au raw_sha256 divergent refusé par les chemins CLI réels ; aucune donnée d'un éventuel holdout externe indépendant montée dans l'environnement d'agent.

## VALIDATION COMMANDS

```bash
python scripts/build_corpus.py labels --adjudication <artefact Gold-AI approuvé> --manifest corpus/manifest.parquet
python scripts/build_corpus.py select --manifest corpus/manifest.parquet --labels corpus/review/labels.jsonl --adjudication <artefact Gold-AI approuvé> --gold-candidates <pool approuvé> --seed 42
python scripts/build_corpus.py freeze --manifest corpus/manifest.parquet --labels corpus/review/labels.jsonl --adjudication <artefact Gold-AI approuvé> --gold-candidates <pool approuvé> --seed 42 --destination corpus/gold
python scripts/build_corpus.py verify-splits --manifest corpus/manifest.parquet --labels corpus/review/labels.jsonl --adjudication <artefact Gold-AI approuvé> --gold-candidates <pool approuvé> --seed 42
python -m pytest tests/test_corpus.py -q
python -m pytest -q
python -m pip check
git diff --check
```

## EXPECTED RESULTS

Exit 0 ; splits sans collision (83 dev / 83 test, familles disjointes) ; nombre/support réel rapporté (déficits visibles, jamais comblés : menace=0, spear_phishing=16 Gold-AI, RAG spam borné par la disponibilité réelle) ; `gold_test.jsonl` matérialisé (métadonnées/labels uniquement) + `test_seal.json` (version, split=test, record_count, family_count, label_support agrégé, seed=42, gold_test_sha256, selection_protocol, created_at, reference_method, reviewer_ref, human_validated=false ; jamais d'ID individuels dans le sceau) ; sceau validé contre les bytes réels du test. Statut DONE si tout passe. BLOCKED seulement pour un prérequis réel manquant : artefacts externes manquants ou hash divergent, manifest incohérent, sceau invalide, invariant de sécurité insatisfait. Jamais BLOCKED au seul motif human_validated=false, explicitement accepté par l'amendement.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold. Pour ce POC approuvé : `gold_test.jsonl` est une partition de validation interne (métadonnées/labels uniquement), matérialisée et validée dans le workspace de build ; ce n'est PAS un holdout indépendant, et toute utilisation pour tuning/prompt/seuil/variante/sélection de modèle reste interdite — développement sur `gold_dev` uniquement. Les éventuels holdouts externes indépendants (désignés hors poste de build) restent inaccessibles aux agents de build.

## ACCEPTANCE CRITERIA

Gold dev exploitable ; `gold_test.jsonl` matérialisé (métadonnées/labels uniquement, validation interne POC — pas un holdout indépendant) et scellé par `test_seal.json` validé ; dev/test/RAG familles disjointes ; références RAG exclusivement publiques et séparées de tous les gold ; aucune décision de développement fondée sur gold_test.

## FAIL CONDITIONS

Contenu email dans un fichier gold, raw_sha256 incohérent ou raw_path hors périmètre, validation humaine fabriquée ou revendiquée, groupes qui traversent splits, tuning/prompt/seuil/variante/sélection de modèle fondé sur gold_test, candidate Gold absent de l'adjuration complète ou au raw_sha256 divergent accepté, import privé dans public_cases, holdout externe indépendant accessible par un agent de build.

## ARTEFACTS PRODUCED

Dev, test (partition de validation interne, métadonnées/labels uniquement), manifest des partitions, index-source public non vectorisé, reçu de gel (test_seal.json) ; jalon d'adjuration opérateur explicite (pas de jalon humain — aucune validation humaine revendiquée).

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-13 — Labels validés, familles et gel du Golden, gate G6. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
