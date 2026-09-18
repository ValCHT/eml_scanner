# TICKET-12 — Inspection des corpus et normalisation

## GATE

G6

## OBJECTIF

Construire un inventaire traçable des données réellement utilisables.

## PRECONDITIONS / DÉPENDANCES

PASS G5 ; archives publiques acquises légalement ; inspections du dossier disponibles comme référence, pas comme nouveaux résultats d’exécution.

## IN SCOPE

Acquisition bornée, manifest Parquet, JSONL, déduplication, contrôle source et labels à revoir.

## OUT OF SCOPE

Index Chroma, reconstruction de headers, validation automatique de vérité par Luna, téléchargement massif sans besoin.

## FILES ALLOWED

scripts/build_corpus.py; tests/test_corpus.py; corpus/sources.json; corpus/normalized/emails.jsonl; corpus/manifest.parquet; corpus/review/labels_template.jsonl; corpus/raw/iwspa/; corpus/raw/spamassassin/; corpus/raw/enron/; corpus/raw/phishfuzzer/; corpus/raw/nazario/; corpus/raw/private/ uniquement si fourni/autorisé; docs/corpus.md; pyproject.toml; requirements.lock. Artefacts de validation sous runs/tickets/TICKET-12/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

CLI inspect/normalize/dedupe ; read_dataset(source)->Iterator[NormalizedRecord] ; fingerprint(record)->str ; build_manifest(records)->Parquet. Champs obligatoires docs/corpus.md, header_integrity et attachment_representation inclus.

## IMPLEMENTATION REQUIREMENTS

Privilégier SpamAssassin et Nazario2025. Enron/PhishFuzzer optionnels. IWSPA archive non récupérée ici : ne pas inventer sa présence. Raw immuable, pas extraction hors périmètre. Conserver labels originaux, normalized_label=null jusqu’à revue. Fichiers JSON sans RFC822 gardent input_format distinct. Remplir tableau réel par source et rapporter dates/empreintes.

## TESTS REQUIRED

Archives réellement obtenues ; comptes cohérents raw/normalized/manifest ; hashes ; champs manquants ; filenames-only ; path traversal dans entrée d’extracteur ; doublons exacts/proches/familles intersources ; parser ne voit pas les labels de source.

## VALIDATION COMMANDS

```bash
python scripts/check_gate.py G5
python scripts/build_corpus.py inspect --sources corpus/sources.json --out runs/corpus/inspection
python scripts/build_corpus.py normalize --sources corpus/sources.json
python scripts/build_corpus.py dedupe --manifest corpus/manifest.parquet --seed 42
python -m pytest tests/test_corpus.py -q
```

## EXPECTED RESULTS

Exit 0 sur sources disponibles ; aucune ligne perdue sans note ; sources inaccessibles déclarées ; RAG/test absents à cette étape.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Inventaire fiable, provenance explicite ; annotations proposées à un analyste dans un fichier séparé sans préremplir de faux labels confirmés.

## FAIL CONDITIONS

Texte transformé en faux .eml, label source converti automatiquement en six classes, erreur de taille/doublons cachée.

## ARTEFACTS PRODUCED

Corpus raw/normalisé gitignored, manifest, rapport d’inspection et formulaire de revue humaine.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-12 — Inspection des corpus et normalisation, gate G6. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
