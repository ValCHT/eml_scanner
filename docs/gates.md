# 5. Gates d'implémentation et exécution Codex

**Binding runtime courant (19/09/2026, précisé par l'opérateur le 20/09/2026) :** AkashML + `Qwen/Qwen3.8-27B` pour tout run officiel, dont la matrice G2 consommée par TICKET-05. `openai/gpt-oss-20b` est réservé aux smokes et validations techniques, archivés séparément, et ne peut jamais produire `runs/gates/G2/assessments.jsonl` ni `fixture_performance.jsonl`. `Qwen3.6-35B-A3B` est autorisé pour le développement non officiel uniquement — boucles bon marché, tests live fonctionnels/débogage nécessitant un LLM, pré-validation avant un run officiel — et ne peut produire aucune évidence de gate ni mesure baseline ; aucun ID fournisseur Akash n'est revendiqué, l'ID exact doit provenir de la liste de modèles de l'endpoint configuré. Les preuves G2 historiques Genspark + `claude-haiku-4-5` restent historiques. Orange LiteLLM demeure une cible future via configuration `LITELLM_*` uniquement.

**Périmètre explicite :** ce dépôt est un outil indépendant d'analyse d'emails suspects / de phishing. Il traite les messages individuellement : aucun historique de boîte mail, aucun modèle de relations organisationnelles, aucun BusinessContext. AUTO/REVIEW/ESCALATE restent des recommandations ; le runtime n'agit jamais sur une boîte mail.

## 5.1 Ordre obligatoire et définition de PASS

`G0 → PASS → G1 → PASS → G2 → PASS → G3 → PASS → G4 → PASS → G5 → PASS → G6 → PASS`. G6 a été rejoué le 22/09/2026 sur `main` propre après le merge PR #19 (`c0273d61689ee7df55d25d33106b652d36c88d47`) avec `Qwen/Qwen3.8-27B` : reçu PASS, smoke HARNESS borné à 5 emails, aucune conclusion de performance. Après G6 (amendement opérateur 2026-09-21, trajectoire accélérée vers l'agentique) : trois pistes de développement **parallèles** — T15 (RAG ; mergé PR #16, fermeture G7-A différée/optionnelle), T16 (vision/QR ; mergé PR #18, smoke de capacité vision live **PASS** — `runs/gates/G7-B/smoke_vision/smoke_result.json`, `status=live_ok` ; fermeture G7-B différée/optionnelle), T19A→T19B (chaîne agentique ; mergée PR #17, indépendante de RAG et Vision) — ont convergé en **T19C** (mergé PR #19, `IMPLEMENTED_SMOKE_VALIDATED`) ; **T19D est la prochaine étape** (fichier ticket non encore matérialisé), puis T19E, la **mesure terminale** (premier benchmark complet avec rerun simultané de la V1 fixe). Les fermetures G7-A/G7-B restent différées/optionnelles avant T19E ; T17 est optionnel après T19E ; T18 est SUPERSEDED BY T19E.

Ce dossier est un plan : statut initial de toutes les gates = NOT_STARTED. PASS signifie exécution effective et preuve archivée ; aucun PASS n'est déduit du nombre de fichiers écrits.

| Gate | Tickets | PASS autorisant la transition |
|---|---|---|
| G0 | 01–02 | installation propre et lock cohérent ; imports, Settings, enums, modèles/schemas et configuration pytest passent ; client minimal testé ; smoke LLM réel si credentials disponibles. Un smoke technique peut utiliser GPT-OSS sans devenir une mesure POC. Si absent : mention live_pending, autorisée uniquement pour G0, levée obligatoirement avant G2 PASS. Aucun parsing/enrichissement avant G0 PASS. |
| G1 | 03 | toutes les fixtures lisibles dans leur limite ; hashes/URLs/headers vérifiés ; malformed sans crash ; aucun réseau ; metadata images sans vision. |
| G2 | 04 | Vrai endpoint AkashML + modèle exact `Qwen/Qwen3.8-27B` + structured output Assessment démontrés ; sorties acceptées conformes au schema, six probabilités valides et IDs existants ; contenu transmis vérifié selon §5.1.1 ; aucune donnée externe ni instruction de fixture exécutée ; erreurs/refus/timeouts et résultats réels archivés. Mauvaise classification ≠ FAIL G2. Absence de clé/capacité, substitution de modèle ou aucun succès structuré réel = BLOCKED. |
| G3 | 05 | R1/R2/R3, frontières et branches SIMPLE/COMPLEX passent sur entrées déterministes ; toutes les sorties réelles du runtime G2 officiel Qwen3.8 sont également évaluées et leur distribution archivée. L’absence de SIMPLE live avant G6 ne bloque pas PASS : `simple_path_live_observed=false` est alors une limitation explicite. Gate sans réseau/label gold et sans modification des seuils. |
| G4 | 06–08 | Trois adaptateurs présents ; OpenCTI et urlscan validés réellement comme en V1. VT : appels réels si disponibles, sinon `unavailable` motivé et traitement vérifié autorisent PASS ; couverture nominale non validée explicitée. Confidentialité, GET VT uniquement, erreurs et poursuite du pipeline vérifiés ; aucun faux enrichissement. Les pannes du moment peuvent utiliser les captures réelles existantes pour régression, avec leur date. |
| G5 | 09–11 | pipeline live complet sur fixtures ; au moins un message bénin construit avec LIVE_BENIGN_URL traverse le vrai enrichissement et FINAL ; un seul conditional edge ; branche SIMPLE (1 appel nominal) et branche COMPLEX (2 appels nominaux) démontrées au niveau code, tandis que le batch live suit exclusivement les décisions réelles du gate. L’absence de SIMPLE live reste non bloquante avant G6 et est tracée. Audits FINAL §5.1.2, V01–V16, policy, JSON/résumé et coupures réelles/budgets/fallback vérifiés. |
| G6 | 12–14 | corpus inspecté et labels revus ; gold sans contenu email, raw_path résolu et raw_sha256 vérifié ; dev/test groupés sans fuite ; **amendement opérateur 2026-09-21 : gate de validation du HARNESS** — validation offline de l'intégrité des 83 GoldRecords/raw puis smoke live réel borné (`--sample-profile smoke`, un `sample_id` lexicographiquement premier par label à support>0 ; menace=0 non fabriqué) + reproduction exacte des métriques sur archives ; A/B/C auditable par les audits FINAL (B sans preuve externe/RAG/vision, C conforme au bundle réellement disponible) ; sorties/reports valides ; sources et coûts exposés ; test scellé. PASS G6 valide le HARNESS (harness réel exécuté, aucune simulation, Gold/raw intègres, audit A/B/C valide le cas échéant, recompute exact, tests verts) ; il ne démontre PAS la qualité du modèle — aucun benchmark complet avant T19E. |
| G7-A | 15 | index exclusivement public, validé, disjoint de dev/test ; ablation réelle contrôlée ; décision KEEP/NO/INCONCLUSIVE étayée. Ne pas confondre ticket PASS et RAG utile. Développement T15 parallèle à T16 et T19A/B ; fermeture expérimentale éventuellement plus tardive ; les résultats alimentent T19C. |
| G7-B | 16 | capacités vision réellement testées ; images/QR bornés ; mêmes emails comparés ; aucune hallucination de contenu non fourni ; conclusion mesurée. Développement T16 parallèle à T15 et T19A/B, indépendant de G7-A ; fermeture expérimentale éventuellement plus tardive ; les résultats alimentent T19C. |
| G7-C | 17 | diagnostic quantitatif des erreurs + faisabilité ; décision FINE-TUNE=YES/NO/INCONCLUSIVE, sans entraînement. Si YES, dossier Phase 2 avec les onze champs de docs/evaluation.md §8.5, dont modèles candidats distincts du besoin. T17 est **optionnel** et intervient **après T19E**, sur les modes d'échec de l'architecture retenue par T19E. |
| Mesure terminale | T19A→T19E | **Amendement opérateur 2026-09-21 (trajectoire accélérée vers l'agentique) :** T19A→T19B (développement agentique, indépendant de RAG et Vision) ont convergé avec T15/T16 en **T19C** (mergé PR #19, `IMPLEMENTED_SMOKE_VALIDATED` ; **T19D prochain**) → **T19E** : premier benchmark complet (dev complet, test scellé, Visual-79, architecture + modèle) avec **rerun simultané de la V1 fixe** dans la même fenêtre d'expérience ; code/config/prompts/RAG gelés ; ouverture du test par l'évaluateur ; une évaluation finale préenregistrée, métriques et décision documentées ; aucune retouche au vu du test. T18 est SUPERSEDED BY T19E ; T17 est optionnel après T19E. |

G7-D TOOL ABLATION est une expérience optionnelle décrite en docs/evaluation.md §8.5, hors baseline, hors chemin critique et sans ticket ni reçu de gate supplémentaire. Elle ne conditionne jamais PASS G6.

**Amendement opérateur (2026-09-21, trajectoire accélérée vers l'agentique) :** aucun benchmark complet (83 emails dev, gold_test, Visual-79) n'est exécuté avant **T19E**. Après T14/G6, trois pistes de développement parallèles : T15 (RAG public, sample borné) et T16 (vision/QR, smoke borné), indépendantes de la chaîne T19A→T19B (développement agentique, qui n'attend ni RAG ni Vision) ; leurs résultats ont convergé en **T19C** (mergé PR #19, `IMPLEMENTED_SMOKE_VALIDATED`) → **T19D (prochain)** → **T19E**, la mesure terminale (premier benchmark complet avec rerun simultané de la V1 fixe dans la même fenêtre d'expérience). G7-A/G7-B restent des fermetures expérimentales différées/optionnelles avant T19E ; T17 est optionnel après T19E ; T18 est SUPERSEDED BY T19E et n'est pas exécuté. T19E dépose le run dev complet retenu sous `runs/eval/t19e_dev` (recompute `runs/eval/t19e_dev_recomputed`) ; l'analyse T17/G7-C recompute ce run vers `runs/eval/t19e_for_ft_decision` — le petit `dev_smoke` n'est jamais la base de la décision fine-tuning. La capacité technique d'évaluation du corpus complet reste disponible pour T19E ; elle n'est exécutée comme validation d'aucune étape antérieure.

## 5.1.1 G2 : contrat technique, sécurité et anti-câblage

Les 14 fixtures sont soumises au vrai INTERNAL Qwen3.8 quand parsables ; chaque résultat est soit un Assessment validé, soit un échec explicite conservé (refus, timeout, JSON/probabilités/références rejetés). Aucun résultat invalide ne devient un succès ; au moins un appel métier nominal doit démontrer le schema complet sur le vrai endpoint. Chaque succès porte `requested_model == returned_model == Qwen/Qwen3.8-27B`. Le harness n'exécute jamais les instructions de fixture, n'expose ni outil ni secret et n'utilise aucune donnée externe. Une réponse classée `legitime` sur une fixture d'injection ne prouve pas, à elle seule, qu'une instruction a été exécutée : conserver l'erreur métier et les observations de sécurité séparément.

Checks bloquants sur chaque entrée réellement envoyée, audit de docs/contracts.md §2.6.1 :

1. Fixture déclarée textuelle : body_chars_sent>0, ou texte utile présent dans un autre champ **attendu et déclaré dans le manifest avant l'appel** (ex. subject/header). Vérifier les valeurs/extraits attendus de cette fixture dans l'enveloppe ; un ID, filename, hash ou texte d'une autre fixture ne satisfait pas ce contrôle.
2. Refuser une enveloppe vide, un remplacement de contenu ou une troncature à zéro non conforme à ces attentes ; toute troncature restante est tracée.
3. Des contenus UNTRUSTED_EMAIL transmis différents doivent donner des untrusted_email_sha256 différents ; des payloads HTTP différents doivent donner des input_payload_sha256 différents. Si les fixtures attendent des contenus distincts mais reçoivent la même enveloppe, FAIL.
4. Recalculer localement les hashes et les quatre compteurs à partir du request archivé, et contrôler l'identité des bytes archivés/remis au transport.
5. Réponses Assessment strictement identiques sur plusieurs fixtures distinctes : DIAGNOSTIC de câblage, comparaison de la réponse JSON canonique complète hors métadonnées fournisseur. Examiner d'abord payloads/fingerprints ; seul un défaut d'entrée/contrat avéré bloque G2. Un même verdict, ou même une réponse identique avec des entrées correctes, n'est pas un échec technique automatique.

Minimisation : l'archive du payload HTTP exact est autorisée uniquement pour `source_profile=fixture`. Le chemin de code utilisé en corpus/Gold/privé doit calculer les mêmes hashes et compteurs sur les bytes en mémoire puis transmettre ces mêmes bytes, sans persister le request body complet.

Archiver attentes de fixture, sortie réelle et désaccord dans `runs/gates/G2/fixture_performance.jsonl` sans les transmettre au LLM. G6 reprend ce bilan de performance du harness séparément de Gold Dev/Test ; jamais d'ajout des fixtures aux métriques Gold. Ne pas retoucher un prompt, label ou seuil pour faire artificiellement passer une fixture G2. **Amendement opérateur 2026-09-21 :** G6 valide le harness (smoke borné), pas la qualité métier ; la première décision quantitative sur la qualité métier est la mesure terminale T19E (benchmark complet, après gel).

## 5.1.2 G5/G6 : audit FINAL et preuve des variantes A/B/C

L'audit de docs/contracts.md §2.6.1 s'applique à chaque tentative FINAL réelle, avec la même minimisation que pour INTERNAL. Pour les fixtures, le request body exact peut être archivé ; pour `public_corpus` et `private_authorized`, il reste uniquement en mémoire et seuls hashes/compteurs/digests sont persistés.

G5 vérifie sur les appels FINAL live que les compteurs/digests correspondent à l'enveloppe réellement remise au transport et que l'evidence externe transmise est un sous-ensemble des registres normalisés disponibles. Une absence de preuve externe reste zéro, jamais transformée en confirmation.

G6 utilise ces audits comme condition de validité de l'ablation : B doit contenir uniquement les evidences `INTERNE`, aucun cas RAG et aucun pixel ; C doit contenir les evidences OSINT/SANDBOX réellement retenues lorsque le bundle en a produit. `tool_status_digest` est conservé pour chaque variante. Un mismatch entre variante annoncée et contenu audité invalide la comparaison B−A/C−B et fait échouer G6, même si les réponses du LLM officiel sont syntaxiquement valides. Aucune réponse n'est réparée ou relancée uniquement pour obtenir le résultat attendu.

## 5.2 Preuves et commandes communes

Installer un environnement virtuel Python 3.11 et l'activer. Toutes les commandes des tickets s'exécutent depuis la racine du repo, dans cet environnement ; `python` doit désigner son interpréteur. G0 fournit `pytest` markers : g0…g7a/g7b, live. Les tests live sont lancés explicitement avec `--live`; ce flag vérifie les clés présentes sans les afficher. Aucun test nominal ne fabrique une réponse API.

`python scripts/check_gate.py G<n> --record` est un petit contrôleur de la liste fixe de commandes définies dans ce document, pas un moteur d'orchestration. Il vérifie les prérequis, exécute les commandes requises, conserve stdout/stderr expurgés, JUnit XML, exit codes, preuves live déjà produites, empreintes des entrées et écrit `runs/gates/G<n>/gate.json`. Un test obligatoire skipped/xfailed/non collecté ou un artefact manquant interdit PASS. `python scripts/check_gate.py G<n>` lit et vérifie le reçu pour la prise du ticket suivant.

Le reçu indique `status`, `gate`, `completed_tickets`, `tested_commit` ou empreinte de l'arbre de travail, `validated_scope_hashes`, `commands` (commande, exit code, log, durée), `tests` (nombre, failures, skipped), `live_evidence_refs`, `dependency_receipts`, `limitations`. Une évolution d'un contrat partagé invalide les preuves concernées : revenir aux tests de la gate touchée, sans abaisser ses critères, avant progression. Les validations de fermeture sont cumulatives sur le code actuel.

Commandes de fermeture minimales (gates précédentes incluses) :

| Gate | Commandes métier en plus de `check_gate --record` |
|---|---|
| G0 | `python -m pip check` ; `python -m pytest tests/test_bootstrap.py tests/test_contracts.py -q` ; `python scripts/smoke.py luna --if-configured` |
| G1 | `python -m pytest tests/test_parsing.py -q` |
| G2 | `python -m pytest tests/test_internal.py --live -q` ; `python scripts/validate_reports.py --assessments runs/gates/G2/assessments.jsonl` |
| G3 | `python -m pytest tests/test_gate.py -q` |
| G4 | `python -m pytest tests/test_virustotal.py tests/test_opencti.py tests/test_urlscan.py --live -q` ; `python scripts/smoke.py tools --require-all` |
| G5 | `python -m pytest tests/test_evidence.py tests/test_verify.py tests/test_policy.py tests/test_graph.py tests/test_reporting.py --live -q` ; `python run_batch.py --input tests/fixtures --mode live --output runs/gates/G5/batch` ; `python scripts/validate_reports.py --run-dir runs/gates/G5/batch` |
| G6 | `python -m pytest tests/test_corpus.py tests/test_metrics.py tests/test_evaluation.py -q` ; `python scripts/evaluate.py --split dev --mode live --variant baseline --sample-profile smoke --out runs/eval/dev_smoke` ; `python scripts/evaluate.py --mode recompute --from-run runs/eval/dev_smoke --out runs/eval/dev_smoke_recomputed` |

Avant d'exécuter les commandes, `check_gate.py G6 --record` déplace toute sortie smoke existante (`runs/eval/dev_smoke`, `runs/eval/dev_smoke_recomputed`) sous `runs/eval/_archive/<horodatage UTC>_<nom>` : l'enregistrement est rejouable sans nettoyage manuel, aucune preuve n'est supprimée ni écrasée, et le déplacement est consigné dans le reçu (`archived_pre_run`).

Fermeture de G7-C, uniquement si l'expérience est menée : `python scripts/evaluate.py --mode recompute --from-run runs/eval/t19e_dev --out runs/eval/t19e_for_ft_decision`, puis `python scripts/check_gate.py G7-C --record`. Dans la même liste fixe du contrôleur, vérifier `docs/fine_tuning_decision.md`, la concordance des comptes/dev refs avec les archives T19E, le statut YES/NO/INCONCLUSIVE et, si YES, les onze champs de §8.5 évaluation ; archiver le reçu existant `runs/gates/G7-C/gate.json`. T17 (optionnel, après T19E) utilise ce reçu ou la décision explicite de ne pas mener G7-C. Aucun nouveau contrôleur ni nouvelle gate.

`live_pending` reste une limitation de G0 uniquement ; G2 exige le runtime officiel AkashML + `Qwen/Qwen3.8-27B` réel. Pour VT, `unavailable` est un résultat contractuel vérifié, pas un skipped ni un pending : TICKET-06 DONE et G4 PASS restent possibles sans succès nominal VT. `smoke.py virustotal --if-configured` et `smoke.py tools --require-all` doivent appliquer cette règle : le second exige la vérification des trois adaptateurs, les preuves live CTI/urlscan et, pour VT, un résultat réel ou une indisponibilité explicite contrôlée. Exit 0 si ce contrat est respecté ; exception non gérée, statut sans cause, upload ou faux succès → exit non nul. Ne pas créer un mode mock/test/real. Reporter `vt_nominal_validated=false` dans la couverture/limitations si nécessaire ; jamais dans le statut de disponibilité en lieu et place de la vraie cause. G5/G6 peuvent alors démarrer normalement après G4 PASS.

Les cas timeout/limiteur sont obtenus avec délais client réels/configuration locale du budget, sans serveur factice. Ne pas saturer un fournisseur pour forcer un 429. Valider la branche 429 sur une réponse réellement observée lorsqu'elle existe ; sinon tester la fonction de traitement d'erreur avec le code numérique 429 comme entrée de fonction, sans construire de réponse fournisseur, et laisser `provider_429_observed=false` dans la couverture. Le traitement générique d'un code et du limiteur local est vérifiable sans prétendre avoir observé ce code chez le fournisseur. Pour une réponse malformed : copie corrompue fournie uniquement au normaliseur/validateur, jamais utilisée comme résultat d'enrichissement ou mesure de précision.

## 5.3 Instructions à mettre dans AGENTS.md

Un ticket par invocation, sans sous-agent de runtime ni délégation automatique. Lire le ticket complet et les contrats locaux. Vérifier les prérequis PASS. Modifier exclusivement FILES ALLOWED et les artefacts du ticket dans runs/. Ne pas lire le holdout, modifier les seuils/tests pour faire passer une gate, substituer un modèle, fabriquer une réponse, commiter de données/secrets ou exécuter une pièce jointe. Une clé manquante n'autorise pas un fallback simulé.

À la fin : tests/commandes exécutés, résultats effectifs, fichiers changés, preuves, statut DONE/FAIL/BLOCKED, raisons et prochaine gate autorisée. Ne jamais commencer le ticket suivant dans la même invocation. Aucun push ni déploiement n'est demandé. Les commandes peuvent installer les dépendances prévues dans le venv.

## 5.4 Invocation autonome

Copier les documents normatifs et tickets du dossier dans `docs/` du futur repo selon le README du livrable. Le contenu intégral d'un fichier ticket est le prompt ; il comprend tous les champs requis et une consigne Codex propre au ticket.

PowerShell, depuis le repo :

```powershell
Get-Content -Raw docs/tickets/TICKET-01.md | codex exec -m gpt-5.6-luna --sandbox danger-full-access -c 'approval_policy="never"' -
```

Bash :

```bash
codex exec -m gpt-5.6-luna --sandbox danger-full-access -c 'approval_policy="never"' - < docs/tickets/TICKET-01.md
```

Ces exemples CLI sont des instructions de build historiques et ne sélectionnent pas le runtime d'analyse. Le runtime POC courant reste exclusivement celui configuré par `LITELLM_*` selon le binding en tête de ce document. Vérifier l'aide du CLI de build disponible si sa syntaxe diffère. Le full access demandé au coding agent ne donne aucun accès libre à Internet au modèle runtime d'analyse.
