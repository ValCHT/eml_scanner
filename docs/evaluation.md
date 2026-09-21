# 8. Évaluation, critères de succès et décision

## 8.1 Trois niveaux et un test final intact

**Binding runtime courant (19/09/2026) :** toute mesure quantitative officielle décrite dans ce document utilise AkashML + `Qwen/Qwen3.8-27B`. `openai/gpt-oss-20b` est limité aux tests techniques et ne rejoint aucune métrique. Ce changement d'exécuteur ne modifie ni prompts, taxonomie, fixtures, seuils, ni design A/B/C. Les coûts utilisent les tarifs/valeurs facturées réellement observés pour AkashML.

**Harness :** fixtures contrôlées, appels LLM et outils réels lorsque éligibles ; tests déterministes de parsing/gate/validation/policy. Aucun résultat fournisseur fabriqué. Les fixtures à `.test` exercent la politique de non-soumission ; les scans live utilisent les deux URL bénignes dédiées. Les sorties authentiques et payloads effectivement envoyés sont archivés pour régression, séparés des données de corpus. G2 valide l'implémentation, le câblage et la sécurité ; un désaccord de classe ne bloque pas G2. G6 comptabilise les désaccords de `fixture_performance.jsonl` dans un bilan harness distinct, sans les mélanger aux métriques Gold.

**Gold dev :** environ 100 exemples validés, groupes séparés. Première baseline avec les prompts V1 et le gate BASELINE V0 (0,90/0,20, R1–R3) inchangés ; ajustements éventuels ensuite seulement sur gold_dev, puis RAG/vision optionnels. Le manifest garde les variantes, nombre d'essais et sélection. Aucun critère statistique ne transforme une exploration répétée sur dev en preuve indépendante.

**Labels de référence du POC exploratoire (amendement opérateur Gold-AI, 2026-09-20).** Les labels de référence de ce POC exploratoire sont produits par ChatGPT (Silver) puis GPT-6 Astra (annotation/adjuration indépendante) : **AI-adjudicated reference labels**, pas un ground truth analyste humain ; `human_validated=false`, `reviewer_ref=astra_gold_ai_v1`. La revue IA indépendante n'était pas parfaitement source-blind (métadonnées résiduelles identifiant le corpus observables dans certains raw), accepté pour ce POC. `menace` a zéro support de référence (aucune fabrication), `spear_phishing` seulement 16 candidats Gold-AI : la Macro-F1 six classes est non concluante quand une classe manque ; des affirmations de production SOC exigeraient une validation humaine ultérieure.

**Gold test :** partition de validation interne du POC exploratoire (amendement opérateur 2026-09-20) — environ 83 emails en métadonnées/labels seulement, scellés par `corpus/gold/test_seal.json` (reçu agrégé reproductible). Ce n'est PAS un holdout indépendant, isolé ou aveuglé. Une seule exécution terminale après gel des variantes ; toute modification de prompt, seuil, variante ou sélection de modèle fondée sur `gold_test` reste interdite, les décisions de développement utilisent `gold_dev` uniquement. Commande exécutée après matérialisation de la partition interne dans l'environnement de mesure :

```bash
python scripts/evaluate.py --split test --mode live --experiment-lock configs/experiment_lock.json --out runs/eval/gold_test_final
```

Avant tout appel, le script valide le GoldRecord fermé de docs/contracts.md §2.8, refuse les champs de contenu (y compris body/html/headers/raw/raw_email/mime_content même vides), résout raw_path et contrôle raw_sha256 sur le message local. Ce contrôle vaut aussi pour dev et emails privés ; les mêmes contrôles s'appliquent à la partition de validation interne (métadonnées seulement). Le script refuse un test non gelé, une empreinte divergente, un index RAG intersectant les groupes, un label ambigu ou un changement de variante non préenregistré. La sortie contient predictions JSONL, matrice CSV, metrics JSON, liste des cas/erreurs, usage/coût et manifest. Une seconde lecture offline recalcule les métriques à partir de ces mêmes réponses sans nouvel appel :

```bash
python scripts/evaluate.py --mode recompute --from-run runs/eval/gold_test_final --out runs/eval/gold_test_recomputed
```

Ce recalcul est reproductible exactement ; il ne mesure pas la disponibilité ni la latence live du jour du recalcul. Il conserve la date des observations initiales. Un nouveau run live est une nouvelle mesure, pas la reproduction exacte d'un modèle stochastique.

## 8.2 Calculs obligatoires

Ordre de labels fixe dans toutes les métriques : spear_phishing, phishing, fraude, menace, spam, legitime. `pred=null` compte comme échec/abstention et faux négatif pour la classe vraie, jamais comme email retiré. Conserver matrice 6×6 et un vecteur d'abstentions par vraie classe ; afficher aussi une colonne technique abstention pour permettre l'audit. Rapporter n total et n avec prédiction valide.

Precision/Recall/F1 par classe, support et Macro-F1 six classes. Calculer les scores sur l'ensemble convenu, y compris erreurs techniques. Une classe sans support n'est pas artificiellement parfaite : métrique non estimable ; Macro-F1-six-classes non concluante. Une absence de prédiction d'une classe avec support donne précision définie à 0 dans le calcul, explicitement documentée.

FP legitime : `(vrais legitime prédits non legitime, hors null)/n_legitime`. Ajouter séparément taux d'abstention sur legitime et taux de faux positifs malveillants `(vrais legitime prédits spear/phishing/fraude/menace)/n_legitime`. Ne pas mélanger spam et malveillance.

Validité schema première tentative par phase, validité après retry, nombre d'échecs définitifs, retries et refus. IOC inventés : nombre de propositions hors registre / nombre total de propositions, et emails ayant ≥1 violation / n ; dénominateur nul=null. Mesurer avant filtrage du verifier et après : « zéro IOC livré » ne signifie pas que le modèle n'en a jamais inventé.

Coûts : somme de l'usage facturable de **toutes** tentatives divisée par n emails ; frais externes réels s'ils existent. Pour le runtime officiel Qwen3.8, la métadonnée AkashML observée le 19/09/2026 indique 0,25 USD/M tokens input, 0,05 USD/M tokens cache-read et 2,20 USD/M tokens output. Archiver le snapshot tarifaire de chaque mesure et appliquer ses unités réelles, sans double comptage du reasoning. Si le fournisseur expose un coût facturé, le conserver et distinguer cette valeur de l'estimation. Coût d'accès/licence VT séparé des coûts variables. Valeurs inconnues/partielles signalées ; pas de 0 fictif.

Durées : moyenne, médiane, p95, maximum, total par email et par phase ; simple/complex séparés. Publier systématiquement % SIMPLE, % COMPLEX, qualité de chaque chemin (métriques ci-dessus et supports, non estimable si support absent), coût moyen/total de chaque chemin et valeurs inconnues. Les chemins sont ceux du gate BASELINE V0 avant tout réglage. Couverture de chaque outil : candidats, soumis, ok, not_found, unavailable, skipped, raisons ; taux complex et nombre de preuves nouvelles. Ne pas conclure « VT inutile » si VT n'a pas été disponible.

Policy : couverture AUTO/REVIEW/ESCALATE, malveillants AUTO, legitime ESCALATE, taux REVIEW, précision des AUTO bénins et support. Présenter simultanément erreurs et couverture pour empêcher la solution triviale « tout REVIEW » d'être assimilée à une réussite d'automatisation.

## 8.3 Valeur internal → final

Comparer les deux verdicts du **même run** et les mêmes labels. n_changed/n_comparable ; wrong→right (amélioration), right→wrong (dégradation), wrong→wrong (changement sans correction), right→right (stable correct). Les probabilités changent séparément du verdict. Publier ΔMacro-F1 et ΔRecall par classe, ainsi que l'évolution des erreurs AUTO. Les fallback/null sont comptés à part et dans la performance globale.

Le delta global inclut les emails simples dont final=internal et les complexes enrichis. Publier les deux périmètres ; ne pas choisir après coup seulement les cas où l'enrichissement a réussi. Une attribution spécifique à VT/OpenCTI/urlscan n'est pas identifiable après un seul appel final contenant toutes les preuves.

Contrôle minimal sur dev, mêmes emails complexes : A=internal medium ; B=second appel xhigh avec contexte interne seulement, sans résultats externes ; C=second appel xhigh avec résultats réellement collectés. Le contexte outils absent dans B est une ablation, pas une réponse simulée. B−A estime l'effet du second raisonnement ; C−B l'apport du bundle externe, avec les limites de stochasticité. Garder les mêmes paramètres, ordre d'emails, snapshots externes et conditions de mesure. Comparer uniquement A et C ne permet jamais d'attribuer un gain au bundle externe. Une attribution individuelle à VT/OpenCTI/urlscan n'est pas requise pour conclure le POC ; elle exige une ablation spécifique optionnelle préenregistrée (G7-D). La variante `baseline` de TICKET-14 exécute et archive A/B/C sur les mêmes cas complexes dev ; A est l'INTERNAL du run partagé par B et C, B conserve le prompt FINAL xhigh avec seuls les registres internes, TOOL_STATUS indiquant l'ablation sans preuves externes, RAG vide et aucune image. Les données indisponibles dans C restent indisponibles et comptées ; l'absence de VT ne bloque pas cette comparaison et limite sa portée au bundle effectivement disponible.

La validité de B−A/C−B dépend aussi de l'audit FINAL de docs/contracts.md §2.6.1. Pour B, exiger `external_evidence_count_sent=0`, `evidence_count_sent=internal_evidence_count_sent`, `rag_case_count_sent=0` et `visual_count_sent=0`. Pour C, lorsque le bundle normalisé contient au moins une evidence OSINT/SANDBOX admissible, exiger `external_evidence_count_sent>0`; sinon conserver zéro avec la limite `no_new_external_evidence`. Archiver `tool_status_digest` pour B et C. Un simple `request_sha256` différent ne suffit pas à prouver l'ablation : si ces invariants ne sont pas vérifiables, marquer la comparaison invalide plutôt que publier C−B.

B est un contrôle expérimental hors run nominal, utilisant les mêmes fonctions ; il ne crée ni second graphe ni troisième appel nominal. Séparer son coût/temps supplémentaire du coût/temps opérationnel (A seul en SIMPLE, A + FINAL C + outils en COMPLEX), tout en comptant toutes les tentatives dans le budget total de l’expérience.

Les lookup actuels sur des emails anciens ne reconstituent pas l'état au moment de réception : analyser séparément historiques et récents et enregistrer email_date vs collected_at. Un ancien domaine désormais malveillant ou bénin peut inverser l'effet. Les pages mortes ne sont pas des preuves d'absence de phishing.

## 8.4 Cibles de succès préenregistrées

Ces seuils sont des objectifs de POC proposés, pas des garanties de performance ; les geler avant test.

| Dimension | Objectif initial / décision |
|---|---|
| Contrats et sécurité | 100 % des rapports émis valides ; 0 secret/divulgation non autorisée ; 0 upload PJ ; 0 IOC non sourcé livré ; 100 % de détection des violations structurées de la suite V01–V16 |
| Harness technique | entrées effectivement transmises et contrats G2 validés ; désaccords de classement archivés sans seuil de justesse bloquant ; images essentielles non vues orientées REVIEW ; aucune fausse preuve sandbox sur `.test` |
| Première sortie LLM officielle | ≥99 % valide schema ; après retry 100 % ou échec explicite REVIEW, sans réparation de chiffres |
| Qualité test | Macro-F1 six classes ≥0,85 ; recall phishing/spear_phishing/fraude ≥0,90 chacune ; FPR strict legitime≤0,05 ; support minimum exposé |
| Sécurité de la policy | 0 vrai malveillant proposé AUTO dans le lot testé ; toute incohérence matérielle/refus/manque essentiel→REVIEW/ESCALATE |
| Utilité opérationnelle | couverture AUTO≥20 % comme cible exploratoire si le lot inclut suffisamment de cas bénins ; sinon résultat d'aide au triage seulement |
| Temps simple | moyenne≤15 s, p95≤30 s, sur calls live sans cache, machine/réseau documentés |
| Temps complexe | moyenne≤90 s, p95≤180 s ; plafond logiciel 240 s avec fallback ; non atteignable sous tous quotas : exposer couverture et attentes de collecte |
| Coût variable LLM | moyenne≤0,02 USD/email, p95≤0,05 USD/email ; inclure reasoning/retries ; licence externe hors de cette cible |
| Enrichissement | gain mesuré sans nouvelle erreur AUTO ; un résultat neutre/négatif est acceptable comme conclusion du POC, pas comme validation de l'hypothèse |

Exemples budgétaires au tarif AkashML Qwen3.8 observé le 19/09/2026, hors cache et non mesures : 10 000 tokens input + 3 000 output = 0,0091 USD ; deux phases totalisant 25 000 input + 10 000 output = 0,02825 USD. La longueur de raisonnement et les retries comptent plus que le nombre d'appels Python. Conserver USD pour ne pas inventer un taux EUR et recalculer si le snapshot tarifaire change.

À 4 requêtes VT/email, 200 emails feraient 800 requêtes : plus de 500/jour. À une URL/email, 200 scans privés dépassent 50/jour et demandent au moins quatre jours de quota. Même 100 emails test avec une URL chacun demanderaient au moins deux jours. Réduire les cibles dédupliquées et planifier les collectes, sans supposer que l'analyse live de tout le corpus tiendra dans une séance. Ce sont maxima de dimensionnement, pas la couverture réelle attendue.

Avec environ 100 emails test et 10–25 exemples par classe, les intervalles sont larges. Rapporter des intervalles bootstrap par family_group (2 000 tirages, seed 42) pour scores/deltas, et Wilson pour proportions simples. Si tous les 20 legitime sont corrects, on n'a pas prouvé un FPR de production <1 % ; zéro erreur ne garantit pas un risque nul. Ne pas annoncer une aptitude à l'auto-clôture SOC à partir de ce seul lot.

## 8.5 Décisions G7

Toutes les expériences G7 sont optionnelles et postérieures à la baseline G6 ; ne pas les imposer pour déclarer PASS G6.

**RAG public :** comparer baseline et baseline+RAG, mêmes données et snapshots externes ; index public gelé avant mesure. Mesurer top-3 pertinence revu analyste sur 20 requêtes dev, gain de classification, wrong→right/right→wrong, erreurs AUTO, coût et latence. Seuil de rétention initial : ΔMacro-F1≥0,02 ou au moins 3 corrections nettes sur le subset pertinent, aucun nouveau malveillant AUTO, aucune fuite/IOC importé ; critère de rappel critique non dégradé de plus d'un cas. Une amélioration dans le bruit donne INCONCLUSIVE, pas KEEP démontré. Confirmer sur test la variante préchoisie ; ne pas choisir le meilleur index après lecture du test.

**Vision :** sur le subset visuel avec labels indépendants, comparer texte seul, texte+QR local, puis texte+QR+vision, pour ne pas attribuer au VLM le gain du seul décodage. Modèle/proxy doivent accepter réellement les pixels. Cible : au moins 3 corrections nettes ou +10 points de recall sur les cas visuels pertinents, aucun nouveau AUTO malveillant, guardrails inchangés. Moins de 20 cas pertinents ou intervalle trop large : INCONCLUSIVE. Les fixtures prouvent le mécanisme, pas la performance de terrain.

**Fine-tuning :** regrouper les erreurs dev en taxonomie/instruction, information absente, enrichissement, retrieval, gate/policy, parsing et annotation. YES uniquement comme recommandation d'expérimentation si ≥10 erreurs revues de la même famille stable, non expliquées par information manquante, persistant sur trois reruns et après une correction raisonnable prompt/schema, avec potentiel de correction d'au moins 20 % des erreurs résiduelles et données d'entraînement validées distinctes. NO si qualité suffisante ou causes ailleurs ; INCONCLUSIVE si échantillon/données insuffisants. Ces seuils sont des règles de décision proposées, pas une propriété des modèles. Même YES doit porter `implementation_feasible_on_current_runtime=false` tant que la combinaison modèle/proxy ne permet pas le fine-tuning. Aucun fine-tuning fondé sur les erreurs du test ; l'analyse du test peut motiver une future étude avec nouveau holdout, pas retuner cette mesure.

Si `FINE-TUNE = YES`, `docs/fine_tuning_decision.md` doit contenir les champs suivants, renseignés à partir des erreurs dev et avec hypothèses/fourchettes explicites (UNKNOWN si non vérifié, sans faux coût ni faux support) :

| Champ | Contenu attendu |
|---|---|
| `target_failure_modes` | familles stables, sample_id dev et fréquence |
| `why_prompting_is_insufficient` | modifications raisonnables réellement testées après baseline et erreurs persistantes ; aucun réglage pour PASS G2 |
| `why_retrieval_is_insufficient` | preuves mesurées ou limite démontrée ; si G7-A non menée, le dire sans prétendre une inefficacité observée |
| `why_enrichment_is_insufficient` | comparaison C−B et couverture réelle ; panne ≠ inefficacité |
| `training_data_needed` | données autorisées, annotations et couverture texte/image, distinctes des gold d'évaluation |
| `estimated_number_of_examples` | fourchette motivée par classes/failure modes, ou UNKNOWN avec méthode d'estimation |
| `candidate_models` | candidats/variantes Phase 2 à benchmarker ; distinguer le runtime Qwen3.8 hébergé officiel du checkpoint ou modèle effectivement adaptable |
| `evaluation_protocol` | comparer la baseline Qwen3.8 officielle, le candidat de base et le candidat adapté ; nouveau holdout indépendant, ablations texte/QR/vision si concerné |
| `non_regression_requirements` | contrats, V01–V16, confidentialité, injection texte/visuelle, faux AUTO, rappels critiques, coût/latence |
| `estimated_training_cost` | matériel, heures, prix unitaires datés, nombre d'essais, intervalle et coût d'annotation séparé ; UNKNOWN si non établi |
| `phase_2_go_no_go_conditions` | données suffisantes, faisabilité technique vérifiée, budget et gain minimum préenregistré ; STOP si absence de gain ou régression critique |

Inclure **Qwen3.8-27B — runtime POC hébergé et candidat de checkpoint Phase 2** dans `candidate_models` : poids ouverts disponibles, modèle dense, entrée texte + image selon sa [fiche officielle](https://huggingface.co/Qwen/Qwen3.8-27B). Le run AkashML ne démontre ni l'identité exacte d'un futur checkpoint d'entraînement ni une supériorité SOC. Un scénario PEFT/QLoRA est plausible au niveau architectural d'après les poids Transformers et les [mécanismes PEFT/QLoRA](https://huggingface.co/docs/peft/developer_guides/lora) ; versions, kernels, matériel et bénéfice restent à éprouver en Phase 2.

Un YES peut conclure : « Le POC Qwen3.8 hébergé révèle un besoin probable de spécialisation ; un checkpoint Qwen3.8 est un candidat Phase 2 à benchmarker/fine-tuner. » Il ne conclut pas qu'un entraînement est déjà faisable ou utile. Distinguer besoin, runtime hébergé, checkpoint candidat, faisabilité et bénéfice attendu ; aucun meilleur modèle sans benchmark. Ne télécharger aucun poids, ne lancer aucun runtime Qwen local ni QLoRA et n'ajouter aucune dépendance d'entraînement dans ce POC.

**G7-D — TOOL ABLATION, optionnelle uniquement :** proposer seulement si C−B suggère un gain intéressant ou laisse un effet ambigu à clarifier ; ne pas exécuter si le bundle ne montre déjà aucune valeur mesurable. Exemples : C_full, C_without_VT, C_without_OpenCTI, C_without_urlscan, mêmes emails et snapshots réels. Objectif : contribution individuelle éventuelle. Hors baseline, hors chemin critique, hors PASS G6, sans nouveau ticket ni nouvelle gate obligatoire. Une indisponibilité réelle reste enregistrée ; ne pas l'interpréter comme une ablation nominale d'un outil disponible.

Livrable final POC : résultats réels, coverage matrix, erreur par cause, décision sur chaque composant, FINE-TUNE=YES/NO/INCONCLUSIVE et limites. Une conclusion « baseline utile, enrichissement indisponible/non concluant, RAG sans gain » est plus informative qu'un succès fabriqué.

## 8.6 TICKET-14 — exécution baseline dev (implémentée)

La variante `baseline` exécute la baseline réelle sur `gold_dev` et archive une mesure auditable. CLI exacte :

```bash
python scripts/evaluate.py \
  --split dev --mode live --variant baseline \
  --out runs/eval/dev_baseline
```

Options : `--split {dev,test}` (test refusé en TICKET-14, voir §8.1/§8.6.3), `--mode {live,recompute}`, `--variant baseline`, `--out` (répertoire vide exigé, jamais écrasé), `--from-run` (recompute), `--evaluation-config` (défaut `configs/evaluation.yaml`), `--experiment-lock` (défaut `configs/experiment_lock.json`). Codes de sortie : `0` OK, `1` FAIL (drift du lock, échec de validation gold, audit A/B/C invalide, métriques recompute différentes), `2` BLOCKED (clé LLM absente, split test).

### 8.6.1 Déroulé live

1. **Lock** : `configs/experiment_lock.json` gèle l'empreinte SHA-256 des prompts, schémas, `gate.yaml`/`policy.yaml`/`tools.yaml`, `requirements.lock`, `evaluation.yaml` et `gold_dev.jsonl`, plus le binding runtime (`Qwen/Qwen3.8-27B`, endpoint AkashML, internal=medium/final=xhigh) et les seuils BASELINE V0 (0,90/0,20). Tout drift = FAIL avant tout appel.
2. **Validation gold préalable** : les 83 GoldRecords dev (schéma fermé, clés de contenu interdites refusées récursivement, `label_status=confirmed`, `email_sha256 == raw_sha256`) sont résolus et hachés depuis `corpus/raw/**` AVANT tout appel LLM/outil ; fichier absent, hash divergent ou chemin sortant de `corpus/raw/**` = échec fort, jamais un échantillon silencieusement retiré.
3. **Pipeline figé** : un graphe séquentiel par email (StateGraph, gate R1–R3, prompts V1, maximum deux appels nominaux, RAG/vision inactifs), rapport authentique archivé sous `<out>/<run_id>/report.json` (runs/ git-ignoré).
4. **Contrôle A/B/C sur les COMPLEX** : A = INTERNAL medium du run partagé (jamais de second appel internal) ; B = contrôle xhigh avec preuves internes seules (`merge_evidence(parsed, None)`), `TOOL_STATUS` marquant explicitement l'ablation (`skipped/ablation_control_b_no_external_evidence`, mode `none`, zéro requête), RAG vide, aucun pixel, audits §2.6.1 archivés dans `responses_control_b/` ; C = FINAL nominal xhigh avec le bundle externe réellement collecté. Les invariants d'audit sont validés avant tout delta : B sans preuve externe/RAG/visuel, C transmettant les evidences OSINT/SANDBOX admissibles lorsque le bundle en produit (sinon `no_new_external_evidence`). Un mismatch invalide la comparaison B−A/C−B et fait échouer le run.
5. **Sorties** : `predictions.jsonl` (exactement une ligne par `sample_id`, métadonnées/verdicts/usage/audits, aucun contenu d'email), `metrics.json` (§8.2 complet : confusion 6×6 + colonne abstention, Macro-F1 six classes non conclusive quand menace=0, FPR strict/malveillant/abstention, SIMPLE/COMPLEX qualité+coût+latence, validité schéma/retries/refus, IOC avant/après vérifier, couverture AUTO/REVIEW/ESCALATE, couverture outils par statut/cause), `matrix.csv`, `report.md`, `manifest.json` (identité, commit, modèle, reasoning, empreintes des entrées gelées, snapshot tarifaire, statuts d'outils, politique de retry — sans aucun secret, présence seulement).
6. **Coûts** : usage réel de chaque tentative ; tarif AkashML du snapshot (0,25 input / 0,05 cache-read / 2,20 output USD par 1M) appliqué seulement sans valeur facturée exposée ; valeurs provider-billed et estimées conservées séparément ; coût inconnu jamais remplacé par 0 ; les tokens de reasoning sont déjà dans `output_tokens` et ne sont jamais additionnés deux fois.
7. **Budget total de l'expérience** : coût/temps opérationnel (A en SIMPLE ; A+outils+C en COMPLEX) et coût/temps du contrôle B sont archivés et séparés, mais toutes les tentatives (y compris B et les retries) comptent dans le budget total.

### 8.6.2 Recompute exact

```bash
python scripts/evaluate.py \
  --mode recompute \
  --from-run runs/eval/dev_baseline \
  --out runs/eval/dev_recomputed
```

Aucun appel fournisseur ni réseau : la partition dev (métadonnées), les lignes archivées et les rapports authentiques (hash vérifié ligne par ligne) sont rechargés et les métriques recalculées de façon déterministe. Les métriques doivent être ÉGALES aux métriques live (aucune horloge n'entre dans une métrique) ; seule la différence autorisée est le manifest de recompute (métadonnées explicites : date du recalcul, run source, `provider_calls=0`, timestamps d'observation préservés). Un recalcul ne reproduit ni la latence ni la disponibilité live et ne remplace pas le run live ; un nouveau run live est une nouvelle mesure.

### 8.6.3 gold_test non lisible en TICKET-14

`--split test` est refusé par l'évaluateur (BLOCKED) tant que le workflow de développement TICKET-14 est actif : `gold_test.jsonl` est une partition de validation interne du POC, sa lecture terminale relève du ticket autorisé après gel des variantes (§8.1). Le chargement dev n'ouvre que `corpus/gold/gold_dev.jsonl`, vérifié par test.
