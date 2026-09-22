# 4. Complexity gate, vérificateur et policy

## 4.1 Trois règles, exactement

`decide_gate(parsed: ParsedEmail | None, internal: Assessment | None, config: GateConfig) -> GateResult` est pur, sans réseau ni LLM.

| Règle | Expression | Reasons émises |
|---|---|---|
| R1 — incertitude | internal absent/invalide OU max(p)<0,90 OU max(p)−deuxième(p)<0,20 | `internal_unavailable`, `low_confidence`, `low_margin` selon causes présentes |
| R2 — matériel investigable | au moins une URL HTTP(S) href/visible/form/QR, OU au moins une pièce jointe non inline | `urls_present`, `attachments_present` |
| R3 — contexte/couverture | parsed absent, limite de contenu atteinte, défaut empêchant de décoder une partie utile, visuel essentiel non lu, ou internal.needs_enrichment=true | `parse_incomplete`, `content_truncated`, `essential_visual_unread`, `model_requests_context` |

COMPLEX si R1 OU R2 OU R3 ; SIMPLE sinon. Reasons toutes conservées, ordre R1 puis R2 puis R3, ordre des causes du tableau, sans doublons. Les ressources distantes décoratives `<img src>` ne déclenchent pas seules R2 ; elles ne sont jamais chargées directement. Un email BEC sans lien peut être SIMPLE et être ESCALATE : simple ≠ bénin.

Configuration initiale `configs/gate.yaml` :

```yaml
version: 1
min_confidence: 0.90
min_margin: 0.20
enrich_http_urls: true
enrich_non_inline_attachments: true
enrich_on_material_coverage_gap: true
```

Ces seuils constituent la configuration **BASELINE V0** du gate. Ils ne représentent pas des seuils optimaux ou calibrés. Conserver min_confidence=0,90, min_margin=0,20 et R1/R2/R3 pour la première baseline ; ne rien optimiser avant sa mesure en G6. Un ajustement éventuel intervient ensuite uniquement sur gold_dev et reste une variante identifiée. Mesurer systématiquement % SIMPLE, % COMPLEX, qualité SIMPLE/COMPLEX et coût SIMPLE/COMPLEX, avec leurs supports. Une newsletter avec URL pertinente reste COMPLEX dans cette baseline : ce n'est pas un défaut d'architecture. Aucune allowlist ni nouvelle heuristique en V1.2.

En G3, démontrer les deux décisions SIMPLE et COMPLEX avec des entrées de fonction contrôlées et déterministes couvrant les frontières R1/R2/R3. Ces objets de test prouvent le branchement du code ; ils ne sont jamais comptés comme réponses LLM ni comme résultats métier. Passer ensuite toutes les réponses réelles archivées du runtime G2 officiel Qwen3.8 dans `decide_gate` et conserver leur distribution réelle sans modifier les scores ni les seuils. La présence d'un SIMPLE live est souhaitée mais **non bloquante** avant G6. Si aucun sample G2 réel ne satisfait BASELINE V0, enregistrer `simple_path_live_observed=false` et la limitation `No live G2 sample satisfied BASELINE V0 SIMPLE criteria` dans le reçu G3 ; réévaluer la couverture SIMPLE/COMPLEX sur gold_dev en G6. Aucun réglage 0,90/0,20 n'est autorisé pour obtenir artificiellement une branche.

## 4.2 Vérificateur déterministe

`verify_assessment(assessment, phase, registry, tool_results, parsed, rag_context) -> VerificationResult`. La validation de schema et de références intervient dès G2 pour protéger le gate ; les contrôles de preuves externes et de policy sont ajoutés en G5. Aucun deuxième LLM vérificateur.

| ID | Vérification exacte | Conséquence |
|---|---|---|
| V01 | Schema strict, six probabilités, nombres finis, somme/tolérance, tailles de listes, argmax/confiance dérivés | invalide : résultat rejeté ; pas de correction silencieuse |
| V02 | Chaque ID d'observable/preuve/rag existe dans l'entrée réellement fournie à cette phase | référence inconnue : unsupported claim, critical |
| V03 | Un Observable final garde type, valeur normalisée et origine du registre ; aucun ajout LLM | ajout/modification : `fabricated_ioc`, critical ; exclusion de la liste acceptée |
| V04 | Provenance cohérente avec producteur : parser→INTERNE, VT/CTI→OSINT, urlscan→SANDBOX ; les interprétations ne deviennent pas faits | provenance impossible : critical |
| V05 | Tout fait externe cité correspond à une réponse réelle ok, archivée et au JSON Pointer/valeur normalisée attendus | absence, faux compteur, mauvaise URL/UUID : critical |
| V06 | La preuve exacte appartient au même observable ; domaine parent/IP partagée ≠ URL exacte | faux exact match : error, bloque AUTO et M |
| V07 | Aucun destinataire To/Cc/Bcc connu n'entre dans la liste d'IOC ou le plan de requêtes ; matching de l'adresse entière | recipient_as_ioc : critical ; suppression de la proposition |
| V08 | Un rôle displayed_brand/spoofed_identity/shared_host ne peut être M/S sans preuve précise sur cet objet ; un URL précis ne propage pas sa catégorie au host parent | attribution globale injustifiée : error ; B/null seulement sur le host |
| V09 | M nécessite confirmation exacte admissible : assertion malveillante explicite dans source configurée fiable, non révoquée, sur même artefact ; jamais présence CTI/0 VT/RAG seuls | preuve insuffisante : proposition M rejetée, error ; pas de conversion cachée en confirmation |
| V10 | Assertions sandbox : final URL/redirections/form fields réellement présentes ; screenshot effectivement fourni avant interprétation | preuve inventée ou image non vue : critical/error |
| V11 | Les motifs de type external_support/conflict citent au moins une preuve OSINT/SANDBOX ; ciblage cite des extraits contextuels et pas seulement To/nom | support formel manquant : error ; qualification sémantique humaine en évaluation |
| V12 | Bénignité ne repose pas exclusivement sur PASS auth, zéro détection, not_found, panne, page morte ou voisin RAG | contradiction codée : error, REVIEW |
| V13 | Si un artefact exact a confirmation malveillante admissible et final=legitime/spam, ou raisons payment_diversion/extortion/credential_collection et verdict bénin sans external_conflict étayé | `verdict_evidence_conflict`, error, REVIEW/ESCALATE selon preuve |
| V14 | Si le verdict change, comparer les vecteurs/IDs ; si aucune nouvelle preuve et hausse de confiance >0,05, flag explicite | `confidence_rise_without_new_evidence`, warning bloquant AUTO ; pas de faux gain attribué aux outils |
| V15 | RAG : chaque case public, validé, hors gold et hors groupes apparentés ; aucun IOC du voisin propagé | contamination/leak : critical, expérience invalide |
| V16 | Cohérence du run : tool status/mode/date, final_source, fallback, non-négativité des durées, usage, comparaison nullable | erreur technique : REVIEW, métriques signalées |

La configuration des sources fiables et des rôles protégés vient du harness, jamais du texte de l'email. Au démarrage, conserver les hôtes d'infrastructure partagée courants dans une petite liste explicite et versionnée, mais ne pas prétendre qu'elle est exhaustive. Une URI exacte sur un service partagé peut être S/M quand étayée ; le service entier reste protégé contre la généralisation. Un domaine inconnu sans preuve d'abus reste null/S selon rôle et preuves ; il n'est pas « confirmé attaquant » par défaut.

Une confirmation admissible en V09 est une règle de provenance : par exemple verdict urlscan explicitement malveillant sur le scan exact, ou assertion de malveillance d'une source CTI approuvée avec référence et statut non révoqué. Les comptages VT seuls restent un signal de suspicion dans la configuration initiale. **Le code peut vérifier la présence et la portée d'une assertion ; il ne peut pas prouver que son auteur a raison.** Pas de blocage réseau automatisé dans ce POC, même pour M.

Une contradiction entièrement sémantique non encodée ne peut pas être garantie détectable par des règles. Le contrat évite les faits externes libres et couvre les contradictions structurées ci-dessus ; l'évaluation humaine mesure le reste. « Toutes les violations artificielles détectées » signifie la suite finie V01–V16, pas tous les raisonnements faux possibles.

## 4.3 Policy et priorités

`decide_policy(report_inputs, PolicyConfig) -> PolicyDecision(action, reasons)` ; aucun appel réseau. L'action est une recommandation SOC, sans effet sur la messagerie.

Appliquer dans cet ordre, s'arrêter à la première règle applicable :

1. Violation critical d'intégrité de preuve/IOC/provenance/RAG → **ESCALATE**, motif technique explicite, sans transformer cela en verdict phishing.
2. Confirmation malveillante exacte admissible non contredite par une preuve de même portée → **ESCALATE**, même si le modèle propose bénin ; conserver la contradiction.
3. Pas d'Assessment valide, erreur parser/LLM, contenu essentiel manquant, fallback, validation error, ou limite matérielle non résolue → **REVIEW**.
4. Verdict dans {spear_phishing, phishing, fraude, menace} avec p≥0,85 → **ESCALATE**. Sous ce seuil → **REVIEW**.
5. Verdict legitime/spam avec p≥0,97, marge≥0,50, aucun avertissement bloquant, aucune information matérielle manquante et aucun enrichissement nécessaire non exploitable → **AUTO**.
6. Tous les autres cas → **REVIEW**.

Les lacunes matérielles sont destination à vérifier pour un lien ayant porté le raisonnement, pièce suspecte non inspectée, contenu visuel essentiel non lu, texte tronqué/inexploitable ou contexte requis. `authentication_untrusted` seul n'est pas une preuve d'attaque ; c'est une limite dont le caractère matériel dépend du scénario. Une panne d'outil sans cible pertinente n'est pas un motif artificiel de REVIEW ; une panne sur une preuve nécessaire interdit AUTO.

`configs/policy.yaml` fixe `auto_min_confidence: 0.97`, `auto_min_margin: 0.50`, `escalate_malicious_min_confidence: 0.85`, `auto_labels: [legitime, spam]`, et la table des codes bloquants. Les seuils ne sont modifiés que sur dev, avec un diff de config et une réévaluation enregistrée. Aucun AUTO sur la seule absence de détection.

Les scores ne sont pas calibrés. En G6, mesurer aussi la couverture AUTO et le nombre d'emails réellement malveillants classés AUTO, afin qu'une policy « tout REVIEW » ne paraisse artificiellement excellente.

**Remarque TICKET-10 — codes et lectures d'implémentation (non normatif).** Le vérificateur déterministe (`src/verify.py`) émet un code stable par règle : V01 `invalid_assessment`/`missing_assessment`, V02 `unsupported_claim`, V03 `fabricated_ioc`, V04 `impossible_provenance`, V05 `unsupported_external_fact`, V06 `false_exact_match`, V07 `recipient_as_ioc`, V08 `unjustified_global_attribution`, V09 `insufficient_malicious_confirmation`, V10 `invented_sandbox_assertion`/`screenshot_not_provided`, V11 `unsupported_external_claim`/`targeting_without_context`, V12 `benign_insufficient_basis`, V13 `verdict_evidence_conflict`, V14 `confidence_rise_without_new_evidence` (warning), V15 `rag_contamination`, V16 `run_inconsistency` (+ l'avertissement de fallback `final_fallback_internal_copy`). Une confirmation M admissible est aujourd'hui l'assertion fournisseur explicite `sandbox_provider_malicious == true`, EXACT, sur le même observable : les compteurs VT, la présence/les labels CTI et un voisin RAG ne confirment jamais M. V14 réutilise exactement le compteur FINAL `external_evidence_count_sent` et le seuil 0,05 de `signals_gain_without_external_evidence`. La liste acceptée d'observables exclut les propositions fabriquées/altérées et les destinataires, sans jamais réécrire l'Assessment conservé pour audit. La policy (`src/policy.py`) lit les lacunes matérielles dans la liste typée de V12/§4.3 (`destination_unverified` inclus, `authentication_untrusted` seul exclu) ; `tool_unavailable` n'est matériel que si un résultat indisponible portait une cible pertinente. Le fallback interne reste REVIEW avant la règle 4, conformément à l'ordre gelé. Toute confirmation librement sémantique reste hors du code déterministe et relève de l'évaluation humaine.

## 4.4 DNS egress actif (TICKET-19D-OSINT §17.1)

Le backend OSINT (`lookup_osint`, source `dns`) émet de vraies requêtes DNS
via le resolver configuré (`dns.resolver.Resolver(configure=True)`,
types A/AAAA/MX/NS/TXT, budget total 5 s). C'est un EGRESS ACTIF :

- la requête peut atteindre l'infrastructure autoritative du domaine ;
- elle peut révéler l'analyse d'un sous-domaine unique ;
- elle est visible par le resolver configuré ;
- elle peut déclencher des contrôles DNS de l'organisation.

Décision POC : **autorisé sur corpus public**. Cette décision n'implique
PAS automatiquement une autorisation en production.
