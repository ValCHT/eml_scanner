# 2. Contrats de données

## 2.1 Règles communes

Pydantic v2, `extra='forbid'`, validation des nombres finis. Toutes les valeurs temporelles ISO 8601 UTC ; durées monotones en millisecondes. Une liste/dict par défaut utilise `default_factory`, jamais un objet mutable partagé. Les TypedDict n'appliquent pas de défauts : `new_state()` doit construire exactement l'état ci-dessous. Aucun secret n'y entre.

Taxonomie fixe : `spear_phishing`, `phishing`, `fraude`, `menace`, `spam`, `legitime`. Provenance fixe : `INTERNE`, `OSINT`, `SANDBOX`, `INFERENCE`. Catégories d'observable : `M`, `S`, `C`, `B`, null. Le statut technique d'échec est distinct de la taxonomie ; il n'existe pas de septième classe « inconnu ». Si aucune évaluation valide n'existe : verdict, confiance et probabilités=null, action REVIEW.

Les schemas livrés `schemas/assessment.schema.json` et `schemas/triage_report.schema.json` sont complets, sans références externes. Ils doivent être reproduits par les modèles de G0. Les invariants entre champs, non exprimables dans ce sous-ensemble JSON Schema, sont obligatoires en Python et détaillés ici.

## 2.2 EmailTriageState : tous les champs et défauts

Notation `T?` = `T | None`. Tous ces champs existent dès new_state.

| Champ | Type | Défaut / initialisation |
|---|---|---|
| schema_version | Literal['1.0'] | '1.0' |
| run_id | str UUID4 | nouvel UUID, unique par invocation |
| input_path | str | argument obligatoire, chemin absolu validé |
| source_profile | Literal['fixture','public_corpus','private_authorized'] | argument, jamais deviné du contenu |
| started_at | str UTC | horloge au lancement |
| config_sha256 | str | empreinte de la configuration sans secrets |
| parsed | ParsedEmail? | null |
| observable_registry | dict[str, Observable] | {} |
| evidence | dict[str, Evidence] | {} |
| visual_evidence | list[VisualEvidence] | [] |
| internal | Assessment? | null |
| internal_call | CallRecord? | null |
| gate | GateResult? | null |
| enrichment | Enrichment | quatre listes vides |
| final_candidate | Assessment? | null |
| final_call | CallRecord? | null |
| final_source | Literal['internal_copy','final_llm','internal_fallback','none'] | 'none' |
| final_validated | Assessment? | null |
| verification | list[VerificationIssue] | [] |
| accepted_observables | list[Observable] | [] |
| errors | list[VerificationIssue] | [] |
| action | Literal['AUTO','REVIEW','ESCALATE'] | 'REVIEW' |
| policy_reasons | list[str] | [] |
| timings | Timings | tous les champs à 0.0 |
| report_path | str? | null |

Hors état : Settings, clients HTTP/VT/pycti/Chroma, horloge monotone et deadline, bytes MIME temporaires, credentials. Un `Services`/`ToolContext` simple porte ces dépendances. Les bytes d'image ne sont chargés qu'au moment de l'appel autorisé ; l'état ne contient que références et empreintes.

`GateResult = {decision: Literal['simple','complex'], reasons: list[str], rule_hits: {R1:bool,R2:bool,R3:bool}}`. Défaut avant décision=null ; après décision reasons=[] seulement pour simple.

## 2.3 ParsedEmail et sous-modèles

Tous les champs suivants sont obligatoires à la création du modèle ; les défauts d'absence sont précisés. Un champ absent dans la source ne doit jamais être complété par une valeur plausible.

| Modèle | Champs, types et défauts |
|---|---|
| ParsedEmail | `email_sha256:str` calculé sur les bytes d'origine ; `raw_size_bytes:int`; `input_format:Literal['rfc822','mbox_member','structured_public_text']`; `headers:list[Header]=[]`; `subject:str?=null`; `from_addresses:list[str]=[]`; `to_addresses:list[str]=[]`; `cc_addresses:list[str]=[]`; `reply_to:list[str]=[]`; `return_path:list[str]=[]`; `date_raw:str?=null`; `message_id:str?=null`; `text_parts:list[TextPart]=[]`; `html_parts:list[TextPart]=[]`; `links:list[Link]=[]`; `attachments:list[Attachment]=[]`; `images:list[VisualEvidence]=[]`; `authentication:list[AuthObservation]=[]`; `defects:list[str]=[]`; `content_limits:list[str]=[]`; `essential_visual_content:bool=false`; `observables:list[Observable]=[]`; `evidence:list[Evidence]=[]` |
| Header | `index:int`, `name:str`, `raw_value:str`, `decoded_value:str`; pas de dict qui supprime les répétitions |
| TextPart | `part_id:str`, `mime_type:str`, `charset:str?=null`, `text:str=''`, `decode_defects:list[str]=[]`; indexation stable des parties par parcours MIME |
| Link | `id:str`, `part_id:str`, `raw_value:str`, `normalized_value:str?=null`, `display_text:str?=null`, `display_url:str?=null`, `role:Literal['href','visible_url','form_action','remote_resource','qr_url']`, `hostname:str?=null`, `href_display_mismatch:bool=false`, `transformation:str?=null`; aucune résolution réseau |
| Attachment | `part_id:str`, `filename:str?=null`, `mime_type:str`, `disposition:str?=null`, `content_id:str?=null`, `decoded_size_bytes:int?=null`, `sha256:str?=null`, `sha1:str?=null`, `md5:str?=null`, `decode_status:Literal['ok','error','over_limit']`, `is_inline:bool=false`; hash=null si les bytes ne sont pas disponibles |
| AuthObservation | `mechanism:Literal['spf','dkim','dmarc']`, `result:str`, `domain:str?=null`, `authserv_id:str?=null`, `header_index:int`, `trust:Literal['trusted_receiver','reported_unverified']='reported_unverified'`; pas de vérification DNS rétroactive |

`has_full_headers` du manifest signifie ici **couverture de champs**, pas authenticité : From, To, Subject, Date, Message-ID, Received et Return-Path présents et non vides. Les champs Authentication-Results/DKIM-Signature restent des dimensions indépendantes ; leur absence n'invalide pas un RFC822 historique. Ajouter `header_integrity: original|transformed|partial|unknown` et `header_presence` par champ pour éviter de surinterpréter le booléen.

`essential_visual_content` est une heuristique conservatrice : image MIME présente et moins de 80 caractères textuels utiles, ou demande explicite de scanner un QR alors qu'aucune URL n'a été extraite. Ne pas prétendre mesurer le pourcentage de pixels sans décodage. Un signal visuel manquant est une limite de couverture, pas une preuve de phishing.

Pour les datasets JSON sans SMTP, `structured_public_text` est réservé aux évaluations de contenu séparées. Le parseur `.eml` de production n'invente aucun header. Le corpus normalisé peut conserver ces exemples mais le benchmark RFC822 les sépare explicitement.

## 2.4 Preuves, assertions et observables

Les champs exacts d'Evidence/Observable/ToolResult/VisualEvidence figurent dans le schema du rapport. IDs déterministes préfixés `obs_`, `ev_`, `vis_` + SHA-256 de leur représentation canonique. Deux IDs identiques avec des contenus différents font échouer le merge. Les références de provenance ne sont pas des chaînes libres inventées par Luna : elles viennent du parser/adaptateur. `Inference.rag_case_ids` est toujours vide en internal ; en final, il référence seulement les voisins effectivement fournis.

`Evidence.value` est un scalaire. Pour une liste de redirections ou de champs DOM, créer plusieurs observations avec source_ref et index distincts. Les compteurs VT sont numériques et positifs ; `vt_engine_total` est la somme des catégories retournées, avec périmètre documenté. Les URL finales/chaînes se fondent sur les navigations du document principal. `source_group` permet de marquer un même feed repris par plusieurs outils ; deux outils ne constituent pas nécessairement deux sources indépendantes.

`source_ref` est local : partie MIME/header/extrait, ou chemin de réponse + JSON Pointer. Une evidence OSINT/SANDBOX doit être retrouvable dans une réponse réelle archivée de statut ok ; timestamps et empreinte de réponse sont obligatoires. Une réponse absente ne peut avoir une evidence positive. Pour not_found/unavailable, conserver le statut, pas une preuve de bénignité.

La provenance de l'existence d'un hash calculé sur l'email reste INTERNE après un lookup VT. La réputation retournée est une autre evidence OSINT. Un domaine découvert uniquement dans une redirection urlscan est SANDBOX. Le LLM n'a aucun droit d'écriture sur ces objets.

**RAG public uniquement :** RagCase porte `public_source_url`, `dataset`, `record_sha256`, `validated_label`, `analyst_validation_ref`, `duplicate_group`, `family_group`, `campaign_id`, `embedding_model_id`, `is_public=true`, `split=rag_reference`. Une annotation humaine d'un exemple public est permise ; aucun historique SOC, email privé ou prediction non validée dans l'index. Les cas RAG ne rejoignent jamais le registre des observables du message courant. Leur emploi par Luna est une INFERENCE d'analogie ; ce n'est pas une cinquième provenance et ce n'est pas OSINT sur l'artefact exact.

## 2.5 Assessment : ce que le LLM runtime produit réellement

Le LLM runtime produit uniquement : six probabilités ; `observations` (IDs de preuves existantes) ; au plus six `inferences` courtes (code, texte ≤240 caractères, IDs de support) ; propositions de catégorie sur IDs d'observables existants ; `needs_enrichment` ; `missing_information` ; au plus trois `decisive_evidence_ids`.

Pas de copie de compteur VT, de nouvel IOC, de timestamp ou de statut outil dans la sortie LLM. Les faits destinés au rapport sont rendus à partir des preuves référencées. Les inferences sont explicitement étiquetées INFERENCE dans le rendu. Ce contrat réduit ce que le vérificateur doit prouver ; il ne prétend pas rendre le jugement sémantique déterministe.

Probabilités p : toutes finies, 0≤p≤1, somme à 1 ±0,000001. Ne pas renormaliser automatiquement une sortie invalide. Le code choisit argmax, tie-break fixe dans l'ordre de la taxonomie ci-dessus, et `confidence=p[verdict]`. Le tri pour la marge utilise les deux plus grandes valeurs. Le tie-break ne doit pas masquer une faible marge : R1 force complex puis REVIEW si ambiguïté persistante.

`internal` ne référence que des preuves INTERNE et les visuels de l'email réellement fournis. `final` peut référencer INTERNE/OSINT/SANDBOX, jamais une prétendue evidence provenant de l'analogie RAG. Les propriétés inconnues sont refusées. Les défauts d'Assessment ne sont jamais utilisés pour créer un faux succès : si Luna manque, Assessment=null.

**Remarque TICKET-09 — énumérations explicites dans le prompt final (écart documenté).** Comme pour l'INTERNAL en TICKET-04, le proxy réel n'applique pas `response_format=json_schema` au modèle : `prompts/final_assessment.txt` énumère désormais mot pour mot les listes fermées de `code` (inference), `reason_code` et `missing_information`, telles que définies par le schema. Le schema, la taxonomie, les règles métier et le message utilisateur final restent inchangés ; aucun label, seuil ou fixture n'a été ajusté.

## 2.6 Rapport, validité et résumés

Le rapport reprend tous les champs minimum demandés. Ajouts nécessaires : version, run_status, final_source, evidence IDs, erreurs typées, usage/coûts, empreintes de reproduction. `decisive_evidence` est une liste de phrases générées par le code à partir de `decisive_evidence_ids`, pas des affirmations libres du modèle. `unsupported_claims` recense les violations de support, pas toutes les inférences légitimes ; les inférences soutenues ont leur propre liste.

Si final_llm échoue et internal est valide : final reprend internal, final_source=internal_fallback, run_status=degraded, REVIEW au minimum. Si les deux échouent : probabilités/verdicts finaux null, run_status=error, REVIEW. `verdict_changed` est bool seulement si les deux verdicts existent, sinon null. Ce n'est pas false quand la comparaison est impossible.

Résumé français ≤100 mots et six rubriques : objet/expéditeur (échappés et bornés), verdict et score déclaré, synthèse des codes de raison validés, preuve la plus forte rendue depuis le registre, principale limite, action. Utiliser des templates déterministes ; pas de troisième appel Luna. Une URL dangereuse est défangée pour lecture, sa valeur exacte reste dans le JSON restreint. Aucun HTML actif.

Le texte libre des inferences est conservé comme analyse du modèle ; il n'est pas réutilisé comme preuve factuelle ni comme titre opératoire. Le résumé utilise les codes et faits typés. Ainsi une hallucination de prose ne se transforme pas automatiquement en IOC ou ordre d'action.

Timings : valeurs non négatives, total mesuré de l'entrée à la fin d'écriture, non obtenu en additionnant des arrondis. Les phases non exécutées valent 0. Les temps de collectes espacées hors pipeline et de recalcul offline sont séparés dans le manifest de batch. Usage output inclut les reasoning tokens lorsque l'API les compte déjà : ne pas les additionner une seconde fois.

## 2.6.1 Audit des entrées LLM INTERNAL et FINAL, sans changement des interfaces

Pour chaque tentative INTERNAL ou FINAL effectivement émise, calculer et archiver `<phase>_attempt_<n>.input_audit.json`, lié au même run, à la phase, au numéro de tentative et à la réponse/erreur. Le client sérialise une seule fois, calcule l'audit sur **ces mêmes bytes**, puis transmet exactement ces bytes (`content=payload_bytes`) au vrai endpoint configuré. Ne pas calculer l'audit sur ParsedEmail ou sur les registres avant projection, réduction de contexte, sélection des preuves ou sérialisation.

La persistance du body HTTP complet dépend du profil de source et s'applique aux deux phases :
- `source_profile=fixture` : `<phase>_attempt_<n>.request.json` peut être archivé pour la preuve de câblage et de routage ;
- `source_profile=public_corpus` ou `private_authorized` : **ne jamais persister le payload HTTP complet**. Il reste en mémoire uniquement le temps du calcul des hashes/compteurs et de l'appel réseau ; seuls l'audit, les hashes, compteurs, statuts et réponses nécessaires au protocole sont conservés.

Aucun en-tête HTTP d'authentification n'est archivé. Cette règle de minimisation ne change ni les prompts, ni le schema, ni les bytes réellement envoyés au modèle.

Champs communs obligatoires INTERNAL et FINAL :

| Champ obligatoire de l'audit | Définition déterministe |
|---|---|
| `phase` | `internal` ou `final` |
| `input_payload_sha256` | SHA-256 des bytes exacts du body HTTP envoyé, prompt système et paramètres compris |
| `untrusted_email_sha256` | SHA-256 de `C(UNTRUSTED_EMAIL)` extrait du message utilisateur dans ce body |
| `body_chars_sent` | somme de `len(text)` des champs `text` des `text_parts` et `html_parts` effectivement inclus dans UNTRUSTED_EMAIL, après réduction de contexte |
| `headers_chars_sent` | somme de `len(name)+len(decoded_value)` des headers effectivement inclus ; champs absents comptés 0 |
| `evidence_count_sent` | nombre d'entrées effectivement incluses dans EVIDENCE_REGISTRY |
| `observable_count_sent` | nombre d'entrées effectivement incluses dans OBSERVABLE_REGISTRY |

Champs supplémentaires obligatoires pour FINAL :

| Champ FINAL | Définition déterministe |
|---|---|
| `internal_evidence_count_sent` | nombre d'entrées EVIDENCE_REGISTRY de provenance `INTERNE` effectivement incluses |
| `external_evidence_count_sent` | nombre d'entrées EVIDENCE_REGISTRY de provenance `OSINT` ou `SANDBOX` effectivement incluses |
| `tool_status_digest` | SHA-256 de `C(TOOL_STATUS)` tel qu'effectivement inclus dans le message utilisateur FINAL |
| `rag_case_count_sent` | nombre de cas effectivement inclus dans `RAG_CONTEXT` |
| `visual_count_sent` | nombre de blocs image/pixels effectivement joints à l'appel FINAL ; les seules métadonnées visuelles ne comptent pas |

`C(x) = json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')`, sans newline. Les compteurs mesurent des caractères Unicode, pas des bytes, du contenu utile seulement : ni ponctuation JSON ni longueur d'un ID/hash ne remplace un body. Le message utilisateur conserve la forme existante ; en multimodal, lire son premier bloc texte JSON. Les mesures et chemins d'audit ne sont jamais ajoutés à l'enveloppe LLM.

Pour les fixtures, la capture exacte et les hashes sont recalculables localement à partir du même fichier request ; le test vérifie aussi que ces bytes sont ceux remis au transport HTTP, sans serveur ni réponse simulés. Pour `public_corpus` et `private_authorized`, le même code sérialise une seule fois, calcule hashes/compteurs sur ces bytes en mémoire, puis transmet ces mêmes bytes sans écrire de fichier request : un test unitaire/fixture démontre cette identité de chemin de code. Conserver les preuves de toutes les tentatives, y compris refus/timeouts/JSON invalide ; une tentative non envoyée est explicitement identifiée et ne compte jamais comme appel réel. `CallRecord.request_sha256` garde son champ existant : hash du dernier payload effectivement envoyé dans la phase, null si aucun. Les audits par tentative portent les autres mesures ; aucune extension du schema Assessment/TriageReport ni de `complete_json`/`assess_internal`/`assess_final` n'est nécessaire.

Pour l'expérience A/B/C de G6, l'audit FINAL est une preuve expérimentale obligatoire :
- variante B : `external_evidence_count_sent == 0`, `evidence_count_sent == internal_evidence_count_sent`, `rag_case_count_sent == 0`, `visual_count_sent == 0` ; `TOOL_STATUS` identifie explicitement l'ablation ;
- variante C : si le bundle réellement collecté contient au moins une evidence OSINT/SANDBOX admissible, `external_evidence_count_sent > 0`. Si aucune evidence externe n'a été produite malgré l'exécution des outils, conserver zéro et tracer `no_new_external_evidence` au lieu d'inventer une preuve ;
- les digests/statuts doivent permettre de démontrer que B et C n'ont pas seulement des hashes de payload différents, mais des contenus expérimentaux conformes au protocole.

Les payloads exacts éventuellement archivés pour les fixtures sont des données restreintes sous `runs/` et git-ignorées ; pour corpus publics et emails privés, seuls hashes, compteurs et digests d'entrée sont persistés hors réponse du modèle.

## 2.7 Settings et dépendances injectées

Noms d'environnement canoniques et valeurs par défaut ; tous les secrets sont SecretStr | None et ne figurent jamais dans model_dump public.

Pour un run officiel, `LITELLM_MODEL` vaut explicitement `Qwen/Qwen3.8-27B`. La seule dérogation est un test technique identifié avec `openai/gpt-oss-20b`, archivé hors des artefacts de mesure G2/G5/G6. `AKASHML_API_KEY` n'est pas un alias applicatif automatique : l'opérateur injecte explicitement la même credential opaque dans `LITELLM_API_KEY`. Une future configuration Orange réutilise exactement ces champs.

| Champ Settings / variable | Type | Défaut |
|---|---|---|
| LITELLM_CHAT_URL | str URL HTTPS | https://api.akashml.com/v1/chat/completions |
| LITELLM_MODEL | str | Qwen/Qwen3.8-27B |
| LITELLM_API_KEY | SecretStr? | null |
| VT_API_KEY | SecretStr? | null |
| VT_ACCESS_AUTHORIZED | bool | false |
| OPENCTI_URL | str URL HTTPS | https://demo.opencti.io |
| OPENCTI_API_KEY | SecretStr? | null |
| URLSCAN_API_KEY | SecretStr? | null |
| MODEL_SUPPORTS_VISION | bool | false |
| RAG_ENABLED | bool | false |
| QR_DECODE_ENABLED | bool | false |
| LIVE_INTEGRATION | bool | false ; --live l'active explicitement pour les tests concernés |
| RUNS_DIR | Path | runs |
| CORPUS_DIR | Path | corpus |
| CONFIG_DIR | Path | configs |
| RAG_DIR | Path | corpus/rag/chroma |
| MAX_EMAIL_SECONDS | float>0 | 240 |
| INTERNAL_PHASE_SECONDS | float>0 | 60 |
| FINAL_PHASE_SECONDS | float>0 | 90 |
| INTERNAL_MAX_OUTPUT_TOKENS | int>0 | 8192 |
| FINAL_MAX_OUTPUT_TOKENS | int>0 | 16384 |
| MAX_LLM_ATTEMPTS | int 1..2 | 2 |
| LIVE_VT_KNOWN_SHA256 | str? | null ; artefact public approuvé du smoke |
| LIVE_CTI_KNOWN_VALUE | str? | null ; valeur connue vérifiée sur l'instance |
| LIVE_CTI_KNOWN_TYPE | ObservableType? | null |
| LIVE_BENIGN_URL | str URL? | null ; URL de test réellement accessible et autorisée |
| LIVE_REDIRECT_URL | str URL? | null ; redirection bénigne pour smoke |

`configs/tools.yaml` possède exactement les sections `virustotal`, `opencti`, `urlscan`, `rag`, `vision`, `egress`, `parse_limits`. Chaque section est validée par Pydantic, valeurs non reconnues interdites. VT : enabled=true mais access non autorisé empêche tout appel, max_targets=4, phase_timeout_s=20, requests_per_minute=4, requests_per_day=500. OpenCTI : enabled=true, max_targets=4, first=10, phase_timeout_s=20. urlscan : enabled=true, max_urls=1, visibility_real=private, visibility_fixture=unlisted, first_poll_s=10, poll_interval_s=5, phase_timeout_s=45 (mapping visibility autoritatif par `source_profile`, §2.7.2). Absence de clé donne unavailable/not_configured, pas un succès.

RAG : enabled piloté par RAG_ENABLED, max_cases=150 initialement, k=3, max_distance=0.40, max_case_chars=1200, embedding_model=all-MiniLM-L6-v2. Vision : enabled piloté par MODEL_SUPPORTS_VISION, max_images=4, max_image_bytes=4194304, max_total_bytes=8388608, max_pixels=16000000 ; le décodage QR obéit séparément à QR_DECODE_ENABLED. parse_limits reprend exactement les nombres de §1.5 architecture.

Egress : `allow_real_urls=false`, `approved_services=[]`, `approved_exact_url_hosts=[]`, `trusted_authserv_ids=[]`, `shared_hosts=[]`, `trusted_cti_sources=[]`. Les services et hôtes autorisés sont une décision de configuration de l'opérateur, issue des autorisations applicables ; aucune inference LLM ne peut les ajouter. Pour les scans de smoke, l'URL configurée et son caractère bénin/public doivent être revus avant activation. Les `.test` ne sont jamais soumis même si un flag est activé. Les secrets détectés restent refusés. Un domaine approuvé ne certifie pas à lui seul l'innocuité d'une URL à jeton.

`Services` contient `settings:Settings`, `luna:LunaClient`, `vt:VirusTotalAdapter`, `cti:OpenCTIAdapter`, `urlscan:UrlscanAdapter`, `rag:RagAdapter|None`, `clock:Callable[[],float]`. Le nom `LunaClient` est conservé comme interface historique ; il désigne le client OpenAI-compatible générique et ne sélectionne aucun fournisseur. `LunaClient(settings)` expose `complete_json(messages, schema, effort, max_output_tokens, deadline) -> (dict | None, CallRecord)`. POST réel à l'endpoint exact de Settings (`LITELLM_CHAT_URL`), headers d'authentification construits par le client hors messages, jamais archivés. La clé est une credential Bearer opaque, sans validation ou conversion de préfixe. Structured output `response_format=json_schema` strict ; aucun fallback de modèle, de fournisseur ou de structured outputs : refus, timeout, `finish_reason` anormal, JSON invalide, schema invalide ou type inattendu produisent une erreur explicite et `result=None`. Captures : usage, modèle réellement retourné, hashes de payload/réponse ; jamais de request header ni de valeur de clé. `ToolContext` contient `run_id:str`, `source_profile`, `deadline:float` monotone, `egress:EgressConfig`, `capture_dir:Path`, `mode:live|recorded`, et n'est jamais sérialisé dans l'état. Les credentials restent dans les instances des clients. `normalize_response(query:Observable, body:Mapping[str,object], metadata:ResponseMetadata)->ToolResult` est propre à chaque adaptateur ; ResponseMetadata contient origin/HTTP status/date/empreinte/référence locale, sans en-tête de clé.

### 2.7.1 OpenCTI : projection bornée et correspondance exacte (figées après lecture réelle)

Lecture réelle du 19/09/2026 sur l'instance configurée : version plateforme observée `7.260914.0` (requête `about`), client `pycti==7.260914.0` verrouillé dans `requirements.lock` (aligné sur la version observée ; toute version serveur différente doit être revalidée avant réutilisation). Introspection observée : le type `StixCyberObservable` n'expose pas de champ `revoked` ; `StixFile` expose `hashes { algorithm hash }`.

- Projection figée (`OPENCTI_PROJECTION`) : `id`, `standard_id`, `entity_type`, `created_at`, `updated_at`, `objectLabel { value }`, `externalReferences { edges { node { source_name url } } }`, `observable_value`, `x_opencti_score`, fragments `... on DomainName | Url | IPv4Addr | IPv6Addr { value }` et `... on StixFile | Artifact { hashes { algorithm hash } }`. Aucune traversée de graphe (`indicators`, `toStix`, `createdBy`, `objectMarking` exclus) ; aucun JSON fournisseur complet ne rejoint le résultat.
- Recherche bornée unique : `stix_cyber_observable.list(search=valeur, first=config.first (10), getAll=False)`, sans pagination. La recherche plein texte est approximative (observé : une valeur proche renvoie d'autres observables, une valeur absente renvoie des candidats sans rapport) : un résultat de recherche n'est jamais une correspondance. La reconnaissance exacte est locale (type attendu ET valeur/algorithme) ; le premier résultat n'est jamais retenu arbitrairement et un candidat non exact ne corrobore rien. `not_found` = recherche techniquement réussie sans correspondance exacte ; ce n'est jamais une preuve de bénignité.
- Types comparables localement : `domain` (insensible à la casse, point final retiré), `url` (égalité exacte avec la valeur extraite ou sa normalisation locale documentée ; aucune renormalisation fournisseur supposée), `ipv4`/`ipv6` (égalité canonique `ipaddress`, adresses globales uniquement), `sha256`/`sha1`/`md5` (algorithme + condensat, types `StixFile`/`Artifact`). `email`, `message_id` et `campaign_id` n'ont pas de comparaison exacte locale : `skipped/not_applicable` ; les destinataires ne sont jamais des cibles de requête.
- Assertions exposées : `cti_exact_match` (EXACT), puis `cti_label`, `cti_score`, `cti_external_reference` uniquement s'ils existent sur l'objet exact (les références sont exposées sans navigation vers leur contenu). `cti_revoked` n'est pas productible pour un SCO (champ absent du schéma observé) et n'est pas fabriqué. Présence, label ou score ne prouvent pas la malveillance et ne décident jamais du phishing.
- Sortie vers tiers : OpenCTI est un tiers externe pour TOUS les types d'observables, même en lecture seule. L'ordre des contrôles est figé : (1) applicabilité locale, (2) dépendance pycti, (3) présence de `OPENCTI_API_KEY` — absente : `unavailable/not_configured`, zéro requête (contrat §2.7) —, (4) approbation du service : sans `opencti` dans `egress.approved_services`, `skipped/privacy_policy` (`service_not_approved_in_egress`), zéro requête et aucune capture ; l'approbation précède toujours toute requête provider. Pour une URL, cette approbation est nécessaire mais non suffisante : `allow_real_urls`, l'hôte exact approuvé et les refus anti-userinfo/jeton/action/identifiant personnel/hôte interne restent exigés. Seuls les contextes officiels de test/smoke contre la démo publique approuvent explicitement le service ; `configs/tools.yaml` reste `approved_services=[]` par défaut.
- Budget et erreurs : borne dure = min(reste de la deadline, `phase_timeout_s`) en float exact, jamais arrondie ; sous 0,5 s restant, `unavailable/deadline` sans requête. Timeout, 401/403, 429, erreurs GraphQL et réponses illisibles deviennent `unavailable` avec cause. Un jeton expiré ou réinitialisé (démo) est observé comme erreur GraphQL `AUTH_REQUIRED` en HTTP 200 et traité en `auth_error`, jamais en résultat fabriqué. Aucune mutation GraphQL n'est émise : elles sont refusées avant émission et aucun chemin create/update/delete n'existe dans l'adaptateur.

### 2.7.2 urlscan : visibilité, observation bornée et navigation du document principal (figées après lecture réelle)

Lecture réelle du 19/09/2026 via l'API publique `https://urlscan.io` (soumissions `private` et `unlisted` confirmées, `pending` naturel observé, chaîne de redirection lue sur `data.redirects`, DOM privé récupéré). Amendement opérateur TICKET-08 : les URLs bénignes à scanner sont fournies par `LIVE_BENIGN_URL` / `LIVE_REDIRECT_URL` ; les contextes officiels de test/smoke construisent un `EgressConfig` temporaire explicite (allow_real_urls, service `urlscan`, hôtes exacts) et `configs/tools.yaml` reste safe-by-default.

- **Origin et endpoints uniques** : toutes les requêtes sont construites à partir de l'origine approuvée `URLSCAN_ORIGIN = https://urlscan.io` : `POST /api/v1/scan/` (une soumission), `GET /api/v1/result/<uuid>/` (poll borné), `GET /dom/<uuid>/` (DOM inerte après succès), `GET /screenshots/<uuid>.png` (binaire, uniquement si `MODEL_SUPPORTS_VISION`). La clé voyage seulement dans l'en-tête `API-Key` de ces appels same-origin ; elle n'entre ni dans le contexte, ni dans les captures, ni dans les résultats. Les redirections HTTP ne sont jamais suivies vers un autre origin : une `Location` cross-origin est refusée localement avant toute requête (l'URL de récupération est reconstruite depuis l'origine et l'UUID validé, jamais depuis une URL arbitraire de la réponse).
- **Une URL, une soumission** : seul un observable `url` est soumis (tout autre type = `skipped/not_applicable`). Le budget local `max_urls` est vérifié avant la soumission et journalisé (petit JSON `runs/quota/urlscan.json`, survit au redémarrage) : une seconde soumission pour le même run est refusée `skipped/budget` avec zéro requête, sans jamais attendre ni consommer le quota fournisseur. Un POST ambigu (timeout/échec de transport) n'est JAMAIS resoumis (`requests_sent=1`, cause explicite) ; la tentative consomme le budget local.
- **Visibilité autoritative par source_profile** (amendement opérateur) : `fixture` et `public_corpus` → `visibility_fixture` (unlisted), `private_authorized` → `visibility_real` (private). Jamais `public`, jamais de fallback. La visibilité demandée est envoyée explicitement et vérifiée dans la réponse POST (`uuid` validé RFC 4122, `visibility` confirmée) ; un `uuid` absent/invalide donne `unavailable/malformed_response`, une visibilité non confirmée donne `unavailable/api_error` (`visibility_not_confirmed`) avec `scan_id` conservé — jamais de downgrade silencieux.
- **Après POST accepté** : attente `first_poll_s` (10 s), puis poll toutes les `poll_interval_s` (5 s) dans le budget total ≤ `phase_timeout_s` (45 s), borne dure = min(reste deadline, phase_timeout_s) en float exact. Avant résultat, `404` = **pending** (jamais `not_found`) ; `410` = résultat supprimé (`unavailable/api_error`, `result_gone_http_410`) ; `429` = `rate_limited` ; `401/403` = `auth_error` ; autre non-2xx = `api_error`. Budget épuisé en attente de résultat = `unavailable` (`timeout`, ou `deadline` si la deadline de contexte est la borne) avec `still_pending_after_phase_budget` et `scan_id` conservé.
- **Schéma de résultat observé (gelé)** : `task` (dont `uuid`, `url`, `visibility`), `page` (dont `url`, `domain`, `status` ; pas de champ `title` observé), `verdicts.overall.malicious` (booléen nommé comme assertion fournisseur), `data.redirects = [{from, to, status}]` (chaîne principale fournie) et `data.requests` (entrées `request.request.url`, `request.type`, `response.response.status/redirectURL` ; après redirection, la liste peut ne contenir que le document final). `page.url` est l'observation de cette exécution, pas une garantie historique.
- **Navigation principale** : `sandbox_redirect` n'utilise `data.redirects` que si la chaîne `from`→`to` part exactement de l'URL soumise ; sinon repli sur les entrées `Document` avec `redirectURL`, en ignorant ressources et sous-requêtes. Chaîne non démontrable = partielle/inconnue, aucune étape inventée ; `sandbox_final_url` provient de `page.url`.
- **DOM inerte** : `GET /dom/<uuid>/` archivé en bytes exacts ; extraction stdlib (`HTMLParser`) sans exécution ni fetch : `script/style/noscript/template/svg` ignorés ; bornes : 2 MiB de HTML, 20 000 caractères stockés (`text_full_bounded`), `text_excerpt` = exactement l'extrait ciblé par l'evidence (≤1 000 caractères), ≤50 champs de formulaire stockés, ≤20 exposés en evidence. `form_fields` = name/id + type déclaré. Un DOM ou un screenshot absent/404 ne supprime jamais le résultat JSON ; le screenshot binaire n'est téléchargé que si la vision est active.
- **Assertions exposées** : `sandbox_final_url`, `sandbox_page_title` (ou titre DOM quand `page.title` est absent), `sandbox_provider_malicious`, `sandbox_redirect`, `sandbox_dom_excerpt`, `sandbox_form_field`, `sandbox_screenshot` (hash, seulement si le binaire a été réellement téléchargé) ; provenance SANDBOX, `source_ref` pointant dans la capture archivée. Absence/skip n'est jamais une preuve de bénignité.
- **Sortie vers tiers** : mêmes refus URL que VT/OpenCTI (userinfo, paramètre de type credential, action à effet, identifiant personnel, hôte interne/réservé, IP non globale, schéma non HTTP(S)) ; approbation du service `urlscan`, `allow_real_urls` et hôte exact requis en plus. Les `.test`/`.invalid`/localhost ne sont jamais soumis, même avec approbations.
- **Couverture live observée** : soumissions réelles `private` (pytest) et `unlisted` (smoke public-fixture) validées, `pending` naturel (404 réels) observé, chaîne de redirection réelle vérifiée, capture DOM privée, budget local refusé sans réseau. Aucun 429 fournisseur observé (`provider_429_observed=false`) : le traitement du code 429 est vérifié comme entrée numérique sur la fonction de mapping, sans fabriquer de réponse.

### 2.7.3 Vision et QR locaux (TICKET-16, figé pour la branche parallèle)

Capabilité Vision/QR bornée dans le module unique `src/vision.py`, réutilisant les contrats existants ; pas de second pipeline, pas d'intégration graphe dans cette branche (la synchronisation appartient à T19C).

- Interfaces : `prepare_visuals(parsed, limits: VisionToolConfig) -> list[VisualEvidence]` et `decode_qr(image_bytes: bytes) -> list[str]`. `prepare_visual_bundle(parsed, limits, *, image_bytes=None, qr_enabled=False)` renvoie en plus les pixels mis en scène (`StagedVisual`, objets runtime uniquement — jamais persistés dans l'état). `load_image_bytes(raw_email, parsed)` charge les bytes des images acceptées par le parseur via `parsing.extract_image_parts` (même parcours, mêmes `part_id`, mêmes limites de décodage).
- Déterminisme : ordre = ordre des images du parseur ; chaque visual conserve id, SHA-256 des bytes d'origine, mime déclaré, provenance, part/content ids et `local_ref` ; seuls `width`/`height`, `status` et `qr_payloads` sont produits. Aucune représentation dérivée n'est créée dans ce POC : `derived_sha256` est le SHA-256 **calculé indépendamment** des bytes exacts mis en scène (jamais recopié du parent) et doit être égal au `sha256` d'origine ; une association `part_id → bytes` erronée (hash différent) est refusée en `unavailable`, jamais envoyée avec le hash de l'original. Toute dérive future devra hasher ses bytes dérivés indépendamment et conserver la référence parente.
- Formats : PNG/JPEG uniquement (mime déclaré ET format réellement détecté par Pillow ; contenu autoritaire en cas de mime mal étiqueté). Tout le reste (SVG, GIF, références distantes, exécutables, PDF, Office) = `unsupported`, jamais décodé. Image corrompue = `unavailable` ; violation de limite = `over_limit` — jamais une exception qui casse l'analyse de l'email.
- Limites exactes (configs/tools.yaml `vision`, pilotées par `MODEL_SUPPORTS_VISION`, QR séparément par `QR_DECODE_ENABLED`) : `max_images=4`, `max_image_bytes=4194304` (4 MiB), `max_total_bytes=8388608` (8 MiB), `max_pixels=16000000`. Les limites sont vérifiées AVANT tout traitement coûteux quand c'est possible (taille avant décodage, pixels avant staging).
- QR : décodage local uniquement via zxing-cpp ; payloads exactes préservées, déduplication déterministe des doublons exacts, ordre stable, attachées à `VisualEvidence.qr_payloads`. Payload HTTP(S) : rejoint uniquement les contrats parser/evidence existants (`Link(role="qr_url")`, `Observable(type="url", roles=["link_target"], provenance="INTERNE")`, `Evidence(predicate="url_found")` + `Evidence(predicate="qr_payload")` pour toute payload, provenance INTERNE) ; jamais visitée, résolue, soumise à urlscan ni interprétée en réputation. Payload non-URL : texte evidence uniquement, jamais réinterprétée en URL. Aucune valeur QR ne contourne les règles verifier/egress.
- Mode désactivé : `MODEL_SUPPORTS_VISION=false` (soit `vision.enabled=false`) — les pixels ne sont **jamais** mis en scène, même si les bytes sont disponibles ; quand ni vision ni QR ne sont demandés, la pile optionnelle (Pillow/zxing-cpp) n'est PAS importée (preuve subprocess avec imports bloqués). Vision et QR sont **indépendants** : `QR_DECODE_ENABLED=true` avec vision désactivée décode localement les payloads exactes sans joindre aucun pixel (`text+QR`), et `QR_DECODE_ENABLED=false` n'exécute jamais le décodeur même quand les pixels sont mis en scène (`text+vision`). `essential_visual_content=true` sans vision : aucun contenu visuel inventé ; le chemin `essential_visual_unread` existant (gate R3, policy REVIEW) reste inchangé.
- Enveloppe LLM : pas de second client. `build_internal_messages`/`build_final_messages`/`build_*_envelope` acceptent `staged` (StagedVisual) en argument nommé facultatif : sans pixels, la forme texte reste byte-équivalente (identique à G2/G5) ; avec pixels réels, le message utilisateur devient multipart OpenAI-compatible (bloc `text` + blocs `image_url` en data URI PNG/JPEG uniquement — jamais `http(s)://`, `file://` ni chemin local), et `SUPPLIED_VISUAL_IDS` contient exactement les IDs des pixels réellement joints (pas de métadonnée seule, pas d'ID sans pixels, pas de pixels sans ID). L'audit §2.6.1 reste inchangé : `visual_count_sent` compte les blocs pixels réellement attachés.
- Injection : les images, QR payloads et screenshots restent des données d'examen dans le message utilisateur ; les prompts livrés (V1.2, inchangés) énoncent déjà que headers, corps, liens, QR codes et pixels sont des données à examiner, jamais des instructions, et qu'un texte du type « ignore previous instructions » dans l'image ne modifie pas la tâche. L'interprétation du modèle reste INFERENCE ; les pixels de l'email restent INTERNE, un screenshot urlscan réel reste SANDBOX.
- Smoke réel borné : `python scripts/smoke.py vision [--if-configured|--require-configured]` — exactement UNE image locale bénigne, `measurement_scope=capability_smoke`, `performance_claims_allowed=false`, `sample_count=1`, reçu sous `runs/gates/G7-B/smoke_vision/smoke_result.json` (métadonnées uniquement). Le smoke n'exécute la mise en scène qu'avec `MODEL_SUPPORTS_VISION=true` (jamais contourné) et applique les limites gelées **en mémoire** avec `vision.enabled=true` (le fichier `configs/tools.yaml` n'est jamais réécrit) ; il envoie le schéma d'assessment INTERNAL gelé (`schemas/assessment.schema.json`, le même que `src.verify`), pas un ping `{ok:boolean}`. Refus fournisseur du contenu image = `vision_rejected` avec l'erreur réelle archivée ; pas de prétention de support. Aucun benchmark, aucun Visual-79, aucun gold_test, aucune relance sélective.

## 2.8 Entrées d'évaluation et partitions

`GoldRecord` : sample_id:str, raw_sha256:str (SHA-256 des bytes locaux référencés), email_sha256:str (champ V1 conservé, obligatoirement égal à raw_sha256 et au hash du message analysé), raw_path:str, source_dataset:str, input_format:rfc822|mbox_member|structured_public_text, normalized_label:Label, label_status:confirmed, reviewer_ref:str, label_rationale:str, public_source:bool, is_synthetic:bool|null, campaign_id:str|null, duplicate_group:str, family_group:str, tags:list[str], split:dev|test. Aucun de ces champs de label/provenance de dataset n'est envoyé au LLM. Un registre normalisé plus large peut contenir label_status=unreviewed/ambiguous et normalized_label=null ; ces lignes ne sont pas des GoldRecord.

`gold_dev.jsonl` et `gold_test.jsonl` sont des fichiers de métadonnées/labels seulement, publics comme privés. La liste des champs GoldRecord ci-dessus est fermée (`extra='forbid'`) ; `label_rationale` est une justification de label sans citation ni extrait du message. Aucun body, HTML, header, MIME, raw email, pièce, image ou extrait privé, même encodé ou sous un autre nom. Aucun contenu dans un champ de notes. Les bytes sources restent dans `corpus/raw/**`, git-ignorés ; pour mbox, raw_path vise le message extrait traçable, et raw_sha256 ses bytes, pas ceux de la mailbox entière.

**Clarification Gold-AI (amendement opérateur, POC exploratoire 2026-09-20).** `label_status=confirmed` signifie « accepté dans le jeu de référence selon le protocole de revue approuvé » ; il n'affirme pas, en soi, que le relecteur était humain. `reviewer_ref` porte la provenance réelle du relecteur/protocole ; pour ce run Gold-AI : `reviewer_ref=astra_gold_ai_v1`, `review_method=independent_dual_model_ai_adjudication`, `human_validated=false` (conservé dans l'artefact d'adjuration externe, source d'audit). Ce ne sont PAS des labels analyste humains ni un ground truth humain ; terminologie admise : AI-adjudicated reference labels, Gold-AI, reference-confirmed. Si les noms legacy V1 `analyst_validation_ref`/`analyst_rationale` subsistent dans `public_cases.jsonl`, ils sont des noms de champ historiques et n'impliquent PAS un relecteur humain pour ce run Gold-AI ; pas de renommage de schéma dans ce ticket.

Avant sélection/évaluation, rejeter tout champ inconnu et rechercher récursivement les clés de contenu, notamment `body`, `html`, `headers`, `raw`, `raw_email`, `mime_content`, `text_parts`, `html_parts`, `attachments`, `images`, `text_excerpt` (comparaison insensible à la casse). Leur présence, même avec une valeur vide/null, invalide le fichier et fait échouer G6. Cette validation ne doit pas ouvrir le vrai test depuis le build : mêmes contrôles sur dev et objets locaux de contrat, puis sur test par l'évaluateur seulement.

Au chargement, raw_path est un chemin relatif à la racine du projet (ex. `corpus/raw/private/...`) dans l'environnement autorisé. Le résoudre, refuser toute sortie de `corpus/raw/` après résolution des liens, charger localement les bytes, recalculer SHA-256 puis vérifier raw_sha256 et email_sha256 avant tout appel Luna/outil. Fichier absent ou mismatch : sample refusé, erreur explicite et validation non PASS, sans exclusion silencieuse des métriques. Le message analysé doit être celui vérifié ; vérifier aussi l'égalité du hash du ParsedEmail/rapport avec raw_sha256, sans réécriture MIME.

**POC simplifié (amendement opérateur, 2026-09-20).** Pour ce POC exploratoire, `gold_test.jsonl` est une **partition de validation interne**, matérialisée dans le workspace de build comme fichier de métadonnées/labels uniquement (même schéma GoldRecord fermé, aucun contenu), accompagnée de `test_seal.json` pour la reproductibilité. Ce n'est PAS un holdout indépendant, isolé ou aveuglé. Interdiction maintenue : tout tuning, modification de prompt, de seuil ou sélection de modèle fondé sur `gold_test` reste interdit ; les décisions de développement utilisent `gold_dev` uniquement.

`public_cases.jsonl` contient la source de RagCase sans distance (qui est calculée à la recherche) et sans embedding_model_id tant que G7 n'a pas préparé l'index. À l'indexation, ces deux champs sont ajoutés aux objets de résultat ; l'artefact de source porte case_id, public_source_url, dataset, record_sha256, validated_label, analyst_validation_ref, campaign_id, duplicate_group, family_group, text_excerpt, analyst_rationale, is_public=true, split=rag_reference. Les features sémantiques d'indexation peuvent utiliser le texte normalisé complet borné ; le résultat transmis au modèle reste limité à 1 200 caractères.
