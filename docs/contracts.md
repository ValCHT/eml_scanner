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

## 2.5 Assessment : ce que Luna produit réellement

Luna produit uniquement : six probabilités ; `observations` (IDs de preuves existantes) ; au plus six `inferences` courtes (code, texte ≤240 caractères, IDs de support) ; propositions de catégorie sur IDs d'observables existants ; `needs_enrichment` ; `missing_information` ; au plus trois `decisive_evidence_ids`.

Pas de copie de compteur VT, de nouvel IOC, de timestamp ou de statut outil dans la sortie LLM. Les faits destinés au rapport sont rendus à partir des preuves référencées. Les inferences sont explicitement étiquetées INFERENCE dans le rendu. Ce contrat réduit ce que le vérificateur doit prouver ; il ne prétend pas rendre le jugement sémantique déterministe.

Probabilités p : toutes finies, 0≤p≤1, somme à 1 ±0,000001. Ne pas renormaliser automatiquement une sortie invalide. Le code choisit argmax, tie-break fixe dans l'ordre de la taxonomie ci-dessus, et `confidence=p[verdict]`. Le tri pour la marge utilise les deux plus grandes valeurs. Le tie-break ne doit pas masquer une faible marge : R1 force complex puis REVIEW si ambiguïté persistante.

`internal` ne référence que des preuves INTERNE et les visuels de l'email réellement fournis. `final` peut référencer INTERNE/OSINT/SANDBOX, jamais une prétendue evidence provenant de l'analogie RAG. Les propriétés inconnues sont refusées. Les défauts d'Assessment ne sont jamais utilisés pour créer un faux succès : si Luna manque, Assessment=null.

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

`C(x) = json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')`, sans newline. Les compteurs mesurent des caractères Unicode, pas des bytes, du contenu utile seulement : ni ponctuation JSON ni longueur d'un ID/hash ne remplace un body. Le message utilisateur conserve la forme existante ; en multimodal, lire son premier bloc texte JSON. Les mesures et chemins d'audit ne sont jamais ajoutés à l'enveloppe Luna.

Pour les fixtures, la capture exacte et les hashes sont recalculables localement à partir du même fichier request ; le test vérifie aussi que ces bytes sont ceux remis au transport HTTP, sans serveur ni réponse simulés. Pour `public_corpus` et `private_authorized`, le même code sérialise une seule fois, calcule hashes/compteurs sur ces bytes en mémoire, puis transmet ces mêmes bytes sans écrire de fichier request : un test unitaire/fixture démontre cette identité de chemin de code. Conserver les preuves de toutes les tentatives, y compris refus/timeouts/JSON invalide ; une tentative non envoyée est explicitement identifiée et ne compte jamais comme appel réel. `CallRecord.request_sha256` garde son champ existant : hash du dernier payload effectivement envoyé dans la phase, null si aucun. Les audits par tentative portent les autres mesures ; aucune extension du schema Assessment/TriageReport ni de `complete_json`/`assess_internal`/`assess_final` n'est nécessaire.

Pour l'expérience A/B/C de G6, l'audit FINAL est une preuve expérimentale obligatoire :
- variante B : `external_evidence_count_sent == 0`, `evidence_count_sent == internal_evidence_count_sent`, `rag_case_count_sent == 0`, `visual_count_sent == 0` ; `TOOL_STATUS` identifie explicitement l'ablation ;
- variante C : si le bundle réellement collecté contient au moins une evidence OSINT/SANDBOX admissible, `external_evidence_count_sent > 0`. Si aucune evidence externe n'a été produite malgré l'exécution des outils, conserver zéro et tracer `no_new_external_evidence` au lieu d'inventer une preuve ;
- les digests/statuts doivent permettre de démontrer que B et C n'ont pas seulement des hashes de payload différents, mais des contenus expérimentaux conformes au protocole.

Les payloads exacts éventuellement archivés pour les fixtures sont des données restreintes sous `runs/` et git-ignorées ; pour corpus publics et emails privés, seuls hashes, compteurs et digests d'entrée sont persistés hors réponse du modèle.

## 2.7 Settings et dépendances injectées

Noms d'environnement canoniques et valeurs par défaut ; tous les secrets sont SecretStr | None et ne figurent jamais dans model_dump public.

| Champ Settings / variable | Type | Défaut |
|---|---|---|
| LITELLM_CHAT_URL | str URL HTTPS | https://management.llmproxy.ai.orange/chat/completions |
| LITELLM_MODEL | str | openai/gpt-5.6-luna |
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

`configs/tools.yaml` possède exactement les sections `virustotal`, `opencti`, `urlscan`, `rag`, `vision`, `egress`, `parse_limits`. Chaque section est validée par Pydantic, valeurs non reconnues interdites. VT : enabled=true mais access non autorisé empêche tout appel, max_targets=4, phase_timeout_s=20, requests_per_minute=4, requests_per_day=500. OpenCTI : enabled=true, max_targets=4, first=10, phase_timeout_s=20. urlscan : enabled=true, max_urls=1, visibility_real=private, visibility_fixture=private, first_poll_s=10, poll_interval_s=5, phase_timeout_s=45. Absence de clé donne unavailable/not_configured, pas un succès.

RAG : enabled piloté par RAG_ENABLED, max_cases=150 initialement, k=3, max_distance=0.40, max_case_chars=1200, embedding_model=all-MiniLM-L6-v2. Vision : enabled piloté par MODEL_SUPPORTS_VISION, max_images=4, max_image_bytes=4194304, max_total_bytes=8388608, max_pixels=16000000 ; le décodage QR obéit séparément à QR_DECODE_ENABLED. parse_limits reprend exactement les nombres de §1.5 architecture.

Egress : `allow_real_urls=false`, `approved_services=[]`, `approved_exact_url_hosts=[]`, `trusted_authserv_ids=[]`, `shared_hosts=[]`, `trusted_cti_sources=[]`. Les services et hôtes autorisés sont une décision de configuration de l'opérateur, issue des autorisations applicables ; aucune inference LLM ne peut les ajouter. Pour les scans de smoke, l'URL configurée et son caractère bénin/public doivent être revus avant activation. Les `.test` ne sont jamais soumis même si un flag est activé. Les secrets détectés restent refusés. Un domaine approuvé ne certifie pas à lui seul l'innocuité d'une URL à jeton.

`Services` contient `settings:Settings`, `luna:LunaClient`, `vt:VirusTotalAdapter`, `cti:OpenCTIAdapter`, `urlscan:UrlscanAdapter`, `rag:RagAdapter|None`, `clock:Callable[[],float]`. `LunaClient(settings)` expose complete_json. `ToolContext` contient `run_id:str`, `source_profile`, `deadline:float` monotone, `egress:EgressConfig`, `capture_dir:Path`, `mode:live|recorded`, et n'est jamais sérialisé dans l'état. Les credentials restent dans les instances des clients. `normalize_response(query:Observable, body:Mapping[str,object], metadata:ResponseMetadata)->ToolResult` est propre à chaque adaptateur ; ResponseMetadata contient origin/HTTP status/date/empreinte/référence locale, sans en-tête de clé.

## 2.8 Entrées d'évaluation et partitions

`GoldRecord` : sample_id:str, raw_sha256:str (SHA-256 des bytes locaux référencés), email_sha256:str (champ V1 conservé, obligatoirement égal à raw_sha256 et au hash du message analysé), raw_path:str, source_dataset:str, input_format:rfc822|mbox_member|structured_public_text, normalized_label:Label, label_status:confirmed, reviewer_ref:str, label_rationale:str, public_source:bool, is_synthetic:bool|null, campaign_id:str|null, duplicate_group:str, family_group:str, tags:list[str], split:dev|test. Aucun de ces champs de label/provenance de dataset n'est envoyé au LLM. Un registre normalisé plus large peut contenir label_status=unreviewed/ambiguous et normalized_label=null ; ces lignes ne sont pas des GoldRecord.

`gold_dev.jsonl` et `gold_test.jsonl` sont des fichiers de métadonnées/labels seulement, publics comme privés. La liste des champs GoldRecord ci-dessus est fermée (`extra='forbid'`) ; `label_rationale` est une justification de label sans citation ni extrait du message. Aucun body, HTML, header, MIME, raw email, pièce, image ou extrait privé, même encodé ou sous un autre nom. Aucun contenu dans un champ de notes. Les bytes sources restent dans `corpus/raw/**`, git-ignorés ; pour mbox, raw_path vise le message extrait traçable, et raw_sha256 ses bytes, pas ceux de la mailbox entière.

Avant sélection/évaluation, rejeter tout champ inconnu et rechercher récursivement les clés de contenu, notamment `body`, `html`, `headers`, `raw`, `raw_email`, `mime_content`, `text_parts`, `html_parts`, `attachments`, `images`, `text_excerpt` (comparaison insensible à la casse). Leur présence, même avec une valeur vide/null, invalide le fichier et fait échouer G6. Cette validation ne doit pas ouvrir le vrai test depuis le build : mêmes contrôles sur dev et objets locaux de contrat, puis sur test par l'évaluateur seulement.

Au chargement, raw_path est un chemin relatif à la racine du projet (ex. `corpus/raw/private/...`) dans l'environnement autorisé. Le résoudre, refuser toute sortie de `corpus/raw/` après résolution des liens, charger localement les bytes, recalculer SHA-256 puis vérifier raw_sha256 et email_sha256 avant tout appel Luna/outil. Fichier absent ou mismatch : sample refusé, erreur explicite et validation non PASS, sans exclusion silencieuse des métriques. Le message analysé doit être celui vérifié ; vérifier aussi l'égalité du hash du ParsedEmail/rapport avec raw_sha256, sans réécriture MIME. Aucun loader n'accède au holdout avant son ouverture terminale autorisée.

`public_cases.jsonl` contient la source de RagCase sans distance (qui est calculée à la recherche) et sans embedding_model_id tant que G7 n'a pas préparé l'index. À l'indexation, ces deux champs sont ajoutés aux objets de résultat ; l'artefact de source porte case_id, public_source_url, dataset, record_sha256, validated_label, analyst_validation_ref, campaign_id, duplicate_group, family_group, text_excerpt, analyst_rationale, is_public=true, split=rag_reference. Les features sémantiques d'indexation peuvent utiliser le texte normalisé complet borné ; le résultat transmis au modèle reste limité à 1 200 caractères.
