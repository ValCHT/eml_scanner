# 7. Corpus, Golden Batch et RAG public

## 7.1 Ce qui a été réellement inspecté

Le 17/09/2026 : téléchargement et inspection intégrale de trois archives SpamAssassin, des deux JSON PhishFuzzer et de la mailbox Nazario 2025 ; inspection des 50 premiers messages du tar Enron CMU en streaming. Pour IWSPA, lecture de la publication des organisateurs et de leur page d'échantillons ; **l'archive du dataset n'a pas été obtenue**, les samples publics sont des PDF. Aucun chiffre d'inventaire IWSPA n'est présenté comme une mesure locale. Aucun corpus privé n'a été fourni ou consulté.

Les fichiers `research/*_inspection.json` du dossier contiennent les empreintes, sources, méthode et comptages. L'inspection actuelle porte sur la structure, pas sur une validation analyste des labels. Les données du corpus ne sont pas incluses dans le livrable.

| Dataset | Taille | Classes source | Format réel | Raw .eml ? | Headers complets ? | HTML ? | URLs ? | Attachments ? | Images ? | Synthétique ? | Transformations | Utilité POC | Limites | Décision |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| IWSPA-AP 2018 headers | Publication : 4 583 train + 4 195 test = 8 778 | phishing / légitime | `.txt` avec headers/corps prétraités | pas de brut non modifié garanti | subset annoncé headers ; couverture par champ non mesurée | HTML nettoyé | URLs remplacées par un marqueur | retirées | pas de bytes d'images garantis | synthétique décrit pour subset sans headers | noms/domaines/signatures normalisés, Base64 retiré | contenu et erreurs de taxonomie | inadapté à mesurer réputation d'URL, MIME/pièces d'origine ; accès archive à obtenir | OPTIONAL ; exclu du benchmark technique principal |
| SpamAssassin 20030228 easy_ham/hard_ham/spam | 2 500 + 250 + 500 = 3 250, comptés | ham / spam | fichiers RFC822 sans extension, dans tar.bz2 | oui, message sérialisé, parfois transformé | nombreux champs conservés, pas tous partout | 431 messages | occurrences HTTP(S) dans 3 016 messages bruts | 51 parties attachées ou nommées | 26 parties image | non annoncé synthétique | certaines adresses/hosts obfusqués et nettoyages documentés | ham difficile, spam, HTML, MIME, RAG public | ancien ; 0 Authentication-Results et DKIM-Signature dans ces trois archives ; spam ≠ notre classe spam automatiquement | KEEP |
| Enron CMU 2015 | environ 0,5 M selon CMU ; 50 premiers inspectés | pas de vérité SOC six classes | fichiers de messages en arborescence tar.gz | sérialisation mail, headers abrégés/transformés | dans 50 : aucun Received/Return-Path/Auth-Results/DKIM | 0/50 ; reste non établi | 2/50 bruts | exclus de cette distribution | aucune/50 | non, source réelle | suppressions et adresses corrigées | style de correspondance métier, exemples bénins à revoir | non preuve d'authenticité ou label legitime garanti ; échantillon non représentatif | OPTIONAL |
| PhishFuzzer seeds | 3 300 comptés | 1 126 Phishing, 1 074 Spam, 1 100 Valid | tableau JSON | non | pas de headers SMTP structurés | Body peut contenir du texte balisé ; pas de MIME original garanti | champ URL non vide 2 723 | File non vide 189 : noms, pas de bytes | pas de champ bytes image | mélange réel et métadonnées enrichies | anonymisation/enrichissement selon auteurs | stress de contenu, transitions de style | labels à revoir ; Original_ID ; pas un `.eml` raw | OPTIONAL ; hors cœur RAG initial |
| PhishFuzzer variants | 19 800 comptés | 6 756 Phishing, 6 444 Spam, 6 600 Valid | tableau JSON | non | non | pas de MIME original | URL non vide 17 438 | File non vide 995, noms | pas de bytes | 19 800 Created by=LLM | six variantes par seed | test séparé de robustesse linguistique | fuite majeure si variantes séparées ; 6 Sender vides | OPTIONAL, pas Golden principal |
| Nazario 2025 | 481 messages comptés | phishing, classé manuellement par auteur | mbox `phishing-2025` | messages RFC822 dans mbox | Received/Return-Path/Auth-Results : 481/481 ; champs parfois manquants | 473/481 | occurrences HTTP(S) brutes 399/481 | 102 parties attachées ou nommées | 55 parties image | collecte réelle déclarée | anciens millésimes anonymisés ; récents non selon auteur | phishing récent, headers, MIME ; référence publique RAG | une boîte personnelle ; erreurs de labels possibles ; pas six classes validées | KEEP, priorité phishing/RAG |
| Privé autorisé | cible 50–100, non fourni | analyste, si disponible | `.eml` à inspecter | à vérifier | à vérifier | à vérifier | à vérifier | à vérifier | à vérifier | dépend de collecte | toutes transformations documentées | évaluation métier contemporaine si autorisé | aucune disponibilité présumée ; **jamais indexé dans le RAG** | OPTIONAL pour évaluation seulement |

Sources de format/provenance : [IWSPA article](https://www2.cs.uh.edu/~rmverma/anti-phishing-pilot.pdf), [page des organisateurs](https://dasavisha.github.io/IWSPA-sharedtask/), [SpamAssassin README](https://spamassassin.apache.org/old/publiccorpus/readme.html), [Enron CMU](https://www.cs.cmu.edu/~enron/), [PhishFuzzer](https://github.com/DataPhish/PhishFuzzer), [Nazario README](https://monkey.org/~jose/phishing/README.txt). Les comptages précis ci-dessus sont nos observations des fichiers téléchargés, et non les performances annoncées dans leurs publications.

**Définitions de l'inspection :** URLs=présence lexicale de `http://`/`https://` dans les bytes bruts, pas comptage du futur parser ; les URL en Base64 peuvent ne pas être repérées. Attachments=nombre de parties MIME avec disposition attachment OU filename, donc peut inclure des images inline nommées. Images=parties MIME image, pas images distantes HTML. HTML et texte se recouvrent en multipart. Ces nombres ne prouvent pas l'exhaustivité des pixels/payloads exploitables. Pour les pièges du parser, recompter par email et bytes décodés en G6.

## 7.2 Présence des headers mesurée

| Source / n inspecté | From | To | Subject | Date | Message-ID | Received | Return-Path | Authentication-Results | DKIM-Signature |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| easy_ham / 2 500 | 2 500 | 2 348 | 2 500 | 2 500 | 2 500 | 2 365 | 2 500 | 0 | 0 |
| hard_ham / 250 | 250 | 250 | 249 | 250 | 250 | 250 | 241 | 0 | 0 |
| spam / 500 | 500 | 500 | 500 | 500 | 500 | 500 | 494 | 0 | 0 |
| Enron / 50 premiers | 50 | 49 | 50 | 50 | 50 | 0 | 0 | 0 | 0 |
| Nazario 2025 / 481 | 481 | 471 | 481 | 478 | 476 | 481 | 481 | 481 | 401 |

Un header présent n'est ni authentifié ni correct. La distribution Enron CMU avertit depuis avril 2026 de questions d'intégrité/authenticité : cela renforce la décision de ne pas assimiler « vient d'Enron » à legitime. Le corps peut rester utile à une étude linguistique. [Avertissement du distributeur](https://www.cs.cmu.edu/~enron/).

## 7.3 Acquisition et normalisation simples

1. Copier/download les originaux dans `corpus/raw/<dataset>/`, avec URL source, date et SHA-256 dans `corpus/sources.json`. Ne jamais exécuter le code fourni par un corpus pour accéder aux données.
2. Sources exactes de départ : [easy_ham](https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2), [hard_ham](https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2), [spam](https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2), [Nazario 2025](https://monkey.org/~jose/phishing/phishing-2025). Enron/PhishFuzzer seulement si le petit corpus manque réellement d'un scénario utile. IWSPA : récupérer une archive officielle/traçable auprès des organisateurs ; ne pas reconstituer les PDF en faux RFC822.
3. Extraire les archives avec prévention des chemins absolus, `..`, liens et taille décompressée excessive. Pour mbox, préserver le fichier parent et enregistrer index/offset et transformations du séparateur ; le message extrait est un dérivé traçable, pas « octets SMTP originaux » prétendument inchangés.
4. Produire `normalized/emails.jsonl` et `manifest.parquet`, sans Chroma. Un seul script `build_corpus.py` avec sous-commandes inspect/normalize/dedupe/select/freeze suffit.
5. Aucun header SMTP manquant n'est rempli. Champs JSON de PhishFuzzer restent des champs de dataset, pas des observations SMTP. Marquer `has_original_attachment_bytes=false` si File n'est qu'un nom.
6. Projection vers Luna : retirer les labels de source et verdicts préexistants tels que X-Spam-Status/X-Rspamd ; conserver l'original intact en raw. Ne pas fournir filename de corpus, chemin de classe, notes gold ou source_dataset dans le prompt de classement. Les headers d'authentification restent observables avec confiance explicite.

Manifest minimum demandé conservé : sample_id, source_dataset, raw_path, original_label, normalized_label nullable, has_full_headers, has_received, has_authentication_results, has_text, has_html, has_urls, has_attachments, has_images, is_synthetic nullable, campaign_id nullable, duplicate_group, notes.

Ajouts justifiés : raw_sha256, source_url, source_record_id, input_format, header_presence, header_integrity, has_original_attachment_bytes, attachment_representation (`bytes|filename|hash|absent`), transformation_notes, public_source, label_status (`unreviewed|confirmed|ambiguous|excluded`), reviewer_ref, label_rationale, split (`candidate|rag_reference|dev|test|excluded`), family_group. Ne pas transformer un is_synthetic inconnu en false.

## 7.4 Doublons et familles avant tout split

Déduplication exacte par raw SHA-256 et par hash de corps décodé/normalisé pour comparaison uniquement. Comparaison de proximité sur un pool candidat borné, par shingles de 5 mots avec Jaccard≥0,85 ; pour textes <20 mots, égalité normalisée uniquement. La normalisation NFKC/lowercase/espaces, retrait des répétitions de séparateurs et substitution de tokens de tracking est réservée au fingerprint, jamais au contenu analysé.

Former des composantes liées par doublon exact, proximité validée, campaign_id analyste, thread ou seed connu. Pour PhishFuzzer, Original_ID réunit **seed et ses six variantes** ; ne pas grouper par simple marque ou domaine partagé. Les égalités de labels ne servent pas à former les groupes.

Chercher aussi les collisions entre corpus : IWSPA réutilise SpamAssassin/Enron/Nazario ; PhishFuzzer mentionne notamment Nazario/CEAS/SpamAssassin dans ses sources. La comparaison doit couvrir toutes les sources choisies. Une origine normalisée impossible à relier avec certitude est motif d'exclusion du test/RAG conjoint, pas de garantie de non-fuite.

## 7.5 Golden Batch : 200 souhaités, pas 200 fabriqués

Allocation indicative : phishing 50, spear_phishing 30, fraude 30, menace 20, spam 30, legitime 40. Viser un équilibre FR/EN documenté selon les données disponibles ; les sources publiques peuvent être principalement anglophones. Présenter leur couverture réelle, ne pas prétendre représenter le SOC France si elle manque.

Un analyste attribue les six labels selon le mécanisme réel. Un deuxième analyste revoit tous les cas ambigus, spear/fraude/menace et tous les désaccords. Si absence de seconde revue, documenter cette limite ; exclure les ambiguïtés non résolues. `ham`/`Valid` ne suffisent pas automatiquement à legitime ; `phishing` source ne suffit pas à distinguer nos quatre classes malveillantes.

Sélectionner les scénarios obligatoires du cadrage et noter support réel par tag. Les fixtures artificielles restent dans le harness, hors métriques Golden principales. Si menace/spear/fraude manquent, laisser le déficit visible et collecter des exemples autorisés supplémentaires. La Macro-F1 six classes est « non concluante » si une classe est absente ; ne pas produire un score flatteur sur trois classes en le nommant six classes.

Répartition par **family_group**, seed RNG 42, stratification approximative par label et tags. Aucun découpage aléatoire ligne par ligne. Environ 100 dev / 100 test ; les groupes peuvent imposer une petite différence. Minimum d'évaluation visé : 10 cas par classe et 20 legitime dans test ; sous ce support, performances exploratoires uniquement.

`gold_dev.jsonl` contient uniquement les métadonnées, références locales et labels validés du GoldRecord de docs/contracts.md §2.8, dont raw_path et raw_sha256 ; aucun contenu email, HTML, header, MIME, pièce, image ou extrait dans les notes. Le contenu, privé compris, reste dans corpus/raw/** git-ignoré. Le loader résout le chemin, charge les bytes et vérifie leur SHA-256 avant analyse ; mismatch ou champ de contenu interdit invalide la validation G6. `gold_test.jsonl` a le même schema, mais demeure chez le responsable évaluation jusqu'au gel du code. Le build voit seulement un reçu d'empreinte et les volumes agrégés. Aucun raw du holdout ni note de label sur le poste full access de build. Un hash prouve l'absence de changement, pas l'absence de lecture : les deux protections sont nécessaires.

## 7.6 RAG : uniquement une base publique distincte

**Choix initial : 150 cas publics validés**, cible 50 phishing Nazario 2025, 50 spam revus et 50 legitime revus provenant de SpamAssassin (dont hard_ham). Nombre ajustable selon revue, sans imposer un faux label pour atteindre 50. Des cas publics fraude/menace/spear identifiés réellement peuvent remplacer une partie des 50 « phishing », avec leurs vraies classes. Aucun besoin d'équilibrer artificiellement six classes dans un petit index.

Base=un fichier `corpus/rag/public_cases.jsonl`, split `rag_reference`, puis une collection Chroma embarquée. Construire les groupes sur le pool public complet, réserver les familles RAG **avant** dev/test, et confirmer que l'intersection des groupes et fingerprints est vide. Ni gold_dev ni gold_test ne sont indexés dans cette version, même s'ils sont publics ; cela simplifie la comparaison et évite les auto-voisins. Les éventuels emails privés du Golden n'entrent jamais dans cet index.

Contenu indexé : objet + corps utile + scénario, pas label ni rationale analyste dans le texte servant d'embedding. Le cas retourné contient label confirmé, justification analyste, source publique et date. Un document par email, pas de chunking multi-niveaux. Trois voisins, distance cosine, seuil initial distance≤0,40 à ajuster sur dev uniquement ; ne pas l'interpréter comme probabilité. Si aucun voisin utile : liste vide, pas un voisin forcé.

À 150 cas, demander tous les candidats à Chroma puis filtrer/exclure et trier localement suffit et évite les subtilités de filtres complexes. Un seul voisin par family_group ; exclure toute famille du message courant et tout cas non public/non confirmé. Retourner au maximum trois cas. Le système reste `add(cases)`, `search(query, exclusions, k=3)`, `clear()` ; pas de sync VT/OpenCTI ni d'apprentissage automatique après chaque verdict.

Le README Nazario décrit une collecte personnelle classée manuellement, avec erreurs possibles ; il annonce CC-BY-4.0 et distingue anciennes anonymisations des données récentes. Conserver attribution et transformations. SpamAssassin conserve les droits des auteurs des messages : sa disponibilité publique ne signifie pas libre redistribution universelle. Le POC garde les sources/liens et n'inclut pas le corpus brut dans le dépôt distribué. [Nazario](https://monkey.org/~jose/phishing/README.txt), [SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/readme.html).

La finalité est une analogie de scénario. Ne pas recopier des IOC historiques dans la liste courante, ni réutiliser le verdict ancien d'une URL comme réputation actuelle. Les images/QR ne sont pas automatiquement couverts par un index textuel. Si les voisins publics sont trop éloignés des emails SOC, G7-A conclura INCONCLUSIVE/NO au lieu d'agrandir l'infrastructure.

## 7.7 Acquisition réelle TICKET-12 (2026-09-20)

Acquisition bornée exécutée le 2026-09-20 (UTC) sur les quatre sources préférées ; les archives sont posées dans `corpus/raw/**` (git-ignoré), immuables, et l'empreinte réelle de chaque archive est consignée dans `corpus/sources.json` (URL source, date UTC, SHA-256, taille). Les comptages ci-dessous sont les observations locales du `scripts/build_corpus.py inspect` de ce ticket, méthode : présence d'en-tête avec valeur décodée **non vide** (définition §2.3), URLs comptées lexicalement dans les octets bruts pour rester comparables au tableau §7.1, comptages parser séparés.

| Source | Statut | Messages | Archive SHA-256 (12) | Taille | Acquis (UTC) | Format |
|---|---|---:|---|---:|---|---|
| SpamAssassin easy_ham | acquis | 2500 | `2b7b65904bcf` | 1 612 216 B | 2026-09-20T14:49:19Z | RFC822 (tar.bz2) |
| SpamAssassin hard_ham | acquis | 250 | `ce2ce6788064` | 1 029 898 B | 2026-09-20T14:49:19Z | RFC822 (tar.bz2) |
| SpamAssassin spam | acquis | 500 | `c08debc32413` | 1 183 768 B | 2026-09-20T14:49:19Z | RFC822 (tar.bz2) |
| Nazario phishing-2025 | acquis | 481 | `f1fa7e0fe35c` | 18 769 863 B | 2026-09-20T14:49:21Z | mbox |
| IWSPA-AP 2018 | **non acquis** | — | — | — | — | `.txt` prétraités |
| Enron CMU | non acquis (optionnel, non requis) | — | — | — | — | — |
| PhishFuzzer | non acquis (optionnel, non requis) | — | — | — | — | JSON |
| Privé autorisé | **non fourni** | — | — | — | — | — |

Total réel : **3731 messages** bruts ; 0 échec de parsing, 0 ligne perdue, 0 membre refusé. Les fichiers `cmds` expédiés par les archives SpamAssassin sont exclus des messages (`exclude_members` déclaré dans `corpus/sources.json`) ; ce sont des métadonnées d'archive, pas des emails.

Sources déclarées indisponibles (aucune fabrication) : l'archive officielle IWSPA n'a pas été obtenue (échantillons publics = PDF prétraités ; interdiction de les reconstituer en faux RFC822) ; Enron et PhishFuzzer sont optionnels et non requis pour le cœur initial ; aucun corpus privé n'a été fourni. `corpus/raw/iwspa/`, `corpus/raw/enron/`, `corpus/raw/phishfuzzer/` et `corpus/raw/private/` doivent rester absents : l'inspect refuse toute présence d'un dossier déclaré absent.

Couverture d'en-têtes mesurée sur ces acquisitions (présence avec valeur non vide ; §7.2 du 17/09 comptait la présence lexicale, d'où de rares écarts, ex. spam To 500 présents / 496 non vides) :

| Source / n | From | To | Subject | Date | Message-ID | Received | Return-Path | Auth-Results | DKIM |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| easy_ham / 2500 | 2500 | 2348 | 2500 | 2500 | 2500 | 2365 | 2500 | 0 | 0 |
| hard_ham / 250 | 250 | 250 | 249 | 250 | 250 | 250 | 241 | 0 | 0 |
| spam / 500 | 500 | 496 | 498 | 500 | 500 | 500 | 494 | 0 | 0 |
| Nazario 2025 / 481 | 481 | 471 | 480 | 478 | 476 | 481 | 481 | 481 | 401 |

Comptages parser (nouveaux, basés sur `src.parsing`, complémentaires des définitions lexicales §7.1) : messages avec URLs extraites par le parser = easy_ham 2005, hard_ham 241, spam 444, Nazario 445 ; messages avec HTML = 8/165/257/470 ; pièces attachées avec octets décodés = 17/3/9/52 messages ; images MIME = 0/2/1/35 messages. Présence lexicale d'URL dans les octets bruts : 3016/481 identique au tableau §7.1 (même méthode).

Sorties du ticket : `corpus/normalized/emails.jsonl` (3731 lignes, métadonnées seulement — le texte reste dans raw), `corpus/manifest.parquet` (3731 lignes × 35 colonnes : minimum §7.3 + ajouts justifiés, dont `raw_sha256`, `header_presence`, `header_integrity`, `attachment_representation`, `has_original_attachment_bytes`, `body_sha256` comparatif, `split='candidate'`), `corpus/review/labels_template.jsonl` (3731 lignes `label_status='unreviewed'`, `normalized_label=null`, aucun faux label prérempli), rapports `runs/corpus/{inspection,normalize,dedupe}.json`.

Déduplication (`dedupe --seed 42`, bornée) : 80 groupes de doublons exacts (>1 membre, par raw SHA-256 ou empreinte de corps normalisée), 145 familles à membres multiples (plus grande = 12), 439 liens de proximité Jaccard ≥ 0,85 sur shingles de 5 mots (0 faillite de borne : 0 dépassement du pool candidat), **0 famille intersource** SA↔Nazario observée, 5 messages sans texte d'empreinte conservés via leurs groupes de hash exacts. `duplicate_group`/`family_group` sont écrits dans le manifest ; les labels source restent intacts, `normalized_label` reste null — la revue humaine (TICKET-13) fait la suite.

Conventions de référence (`raw_path`) : `<archive>!<membre>` pour les tar (membre lu en place, jamais extrait), `<mbox>!<ordinal 1-based sur 4 chiffres>` pour le mbox (lignes séparatrices `From ` exclues — dérivé documenté, cf. §7.3). `raw_sha256` couvre toujours les octets exacts du message référencé ; pour un membre mbox, c'est le message RFC822 sans la ligne séparatrice. `input_format` : `rfc822` (SpamAssassin), `mbox_member` (Nazario) ; `structured_public_text` reste réservé aux fichiers JSON sans RFC822 (PhishFuzzer), non acquis ici — aucune donnée n'est inventée pour l'exercer. `header_integrity` décrit la chaîne locale : `original` (membre tar conservé tel quel), `transformed` (flux mbox dérivé du conteneur), `unknown` (JSON sans SMTP) ; les transformations documentées par les auteurs des corpus figurent dans `transformation_notes`, jamais comme un nettoyage de notre part. `attachment_representation` : `bytes` (octets décodés présents), `filename` (nom seul — cas PhishFuzzer, unit-testé sans données réelles), `hash`, `absent`.
