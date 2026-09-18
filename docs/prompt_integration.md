# 3. Prompts complets et intégration

Les fichiers `prompts/internal_assessment.txt` et `prompts/final_assessment.txt` contiennent chacun un message système autonome complet. Ils sont normatifs ; ne pas réintroduire le prompt historique de navigation. La première phase utilise medium, la seconde xhigh.

Le message utilisateur est un JSON sérialisé par le code, sans interpolation de données dans le message système. Enveloppe internal : `UNTRUSTED_EMAIL`, `EVIDENCE_REGISTRY`, `OBSERVABLE_REGISTRY`, `SUPPLIED_VISUAL_IDS`. Enveloppe final : mêmes champs + `INTERNAL_ASSESSMENT`, `TOOL_STATUS`, `RAG_CONTEXT`. Seuls les champs métier utiles de ParsedEmail sont inclus ; aucun chemin révélant le label du corpus, aucune note analyste de gold, aucun nom de fixture, aucune clé de configuration/secrète.

Les prompts système livrés sont inchangés en V1.2. L'audit par tentative de docs/contracts.md §2.6.1 porte sur les enveloppes INTERNAL et FINAL effectivement envoyées ; l'audit ne fait pas partie des prompts et ne change ni leurs champs ni le schema Assessment.

Le modèle doit lire les valeurs exactes à analyser. La séparation de rôle n'est pas une garantie mathématique contre la prompt injection : absence d'outils, sorties restreintes à des références, validation et policy limitent ses conséquences. Les tests live mesureront aussi les erreurs de classification causées par l'injection.

En vision, le user message est une liste de parties content : le JSON d'abord, puis blocs image identifiés avec `image_url` en data URI préparée par le harness. Aucune URL distante donnée au modèle comme image. Sur rejet du proxy, marquer `vision_unavailable`, reprendre le mode texte de manière explicite et faire REVIEW si l'image est essentielle. Pas de second modèle/pipeline.

Budget contexte : garder toutes les preuves sélectionnées nécessaires aux IDs référencés, jusqu'à 24 000 caractères de body utile, 8 000 de headers sélectionnés, 16 000 d'URLs/observables et 24 000 de preuves/outils ; maximum 100 000 caractères de payload texte hors système. Toute troncature est mesurée et signalée ; aucune preuve tronquée ne reste référençable. RAG : 3 cas × 1 200 caractères maximum. Les limites de tableaux (6 inférences, 3 preuves décisives) sont contrôlées localement même si le proxy n'accepte pas tous les mots-clés de longueur dans le schema strict.

Le modèle ne produit pas le rapport final : le harness ajoute run_id, hashes, statuts, timers, métriques, verdict/confidence calculés, faits rendus et décision de policy. Les deux contrats JSON complets sont livrés dans schemas/. Ils seront testés avec le proxy réel en G0, puis avec le contenu métier réel en G2.
