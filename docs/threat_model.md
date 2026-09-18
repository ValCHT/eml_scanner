# Threat model du POC

Périmètre : protection des données et intégrité du triage, pas défense complète d'une plateforme SOC en production.

| Entrée / frontière | Risque concret | Contrôle retenu | Risque restant / validation |
|---|---|---|---|
| `.eml`, HTML, en-têtes | Injection d'instructions et faux résultats d'auth | Données séparées du système, aucun outil LLM, auth trust explicite | Mauvaise classification encore possible : fixtures et gold |
| Pièces et images | Exécution, chemin traversant, volume/décodage excessif | Hashing sans exécution, noms basés sur hashes, limites MIME/pixels | Bibliothèques à maintenir ; pas d'affirmation « fichier sain » |
| URL fournie | Divulgation de token, activation de tracking, hôte interne | Filtre d'egress, approbation de sources, private, aucun fetch direct | Private protège la visibilité, pas la transmission au fournisseur |
| API fournisseurs | Résultat absent, format changé, données hostiles, fausse indépendance | Contrats typés, bornes, source_ref, date, statut, source_group | Fiabilité de la source n'est pas prouvée par le schema |
| Sortie Luna | IOC inventé, faux fait externe, excès de confiance | Références au registre, vérification V01–V16, policy déterministe | Erreurs de jugement sémantique mesurées humainement |
| RAG | Instruction cachée, mauvais label, copie d'un IOC historique | Public seulement, labels revus, contexte d'analogie, aucun write-back automatique | Corpus publics peuvent contenir erreurs et décalage de domaine |
| Évaluation | Fuite de test ou famille/seed, verdict antispam visible | Groupes avant split, test hors build, retrait de verdicts antispam du payload | Contamination pré-entraînement des corpus publics non exclue |
| Codex full access | Lecture de holdout/secrets, scripts externes exécutés | Holdout absent du poste, secrets hors prompts/logs, scope de ticket, sources données seulement | Instructions seules ne constituent pas une isolation système |

Règle de sortie : AUTO/REVIEW/ESCALATE sont des recommandations. Ce POC n'envoie aucun message, ne supprime aucun email et n'ajoute aucun blocage réseau. Les documents, logs d'erreurs et résumés restent des rendus inertes.
