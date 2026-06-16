La cybersécurité est devenue un enjeu majeur pour les entreprises et les organisations du monde entier face à la multiplication des attaques informatiques. Les vulnérabilités logicielles et matérielles constituent une porte d’entrée privilégiée pour les attaquants, rendant impératif leur identification rapide et leur correction efficace.

En France, l’Agence Nationale de la Sécurité des Systèmes d’Information (ANSSI) joue un rôle central dans la veille et la diffusion d’informations sur les menaces. Elle publie régulièrement des bulletins de sécurité (CERT-FR – Centre gouvernemental de veille, d’alerte et de réponse aux attaques informatiques) visant à informer les entreprises et les particuliers sur les vulnérabilités existantes et les risques associés. Les principaux types de bulletins émis sont de trois natures :

Les avis de sécurité : Ils signalent des vulnérabilités connues et fournissent des recommandations concrètes pour les corriger ou atténuer leurs effets. Ils permettent aux organisations d’agir préventivement pour sécuriser leurs systèmes.

Les alertes : Elles concernent des vulnérabilités critiques qui sont activement exploitées par des acteurs malveillants. Ces vulnérabilités nécessitent une intervention urgente pour éviter d’éventuelles compromissions de sécurité.

Ces bulletins contiennent des identifiants CVE (Common Vulnerabilities and Exposures) qui permettent de référencer précisément chaque vulnérabilité.

Contrairement à son homologue américain, le NIST (National Institute of Standards and Technology) qui propose une API dédiée et complète (NVD API) permettant de collecter et d’analyser facilement ces informations, il est plus difficile d’automatiser le traitement des flux publiés par l’ANSSI. En effet, l’ANSSI ne fournit actuellement à disposition un flux RSS relativement sommaire (ANSSI RSS Feed) destiné aux entreprises et aux particuliers. Les informations détaillées nécessitent de naviguer dans le DOM de pages web ou directement le JSON mentionnés dans ces flux pour être extraites et exploitées.

De plus, contrairement au NIST qui offre des fonctionnalités avancées, telles que des interprétations statistiques automatisées ou des systèmes d’alertes personnalisés, l’ANSSI ne permet pas, dans son format actuel, de générer des statistiques avancées ni des alertes sur mesure en fonction des besoins spécifiques des utilisateurs. Ce manque d’automatisation et de flexibilité justifie pleinement la réalisation d’un outil capable de traiter, d’enrichir et d’analyser ces données pour en tirer des conclusions exploitables.

- Extraire les données des flux RSS des avis et alertes ANSSI.
- Identifier les CVE mentionnées dans les bulletins.
- Enrichir les CVE avec des informations complémentaires via des API externes.
- Consolider les données dans un format exploitable (DataFrame pandas).
- Analyser et visualiser le DataFrame obtenu (vulnérabilités critiques, scores...)
- Modèles Machine learning
- Générer des alertes personnalisées pour les produits affectés et envoyer des
notifications par email.

# Pour exécuter les scripts, vous devez disposer d'un environnement Python (3.9+) et installer les dépendances nécessaires :

# Installation des bibliothèques via pip
pip install feedparser requests pandas numpy matplotlib
Note : Assurez-vous d'avoir accès à Internet pour la récupération des flux RSS et les appels aux API externes.

# Configuration (Gestion des secrets)
Le projet utilise un fichier .env pour la gestion sécurisée des identifiants (ex: configuration SMTP pour les alertes email).

Créez un fichier nommé .env à la racine de votre dossier.

Ajoutez vos variables de configuration sur le modèle suivant :
email_sender=votre_email@gmail.com
email_password=votre_mot_de_passe_application
Attention : Ce fichier .env ne doit jamais être inclus dans votre dépôt public ou partagé.

# Comment lancer l'application
Extraction et enrichissement : Exécutez le script principal (ou les cellules correspondantes dans le notebook si vous utilisez une version scriptée).

Consolidation : Le script génère automatiquement un fichier cve_consolidated.csv contenant l'ensemble des données traitées.

Analyse : Lancez les scripts de visualisation pour générer les graphiques de performance et de distribution des vulnérabilités.

# Points de vigilance
Temps d'exécution : L'étape d'enrichissement des données (appel aux API MITRE/EPSS) peut être longue (environ 15 minutes). Un fichier cve_info.json est utilisé comme cache pour éviter de refaire ces appels à chaque exécution.

Limitation d'API : Si vous effectuez de nombreux tests, respectez un délai (time.sleep) entre les requêtes pour ne pas être bloqué par les serveurs externes.

Format des données : Le script effectue un nettoyage des données (replace('na', np.nan)). Vérifiez toujours la cohérence du DataFrame final avant l'étape de Machine Learning.
