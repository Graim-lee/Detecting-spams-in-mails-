# %% [markdown]
# # **Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE**

# %% [markdown]
# **Ce projet utilise un fichier .env local pour la gestion sécurisée des secrets, non inclus dans ce dépôt.**

# %% [markdown]
# ## Contexte et objectifs

# %% [markdown]
# La cybersécurité est devenue un enjeu majeur pour les entreprises et les organisations du monde entier face à la multiplication des attaques informatiques. Les vulnérabilités logicielles et matérielles constituent une porte d’entrée privilégiée pour les attaquants, rendant impératif leur identification rapide et leur correction efficace.
# 
# En France, l’Agence Nationale de la Sécurité des Systèmes d’Information (ANSSI) joue un rôle central dans la veille et la diffusion d’informations sur les menaces. Elle publie régulièrement des bulletins de sécurité (CERT-FR – Centre gouvernemental de veille, d’alerte et de réponse aux attaques informatiques) visant à informer les entreprises et les particuliers sur les vulnérabilités existantes et les risques associés. Les principaux types de bulletins émis sont de trois natures :
# 
# Les avis de sécurité : Ils signalent des vulnérabilités connues et fournissent des recommandations concrètes pour les corriger ou atténuer leurs effets. Ils permettent aux organisations d’agir préventivement pour sécuriser leurs systèmes.
# 
# Les alertes : Elles concernent des vulnérabilités critiques qui sont activement exploitées par des acteurs malveillants. Ces vulnérabilités nécessitent une intervention urgente pour éviter d’éventuelles compromissions de sécurité.
# 
# Ces bulletins contiennent des identifiants CVE (Common Vulnerabilities and Exposures) qui permettent de référencer précisément chaque vulnérabilité.
# 
# Contrairement à son homologue américain, le NIST (National Institute of Standards and Technology) qui propose une API dédiée et complète (NVD API) permettant de collecter et d’analyser facilement ces informations, il est plus difficile d’automatiser le traitement des flux publiés par l’ANSSI. En effet, l’ANSSI ne fournit actuellement à disposition un flux RSS relativement sommaire (ANSSI RSS Feed) destiné aux entreprises et aux particuliers. Les informations détaillées nécessitent de naviguer dans le DOM de pages web ou directement le JSON mentionnés dans ces flux pour être extraites et exploitées.
# 
# De plus, contrairement au NIST qui offre des fonctionnalités avancées, telles que des interprétations statistiques automatisées ou des systèmes d’alertes personnalisés, l’ANSSI ne permet pas, dans son format actuel, de générer des statistiques avancées ni des alertes sur mesure en fonction des besoins spécifiques des utilisateurs. Ce manque d’automatisation et de flexibilité justifie pleinement la réalisation d’un outil capable de traiter, d’enrichir et d’analyser ces données pour en tirer des conclusions exploitables.
# 
# - Extraire les données des flux RSS des avis et alertes ANSSI.
# - Identifier les CVE mentionnées dans les bulletins.
# - Enrichir les CVE avec des informations complémentaires via des API externes.
# - Consolider les données dans un format exploitable (DataFrame pandas).
# - Analyser et visualiser le DataFrame obtenu (vulnérabilités critiques, scores...)
# - Modèles Machine learning
# - Générer des alertes personnalisées pour les produits affectés et envoyer des
# notifications par email.

# %% [markdown]
# # **Étape 1 : Extraction des Flux RSS**

# %% [markdown]
# Récupération des avis et des alertes grâce à feedparser et les urls suivants:
# - "https://www.cert.ssi.gouv.fr/alerte/feed/"
# - "https://www.cert.ssi.gouv.fr/avis/feed/"
# 
# Nous stockons ensuite toutes les entrées grâce à `feedparser.parse`.

# %%
import feedparser

# Récupération des alertes (menaces immédiates, majeures et hautement critiques)

url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed/"
rss_alerte_feed = feedparser.parse(url_alerte)
for entry in rss_alerte_feed.entries:
    print("Titre :", entry.title)
    print("Description:", entry.description)
    print("Lien :", entry.link)
    print("Date :", entry.published)

# Récupération des avis (vulnérabilités courantes)

url_avis = "https://www.cert.ssi.gouv.fr/avis/feed/"
rss_avis_feed = feedparser.parse(url_avis)
for entry in rss_avis_feed.entries:
    print("Titre :", entry.title)
    print("Description:", entry.description)
    print("Lien :", entry.link)
    print("Date :", entry.published)


# %% [markdown]
# # **Étape 2 : Extraction des CVE**

# %% [markdown]
# Après voir récupéré tous nos avis / alertes, nous devons en extraire les CVE.
# 
# Cette partie consiste uniquement à créer la fondation pour notre futur dataframe.
# Nous stockons donc une liste de dictionnaire avec différentes infos pour chaque CVE.
# Etant donné qu'un bulletin peut avoir une dizaine voir une centaine de CVE, nous faisons un ligne par CVE au lieu d'avoir une liste de CVE pour chaque bulletin.

# %%
import requests
import re
import time

list_cve = [] # Liste de dictionnaire pour le dataframe

cve_list_avis = [] # CVE extraits des avis

# Enregistrement des CVE extraits des avis
for entry in rss_avis_feed.entries:

    # Récupération de l'identifiant du bulletin (contient plusieurs avis)
    link_array = entry.link.split("/")
    # example split :
    #['https:', '', 'www.cert.ssi.gouv.fr', 'avis', 'CERTFR-2026-AVI-0701', '']
    bulletin_name = link_array[4]

    # Récupération des infos JSON liées au bulletin
    url = "https://www.cert.ssi.gouv.fr/avis/" + bulletin_name +"/json/"
    response = requests.get(url)
    data = response.json()

    # Parcours et enregistrement des CVE et leurs informations mentionnées dans les données
    for cve_item in data.get("cves", []):

        cve_id = cve_item.get("name")

        cve_data = {
            "ID ANSSI": bulletin_name,
            "Titre ANSSI": data.get("title"),
            "Type": "Avis",
            "Date": data.get('revisions')[0]['revision_date'],
            "CVE": cve_id,
            "CVSS": None,
            "Base Severity": None,
            "CWE": None,
            "EPSS": None,
            "Lien": cve_item.get("url"),
            "Description": None,
            "Editeur": None,
            "Produit": None,
            "Versions affectées": None
        }

        list_cve.append(cve_data)
        # time.sleep(1) # Délai pour éviter une surcharge de requêtes

    # Extraction des CVE referencés dans la clé cves du dict data
    ref_cves=list(data["cves"])

    # Extraction des CVE avec une regex
    cve_pattern = (r"CVE-\d{4}-\d{4,7}")
    cve_list_avis.append(list(set(re.findall(cve_pattern, str(data)))))

# Enregistrement des CVE extraits des alertes
cve_list_alert = []

for entry in rss_alerte_feed.entries:

    # Récupération de l'identifiant du bulletin (contient plusieurs alertes)
    link_array = entry.link.split("/")
    # example split :
    #['https:', '', 'www.cert.ssi.gouv.fr', 'avis', 'CERTFR-2026-AVI-0701', '']
    # Récupération de l'identifiant du bulletin (contient plusieurs alertes)
    bulletin_name = link_array[4]
    url = "https://www.cert.ssi.gouv.fr/alerte/" + bulletin_name +"/json/"

    # Récupération des infos JSON liées au bulletin
    response = requests.get(url)
    data = response.json()

    # Parcours et enregistrement des CVE et leurs informations mentionnées dans les données
    for cve_item in data.get("cves", []):

        cve_id = cve_item.get("name")

        cve_data = {
            "ID ANSSI": data.get("reference"),
            "Titre ANSSI": data.get("title"),
            "Type": "Alerte",
            "Date": data.get('revisions')[0]['revision_date'],
            "CVE": cve_id,
            "CVSS": None,
            "Base Severity": None,
            "CWE": None,
            "EPSS": None,
            "Lien": cve_item.get("url"),
            "Description": None,
            "Editeur": None,
            "Produit": None,
            "Versions affectées": None
        }
        list_cve.append(cve_data)
        # time.sleep(1) # Délai pour éviter une surcharge de requêtes

    #Extraction des CVE referencés dans la clé cves du dict data
    ref_cves=list(data["cves"])

    # Extraction des CVE avec une regex
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_list_alert.append(list(set(re.findall(cve_pattern, str(data)))))

print(*list_cve)

# %%
print("CVE trouvés alerte:",cve_list_alert)
print("CVE trouvés avis",cve_list_avis)

alert_size = sum([len(cve_list) for cve_list in cve_list_alert])
avis_size = sum([len(cve_list) for cve_list in cve_list_avis])

# %%
print("Tailles des alertes :", alert_size)
print("Tailles des avis :", avis_size)

# calcul ratio alerte avis
print(max(avis_size, alert_size)/min(avis_size,alert_size))

# %% [markdown]
# On remarque qu'il y'a bien plus de CVE avis qu'alertes (17x plus). C'est un point important à retenir pour nos futurs modèles de Machine Learning.

# %%
import itertools

# Transforme la suite de listes imbriquées en liste simple
list_cve_id = list(itertools.chain.from_iterable(cve_list_alert)) + list(itertools.chain.from_iterable(cve_list_avis))
print(list_cve_id)

# %% [markdown]
# On récupère tous les noms de CVE afin de pouvoir plus facilement naviguer à travers notre dictionnaire. Cependant plusieurs CVE peuvent se répéter. Il est donc inutile de les garder car elles ont exactement la même description. Pour éviter du calcul inutile en plus, nous décidons de convertir la `list` en `set` puis la faire revenir en `list`.

# %%
# Nombres d'éléments vs. nombre d'éléments uniques
print(len(list_cve_id))
print(len(set(list_cve_id)))

# %%
# Suppression des duplicats
list_cve_id = list(set(list_cve_id))
print(len(list_cve_id))

# %% [markdown]
# Notre logique fut bonne car on se retrouve avec 45 duplicates que l'on supprime.

# %% [markdown]
# # **Étape 3 : Enrichissement des CVE**

# %% [markdown]
# <div class="alert alert-block alert-danger">
# <b>ATTENTION:</b> Cette cellule met 15 min à terminer. Elle crée un dictionnaire utilisé après.
# Ce dictionnaire est déjà présent dans le fichier 'cve_info.json' et ensuite save dans 'cve_consolidated.csv'.
# Vous pouvez regarder les cellules suivantes pour le charger
# </div>

# %% [markdown]
# Appel de l'API MITRE pour récupérer le `CVSS`, la `description`, les `versions affectés`, `l'éditeur` et le `CWE`.

# %%

def cellule_not_to_lauch(cve_list):
    cve_info = {}
    for cve_id in cve_list:
        cve_info[cve_id] = {}
        url = (f"https://cveawg.mitre.org/api/cve/{cve_id}")
        response = requests.get(url)
        data = response.json()
        cvss_score = "na"

        # Extraire la description
        try:
            description = data["containers"]["cna"]["descriptions"][0]["value"]
        except:
            description = "na"
            cve_info[cve_id]['cvss_score'] = cvss_score
            cve_info[cve_id]['cwe'] = "na"
            cve_info[cve_id]['products'] = []
            cve_info[cve_id]['description'] = description
            continue

        # Extraire le score CVSS
        # ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l'exception,
        # ou peut etre au lieu de cvssV3_0 c'est cvssV3_1 ou autre clé
        key = None
        try:
            if list(data["containers"]["cna"]["metrics"][0].keys())[0] == 'format':
                key = list(data["containers"]["cna"]["metrics"][0].keys())[2]
            else:
                key = list(data["containers"]["cna"]["metrics"][0].keys())[0]
        except:
            pass
            # print("no metrics")

        try:
            cvss_score = data["containers"]["cna"]["metrics"][0][key]["baseScore"]
        except Exception:
            pass
            # print("not found")

        cwe = "na"
        cwe_desc = "na"
        try:
            problemtype = data["containers"]["cna"].get("problemTypes", {})
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "na")
                cwe_desc = problemtype[0]["descriptions"][0].get("description", "na")
        except:
            pass

        # Extraire tous les produits affectés
        # -> liste de dicts {vendor, product, versions}
        products = []
        try:
            affected = data["containers"]["cna"]["affected"]
            for product in affected:
                try:
                    vendor = product["vendor"]
                    product_name = product["product"]
                    versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                    products.append({"vendor": vendor, "product": product_name, "versions": versions})
                except:
                    print(f"version error {cve_id}")
        except:
            pass

        cve_info[cve_id]['cvss_score'] = cvss_score
        cve_info[cve_id]['cwe'] = cwe
        # On garde la liste complète des produits affectés
        cve_info[cve_id]['products'] = products
        cve_info[cve_id]['description'] = description

    return cve_info


"""
Ne pas lancer sauf si c'est vraiment nécessaire
"""
cve_info = cellule_not_to_lauch(list_cve_id)

# %%
cve_info

# %%
cve_info_copy = cve_info.copy()

# %%
import json

def save_dict_to_json(data_dic, filename):
    """Sauvegarde le dictionnaire dans un fichier JSON"""
    with open(filename, 'w', encoding='utf-8') as f:
        # indent=4 makes the JSON file human-readable
        json.dump(data_dic, f, indent=4, ensure_ascii=False)
    print(f"Data successfully saved to {filename}")

def load_json_to_dict(filename):
    """Charge le fichier JSON dans un dictionnaire"""
    with open(filename, 'r', encoding='utf-8') as f:
        return json.load(f)

# %% [markdown]
# Une fois que l'on a save nos données, on les extrait vers un `json`

# %%
# Sauvegarde nos données dans un JSON pour ne pas avoir a éxécuter de nouveau la cellule chronophage
save_dict_to_json(cve_info, "cve_info.json")

# %%
# Récupère cve_info depuis le fichier JSON
cve_info = load_json_to_dict("cve_info.json")

# %%
print(cve_info['CVE-2026-22977'])

# %%
print(list_cve[0])

# %% [markdown]
# Appel de l'API EPSS pour récupérer les infos pour chaque CVE.
# 
# On récupère uniquement le **score EPSS**

# %%
for cve in list_cve:
    cve_id = cve['CVE']
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    # Requête GET pour récupérer les données JSON
    response = requests.get(url)
    data = response.json()

    # Extraire le score EPSS
    epss_data = data.get("data", [])
    if epss_data:
        epss_score = epss_data[0]["epss"]
        print(f"CVE : {cve_id}")
        print(f"Score EPSS : {epss_score}")
        cve['EPSS'] = epss_score
    else:
        print(f"Aucun score EPSS trouvé pour {cve_id}")

# %%
# Enrichissement de list_cve avec les infos de cve_info (CVSS, CWE, description, éditeur/produit/versions)
for element in list_cve:
    cve_id = element['CVE']
    try:
        info = cve_info[cve_id]
        element['CVSS'] = info['cvss_score']
        element['CWE'] = info['cwe']
        element['Description'] = info['description']

        # Enregistre les produits s'ils sont mentionnés
        products = info.get('products', [])
        if products:
            element['Editeur'] = products[0]['vendor']
            element['Produit'] = products[0]['product']
            element['Versions affectées'] = products[0]['versions']
        else:
            element['Editeur'] = None
            element['Produit'] = None
            element['Versions affectées'] = []
    except Exception:
        print(f'{cve_id} not in the database')

# %% [markdown]
# # **Étape 4: Consolidation des données**

# %% [markdown]
# Notre but est maintenant de consolider nos données notamment en donnant des noms en fonction du score CVSS.

# %%
import pandas as pd
import numpy as np

#
df = pd.DataFrame.from_dict(list_cve)
df = df.replace('na', np.nan)

df['EPSS'] = df['EPSS'].astype(float)
df['CVSS'] = df['CVSS'].astype(float)
df['Date'] = pd.to_datetime(df['Date'])
df

# %%
def cvss_to_severity(score):
    if pd.isna(score):
        return np.nan
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"

df["Base Severity"] = df["CVSS"].apply(cvss_to_severity)
df

# %% [markdown]
# Certaines lignes ont un score CVSS mais d'autres noms. Quand ce n'est pas le cas, on prend le dernier mot des descriptions et on attribue un score en fonction du mot. 
# 
# Après analyse, beaucoup de CVE possèdent une ligne correspondant à la Severity dans la description.

# %%
#Récupération des "base severity" et conversion entre score CVSS et base severity

# Si la base severity pas là alors CVSS aussi
getBaseSeverity = {"Critical": 9.5, "High": 8, "Medium": 5.5, "Low": 2}

# Récupère le dernier mot de la description (c'est le seul endroit où la base severity est mentionnée)
lastWord = df["Description"].str.split(" ").str[-1].str[:-1]
fallback_severity = lastWord.map(getBaseSeverity)

# Appplique les scores CVSS et base severity sur le dataframe
mask = df["Base Severity"].isna()
df.loc[mask, "Base Severity"] = fallback_severity[mask].map({9.5:"Critical", 8:"High", 5.5:"Medium", 2:"Low"})
df.loc[mask, "CVSS"] = df.loc[mask, "CVSS"].fillna(fallback_severity[mask])

# %% [markdown]
# On analyse notre dataframe après cette update

# %%
df.describe()

# %%
df.isnull().sum()

# %% [markdown]
# On convertit les listes des versions affectées en simplement un string pour éviter les problèmes d'index plus tard.

# %%
# On applique le .join ligne par ligne sur la colonne (uniquement si ce sont des listes)
df["Versions affectées"] = df["Versions affectées"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)

df

# %% [markdown]
# # Export des données consolidées (CSV)

# %% [markdown]
# On exporte ces données vers un CSV pour éviter d'avoir à réappeler les API.

# %%
df.to_csv("cve_consolidated.csv", index=False)
print(f"Export ok : cve_consolidated.csv ({len(df)} lignes, {len(df.columns)} colonnes)")

# %%
import pandas as pd
import numpy as np

# Lecture depuis le csv
df = pd.read_csv('cve_consolidated.csv')
df['Date'] = pd.to_datetime(df['Date'])
df

# %% [markdown]
# # **Étape 5: Interprétation et visualisation**

# %%
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt

# %%
"""
Histogramme des scores CVSS :

Distribution des vulnérabilités selon leur niveau de gravité (critique, élevée, moyenne)
"""

n, bins, patches = plt.hist(df["CVSS"], bins = 30)

# Change la couleur des barres selon leur danger
for patch in patches:
    value = patch.get_x()
    if value < 4: patch.set_facecolor('green')
    elif value < 7: patch.set_facecolor('yellow')
    elif value < 9: patch.set_facecolor('orange')
    else: patch.set_facecolor('red')

# Légende personnalisée
green_patch = mpatches.Patch(color='green', label='Vulnérabilité faible')
yellow_patch = mpatches.Patch(color='yellow', label='Vulnérabilité moyenne')
orange_patch = mpatches.Patch(color='orange', label='Vulnérabilité élevé')
red_patch = mpatches.Patch(color='red', label='Vulnérabilité critique')

plt.title("Histogramme des scores CVSS et leurs distributions")
plt.xlabel("CVSS score")
plt.ylabel("Nb de vulnérabilités")
plt.legend(handles=[green_patch, yellow_patch, orange_patch, red_patch])
plt.xticks(np.arange(0, 11, 1))
plt.yticks(np.arange(0, 250, 20))
plt.grid(True, alpha=0.1)

plt.show()

# %% [markdown]
# On peut voir que la majorité des vulnérabilités sont d'une gravité élevée, ce qui montre l'importance de ce genre de projet et l'attention que l'on doit porter à la cybersécurité et aux alertes/avis.
# 

# %%
"""
Diagramme circulaire des types de vulnérabilités (CWE) rencontrées
"""

countsANSSI = df["Titre ANSSI"].value_counts()

labelsANSSI = countsANSSI.index.tolist()
sizesANSSI = countsANSSI.values.tolist()

# Masque le nom des elements trop peu nombreux
for i in range(len(labelsANSSI)):
    if sizesANSSI[i] < 50:
            labelsANSSI[i] = ""

plt.pie(sizesANSSI, labels=labelsANSSI)
plt.title("Type des vulnérabilités rencontrées")

plt.show()

# %%
"""
Diagramme circulaire des editeurs affectés par des vulnérabilités
"""

countsEditeur = df["Editeur"].value_counts()

labelsEditeur = countsEditeur.index.tolist()
sizesEditeur = countsEditeur.values.tolist()

for i in range(len(labelsEditeur)):
    if sizesEditeur[i] < 50:
        labelsEditeur[i] = ""

plt.pie(sizesEditeur, labels=labelsEditeur)
plt.title("Editeurs affectés par des vulnérabilités")
plt.show()

# %%
"""
Diagramme circulaire des Produit affectés par des vulnérabilités
"""

countsProduit = df["Produit"].value_counts()

labelsProduit = countsProduit.index.tolist()
sizesProduit = countsProduit.values.tolist()

for i in range(len(labelsProduit)):
    if sizesProduit[i] < 50:
        labelsProduit[i] = ""

plt.pie(sizesProduit, labels=labelsProduit)
plt.title("Produits affectés par des vulnérabilités")

plt.show()

# %%
"""
Courbe cumulative des vulnérabilités en fonction du temps
"""


countsDate = df["Date"].dt.year.value_counts().sort_index()

labelsDate = countsDate.index.tolist()
sizesDate = np.cumsum(countsDate.values.tolist())

plt.plot(labelsDate, sizesDate, "ob-")
plt.xticks(np.arange(min(labelsDate), max(labelsDate)+1, 1))
plt.title("Courbe cumulative des vulnérabilités")

plt.show()

# %% [markdown]
# Les majorités sont récentes (2026), ce qui est d'autant plus d'actualité avec le récent cas de l'IA Mythos qui a decelé des miliers de failles.
# 

# %%
"""
Moyenne des scores CVSS pour un éditeur
"""

counts = df.groupby(['Editeur']).CVSS.mean()
plt.subplots(figsize=(15, 6))
plt.bar(counts.index, counts.values)
plt.tick_params('x', rotation=90)
plt.xlabel("Editeurs")
plt.ylabel('Moyenne de leurs CVSS')
plt.title('Moyenne des scores CVSS par éditeur')
plt.show()

# %%
"""
Nombre d'alertes par éditeur
"""

counts = df.Editeur[df["ID ANSSI"].str.contains('ALE')].value_counts()

plt.subplots(figsize=(15, 6))
plt.bar(counts.index, counts.values)
plt.tick_params('x', rotation=70)
plt.title("Nombre d'alertes par éditeur")
plt.show()

# %%
"""
Nombre d'avis par éditeur
"""

counts = df.Editeur[df["ID ANSSI"].str.contains('AVI')].value_counts()

plt.subplots(figsize=(15, 6))
plt.bar(counts.index, counts.values)

plt.tick_params('x', rotation=90)
plt.title("Nombre d'avis par éditeur")
plt.show()

# %% [markdown]
# # **Étape 6: Modèles Machine Learning**

# %% [markdown]
# ## Modèle non-supervisé

# %% [markdown]
# Le but de ce modèle va être de prédire un titre pour un nouvel élément donnée qui n'aurait pas de titre
# 

# %%
# rappel du dataframe
df

# %% [markdown]
# Installation des packages nécessaires

# %%
# %pip install sklearn sentence_transformers matplotlib

# %% [markdown]
# Premièrement, on va enlever les quelques colonnes non nécéssaires. On n'a pas besoin de:
# - l'ID
# - Les dates (les dates ne sont que du bruit, on ne veut pas que les clusters soient biaisé par les dates)
# - La base severity qui est en vérité le score CVSS
# - Les liens
# - Les versions

# %%
df_dropped_useless = df.drop(['ID ANSSI', 'Date', 'Base Severity', 'Lien', 'Versions affectées'], axis = 1)
df_dropped_useless

# %%
df_dropped_useless.info()

# %% [markdown]
# On remarque des valeurs null dans le tableau, sachant qu'elle sont plutôt aléatoires, on va juste enlever les lignes ayant des valeurs null

# %%
df_dropped_useless = df_dropped_useless.dropna()

# %% [markdown]
# Nous allons séparer train et test pour tester l'efficacité de notre model plus tard
# 

# %%
from sklearn.model_selection import train_test_split

X_train, X_test= train_test_split(df_dropped_useless, test_size=0.33, random_state=42)

# %%
X_train

# %%
X_test

# %% [markdown]
# Dans le futur, nous aurons une ligne sans titre et le but sera de le deviner, nous allons donc enlever les titres pour les garder de côté

# %%
titles = X_train['Titre ANSSI']
X_train.drop(['Titre ANSSI'], axis=1, inplace=True)

# %% [markdown]
# Nous allons donc maintenant encoder les différents strings
# 
# Nous effectuons un one hot encoding pour type, CVE, CWE, Editeur et produit
# 
# Nous ne pouvons faire un encodage simple pour 'description'. Nous utilisons un sentenceTransformer car il s'agit d'un texte qui peut être long. Le sentenceTransformer va nous donner une matrice où chaque ligne représente une description et chaque colonne représente le score de la description selon une caractéristique précise. C'est similaire à un TF-IDF en plus avancé

# %%
# OneHotEncoding de type, CV, CWE, Editeur et produit
from sklearn.preprocessing import OneHotEncoder

encoder = OneHotEncoder(handle_unknown='ignore')
column_to_encode = ['Type', 'CVE', 'CWE', 'Editeur', 'Produit']
encoded_data = encoder.fit_transform(X_train[column_to_encode])

#Récupération d'un dataframe pour pouvoir merge après
#'index' précise de garder les indices de X_train car sinon ils sont réinitialisé et cela pose de grands project.ipynb problèmes
encoded_df_no_description = pd.DataFrame(
    encoded_data.toarray(),
    columns=encoder.get_feature_names_out(column_to_encode),
    index=X_train.index
)
encoded_df_no_description

# %%
#SentenceTransformer pour la colonne description
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
X_descriptions = model.encode(X_train['Description'].fillna('').tolist(), show_progress_bar=True)
X_descriptions

# %%
#Récupération d'un dataframe pour pouvoir merge après
#'index' précise de garder les indices de X_train car sinon ils sont réinitialisé et cela pose de grands project.ipynb problèmes
X_descriptions = pd.DataFrame(X_descriptions, index=X_train.index)
X_descriptions

# %%
# Merge de nos 3 DataFrame, les données originales sans ce qu'on a encodé, les données encodées en oneHot et les desriptions
encoded_df = pd.concat(
    [X_train.drop(columns=column_to_encode).drop(['Description'], axis=1), encoded_df_no_description, X_descriptions],
    axis=1
)
encoded_df

# %% [markdown]
# On a maintenant un dataframe encodé, on va importer l'algorithme de K-means pour faire un apprentissage non supervisé

# %%
# nom de cs colonnes en string
encoded_df.columns = encoded_df.columns.astype(str)

# %% [markdown]
# Pour savoir combien de cluster choisir, on peut utiliser le code donné par les developpeur de scikit-learn
# 
# Leur code nous donne premièrement un score, plus le plus proche de 1 est le score, plus le nombre de cluster est bien.
# 
# Ensuite, le plot doit avoir des tailles de cluster equivalente et être supérieur à la moyenne des silouhette (la barre rouge)

# %%
# Authors: The scikit-learn developers
# SPDX-License-Identifier: BSD-3-Clause

import matplotlib.cm as cm
import matplotlib.pyplot as plt
import numpy as np

from sklearn.cluster import KMeans
from sklearn.datasets import make_blobs
from sklearn.metrics import silhouette_samples, silhouette_score


X = encoded_df

range_n_clusters = [5, 6, 9, 12, 15, 20]

for n_clusters in range_n_clusters:
    # Create a subplot with 1 row and 2 columns
    fig, ax1 = plt.subplots(1, 1)
    fig.set_size_inches(18, 7)

    # The 1st subplot is the silhouette plot
    # The silhouette coefficient can range from -1, 1 but in this example all
    # lie within [-0.1, 1]
    ax1.set_xlim([-0.1, 1])
    # The (n_clusters+1)*10 is for inserting blank space between silhouette
    # plots of individual clusters, to demarcate them clearly.
    ax1.set_ylim([0, len(X) + (n_clusters + 1) * 10])

    # Initialize the clusterer with n_clusters value and a random generator
    # seed of 10 for reproducibility.
    clusterer = KMeans(n_clusters=n_clusters, random_state=10)
    cluster_labels = clusterer.fit_predict(X)

    # The silhouette_score gives the average value for all the samples.
    # This gives a perspective into the density and separation of the formed
    # clusters
    silhouette_avg = silhouette_score(X, cluster_labels)
    print(
        "For n_clusters =",
        n_clusters,
        "The average silhouette_score is :",
        silhouette_avg,
    )

    # Compute the silhouette scores for each sample
    sample_silhouette_values = silhouette_samples(X, cluster_labels)

    y_lower = 10
    for i in range(n_clusters):
        # Aggregate the silhouette scores for samples belonging to
        # cluster i, and sort them
        ith_cluster_silhouette_values = sample_silhouette_values[cluster_labels == i]

        ith_cluster_silhouette_values.sort()

        size_cluster_i = ith_cluster_silhouette_values.shape[0]
        y_upper = y_lower + size_cluster_i

        color = cm.nipy_spectral(float(i) / n_clusters)
        ax1.fill_betweenx(
            np.arange(y_lower, y_upper),
            0,
            ith_cluster_silhouette_values,
            facecolor=color,
            edgecolor=color,
            alpha=0.7,
        )

        # Label the silhouette plots with their cluster numbers at the middle
        ax1.text(-0.05, y_lower + 0.5 * size_cluster_i, str(i))

        # Compute the new y_lower for next plot
        y_lower = y_upper + 10  # 10 for the 0 samples

    ax1.set_title("The silhouette plot for the various clusters.")
    ax1.set_xlabel("The silhouette coefficient values")
    ax1.set_ylabel("Cluster label")

    # The vertical line for average silhouette score of all the values
    ax1.axvline(x=silhouette_avg, color="red", linestyle="--")

    ax1.set_yticks([])  # Clear the yaxis labels / ticks
    ax1.set_xticks([-0.1, 0, 0.2, 0.4, 0.6, 0.8, 1])

plt.show()

# %% [markdown]
# On remarque que le meilleur choix est 5 cluster. C'est le score le plus haut et les silhouettes sont presque les meilleurs.
# 
# On effectue donc le Kmeans avec 5 cluster

# %%
from sklearn.cluster import KMeans

kmeans = KMeans(n_clusters=5, random_state=42)
kmeans.fit(encoded_df)

X_train['cluster'] = kmeans.labels_

# %% [markdown]
# Pour prédire un titre on:
# 
# - filtre et encode la nouvelle donnée comme on a fait au-dessus.
# - applique kmeans sur la valeur filtrée et encodée
# - On regarde dans le cluster assigné la valeur la plus similaire
# - On retourne le titre de cette donnée trouvé

# %%

def filter_info(new_X):
    new_X_encoded_data = encoder.transform(new_X[column_to_encode])
    new_X_encoded_df_no_description = pd.DataFrame(
        new_X_encoded_data.toarray(),
    columns=encoder.get_feature_names_out(column_to_encode),
    index=new_X.index
    )

    new_X_description = model.encode(new_X['Description'].fillna('').tolist())
    new_X_description_df = pd.DataFrame(new_X_description, index=new_X.index)

    new_X_encoded_df = pd.concat(
    [new_X.drop(columns=column_to_encode).drop(['Description'], axis=1), new_X_encoded_df_no_description, new_X_description_df],
    axis=1
    )

    new_X_encoded_df.columns = new_X_encoded_df.columns.astype(str)

    return new_X_encoded_df

def get_title_new_value(new_X):

    new_X_encoded_df = filter_info(new_X)

    cluster_predit = kmeans.predict(new_X_encoded_df)[0]

    X_cluster = filter_info(X_train[X_train['cluster'] == cluster_predit])
    X_cluster.drop('cluster', axis=1, inplace=True)
    indices = X_cluster.index

    similarities = cosine_similarity(new_X_encoded_df, X_cluster)

    index_plus_proche_local = similarities.argmax()
    index_global = indices[index_plus_proche_local]

    titre_attribue = df.loc[index_global]['Titre ANSSI']
    return titre_attribue

# %% [markdown]
# Test sur une valeur, la première de X_test
# 

# %%
test = X_test.head(1).drop('Titre ANSSI', axis=1)
titre_originel = X_test.head(1)['Titre ANSSI']
test

# %%
get_title_new_value(test)

# %%
titre_originel

# %% [markdown]
# Les deux valeurs sont les mêmes. Nous allons tester le modèle final
# 

# %%
#Rappelle du DataFrame X_test
X_test

# %% [markdown]
# Test global pour chaque valeur dans X_test
# 
# Au lieu de chercher combien de titre sont équivalent, on récupère le titre trouvé et on ré utilise un SentenceTransformer pour comparer les 2 valeurs.
# 
# Comme ça, un haut score est donnée si les titres sont très similaires bien qu'un ou deux mots soient différents.

# %%
from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
precision = 0

for i in range(len(X_test)):

    row = X_test.iloc[i: i+1]
    value_to_deduct_from = row.drop('Titre ANSSI', axis=1)

    original_title = row['Titre ANSSI'].iloc[0]
    guessed_title = get_title_new_value(value_to_deduct_from)

    emb1 = model.encode(original_title, convert_to_tensor=True)
    emb2 = model.encode(guessed_title, convert_to_tensor=True)

    score = util.cos_sim(emb1, emb2).item()
    precision += score

    print("Title to guess : ", original_title)
    print("Guessed title  : ", guessed_title)
    print(f"Semantic Score :  {score:.4f}\n")

precision /= len(X_test)
print("Total precision : ", precision)

# %% [markdown]
# On obtient une **total precision de 90%**
# 
# Ce modèle a une précision très satisfaisante

# %% [markdown]
# ## Modèle supervisé : Prédiction de la Base Severity (Critical / High / Medium / Low)
# 
# Objectif : prédire la gravité (Base Severity, dérivée du CVSS) à partir d'informations
# disponibles sans connaître le score CVSS lui-même : description textuelle, type CWE,
# type de bulletin (Avis/Alerte) et score EPSS.
# 
# Cela permet d'estimer la gravité d'un CVE même lorsque le score CVSS n'a pas encore
# été publié par MITRE.
# 
# Validation : séparation train/test stratifiée, rapport de classification (précision,
# rappel, f1-score) et matrice de confusion.

# %%
# téléchargement pour SMOTE
%pip install imbalanced-learn

# %%
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
df_sup = df.dropna(subset=['Base Severity']).copy()

# Vectorisation sémantique
X_embeddings = model.encode(df_sup['Description'].fillna("").tolist(), show_progress_bar=True)

X = X_embeddings
y = df_sup['Base Severity']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42
)


classifier_rf = RandomForestClassifier(n_estimators=100, random_state=42)

from imblearn.over_sampling import SMOTE

# pour fix le class imablance
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train, y_train)

classifier_rf.fit(X_train_res, y_train_res)

print("Training done")

y_pred = classifier_rf.predict(X_test)

print("\nRapport performance")
print(classification_report(y_test, y_pred))

# confusion matrix
cm = confusion_matrix(y_test, y_pred, labels=classifier_rf.classes_)
plt.figure(figsize=(7, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges',
            xticklabels=classifier_rf.classes_,
            yticklabels=classifier_rf.classes_)
plt.title('Matrice de Confusion (Base Severity via LLM Embeddings)')
plt.ylabel('Vraie sévérité')
plt.xlabel('Sévérité prédite')
plt.show()

# %% [markdown]
# Notre premier modèle sans la class balancing affichait une accuracy trompeuse de 70%. En analysant le rapport, nous avons détecté un fort déséquilibre de nos classes : la catégorie 'High' écrasait les autres, provoquant un recall catastrophique de 17% sur les failles 'Critical'. Pour un outil de veille de l'ANSSI, rater une faille critique est inacceptable. Nous avons donc corrigé ce biais en intégrant une stratégie de rééquilibrage des poids (class_weight='balanced'), ce qui a permis de sacrifier un peu d'accuracy globale au profit d'une bien meilleure détection des menaces critiques

# %% [markdown]
# Dans notre premier modèle, le Random Forest trichait inconsciemment en prédisant presque toujours 'High' (la classe majoritaire), ce qui gonflait artificiellement l'accuracy. En appliquant SMOTE, on a forcé le modèle à prendre des risques sur les classes minoritaires (Critical, Medium, Low). Cela a légèrement fait baisser l'accuracy globale, mais la moyenne macro (macro avg) du F1-Score est passée de 0.37 à 0.46. Le modèle est donc devenu beaucoup plus équitable et performant pour détecter tous les types de menaces, pas seulement les plus fréquentes.

# %%
from sklearn.linear_model import LogisticRegression

classifier_lr = LogisticRegression(max_iter=1000, random_state=42)
classifier_lr.fit(X_train_res, y_train_res)
y_pred = classifier_lr.predict(X_test)

print("\nRapport performances")
print(classification_report(y_test, y_pred))

# confusion matrix
cm = confusion_matrix(y_test, y_pred, labels=classifier_rf.classes_)
plt.figure(figsize=(7, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges',
            xticklabels=classifier_rf.classes_,
            yticklabels=classifier_rf.classes_)
plt.title('Matrice de Confusion (Base Severity via LLM Embeddings)')
plt.ylabel('Vraie sévérité')
plt.xlabel('Sévérité prédite')
plt.show()

# %% [markdown]
# Pour tester et comparer nous avons testé avec LogisticRegression qui donne des résultats plus ou moins similaires. Cependant RandomForest reste meilleur.

# %% [markdown]
# # **Étape 7 : Génération d'Alertes et Notifications Email**

# %% [markdown]
# ## Définition des critères d'alerte
# 
# On considère qu'une vulnérabilité doit déclencher une alerte personnalisée si :
# - son score CVSS est **>= 9** (Critical) **OU**
# - son score EPSS est **> 0.7** (forte probabilité d'exploitation active)
# 
# et qu'elle concerne un éditeur/produit présent dans une liste de `watched_product`
# définie par nous ou bien un utilisateur (simulant un abonné suivant certains logiciels de son
# infrastructure).

# %%
# Liste des produits surveillés par l'utilisateur (on peut la modifier pour rajouter ou enlever)
watched_product = ["Windows", "Linux Kernel", "Chrome"]

def is_monitored(produit, watchlist):
    if pd.isna(produit):
        return False
    produit_lower = str(produit).lower()
    return any(p.lower() in produit_lower for p in watchlist)

# créer surveille pour chaque produit
df["Surveille"] = df["Produit"].apply(lambda p: is_monitored(p, watched_product))

# Critères
alertes = df[
    df["Surveille"]
    & ((df["CVSS"] >= 9) | (df["EPSS"] > 0.7))
].copy()

alertes = alertes.sort_values(by=["CVSS", "EPSS"], ascending=False)
print(f"{len(alertes)} alerte(s) générée(s) sur {len(df)} lignes")
alertes[["ID ANSSI", "CVE", "CVSS", "EPSS", "Editeur", "Produit", "Lien"]].head(10)



# %% [markdown]
# ## Construction du contenu des emails d'alerte
# 
# Pour chaque produit surveillé concerné, on génère un email récapitulant les
# vulnérabilités critiques le concernant (sujet + corps du message).

# %%
def build_alert_email(produit, alertes_produit):
    """Construit le sujet et le corps d'un email d'alerte pour un produit donné."""
    nb_alertes = len(alertes_produit)
    cvss_max = alertes_produit["CVSS"].max()

    subject = f"[ALERTE SECURITE] {nb_alertes} vulnérabilité(s) critique(s) détectée(s) pour {produit}"

    lines = [
        f"Bonjour,",
        "",
        f"{nb_alertes} vulnérabilité(s) nécessitant votre attention ont été détectées",
        f"pour le produit '{produit}' (score CVSS maximum : {cvss_max}).",
        "",
        "Détail des vulnérabilités :",
        "",
    ]

    for _, row in alertes_produit.iterrows():
        lines.append(f"- {row['CVE']} | CVSS: {row['CVSS']} | EPSS: {row['EPSS']:.2f}")
        lines.append(f"  Bulletin ANSSI : {row['ID ANSSI']} - {row['Titre ANSSI']}")
        lines.append(f"  Lien : {row['Lien']}")
        lines.append("")

    lines.append("Nous vous recommandons d'appliquer les correctifs disponibles dans les plus brefs délais.")
    lines.append("")
    lines.append("Cordialement,")
    lines.append("Le service de veille en cybersécurité")

    body = "\n".join(lines)
    return subject, body


# Génération d'un email par produit concerné
email_to_send = []
for produit, group in alertes.groupby("Produit"):
    subject, body = build_alert_email(produit, group)
    email_to_send.append({"produit": produit, "subject": subject, "body": body})


if email_to_send:
    print("SUJET :", email_to_send[0]["subject"])
    print("-" * 60)
    print(email_to_send[0]["body"])
else:
    print("Aucune alerte ne correspond aux critères définis.")

# %% [markdown]
# ## Envoi des notifications par email
# 
# L'envoi réel est désactivé par défaut (`email_send_bool = False`). Pour l'activer,
# renseigner un compte expéditeur et un mot de passe d'application (ex : mot de passe
# d'application Gmail), et une liste de destinataires.
# 
# **Attention**: ne jamais mettre son mdp directement mais utiliser un `.env`.
# 
# Ne pas oublier de mettre le `.env` dans le `.gitignore`

# %%
%pip install python-dotenv

# %%
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv

# Charge les variables définies dans le fichier .env
load_dotenv()

email_sender = os.getenv("email_sender")
email_password = os.getenv("email_password")

email_send_bool = False

if not email_sender or not email_password:
    raise ValueError("Identifiants email manquants ou variables d'environnement incorrects.")


def send_email(to_email, subject, body):



    msg = MIMEText(body)
    msg['From'] = email_sender
    msg['To'] = to_email
    msg['Subject'] = subject

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email_sender, email_password)
    server.sendmail(email_sender, to_email, msg.as_string())
    server.quit()


destinataires = ["email@efrei.net","email@gmail.com"]

if email_send_bool:
    for email_info in email_to_send:
        for dest in destinataires:
            send_email(dest, email_info["subject"], email_info["body"])
            print(f"Email envoyé à {dest} pour le produit {email_info['produit']}")
else:
    print(f"{len(email_to_send)} email(s) prêt(s) à être envoyé(s), modifier email_send_bool.")


