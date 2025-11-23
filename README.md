# AndroSleuth 🔍

**Advanced Android APK Forensic Analysis Tool**

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

## 🎯 Description

AndroSleuth est un outil d'analyse forensique avancé pour les fichiers APK Android. Il permet de détecter les comportements suspects, les fonctionnalités cachées, et les shellcodes potentiels dans les applications mobiles.

Sur internet, il y a plein d'applications Android disponibles sur des plateformes comme APKPure, mais on ne sait jamais si elles sont fiables ou non. Ce projet vise à fournir un outil complet d'analyse statique et dynamique pour identifier les malwares et les comportements malveillants.

## 🚀 Fonctionnalités

### ✅ Actuellement Implémenté (Phases 1-9 - COMPLET!)
- ✅ **Structure du projet** : Architecture modulaire et extensible
- ✅ **Interface CLI** : Commandes complètes avec argparse
- ✅ **Configuration YAML** : Paramétrage flexible
- ✅ **Modes d'analyse** : Quick / Standard / Deep
- ✅ **Intégration VirusTotal** : Vérification de réputation via API
- ✅ **Ingestion APK** : Extraction et validation complète
- ✅ **Analyse du Manifeste** : Permissions, receivers, anomalies
- ✅ **Détection d'obfuscation** : ProGuard, packers, entropie
- ✅ **Analyse statique** : Strings, APIs, chargement dynamique
- ✅ **Analyse de shellcode** : Désassemblage ARM/x86, patterns malveillants
- ✅ **Système de scoring** : Score de menace intelligent (0-100)
- ✅ **Génération de Rapports** : HTML, JSON et **PDF** avec visualisations
- ✅ **Scan YARA** : Détection de malware avec règles personnalisées
- ✅ **Émulation** : Unicorn Engine pour code auto-déchiffrant
- ✅ **Instrumentation Frida** : Analyse dynamique en temps réel
- ✅ **Docker** : Container isolé et sécurisé pour analyse de malware
- ✅ **Poetry** : Gestion moderne des dépendances

### 🎉 Projet Complet!
AndroSleuth est maintenant un outil d'analyse APK complet avec :
- **Analyse Statique** : Manifeste, obfuscation, strings, shellcode, YARA
- **Analyse Dynamique** : Émulation Unicorn + Instrumentation Frida
- **Rapports Professionnels** : HTML, JSON, PDF avec code couleur
- **Environnement Isolé** : Container Docker sécurisé
- **Gestion Moderne** : Poetry pour dépendances reproductibles

### ✅ Détections Avancées Disponibles
- 🔍 **15+ permissions dangereuses** (SMS, localisation, caméra, etc.)
- 🔍 **10+ packers commerciaux** (UPX, Bangcle, Tencent, etc.)
- 🔍 **20+ patterns suspects** (shell, root, crypto, etc.)
- 🔍 **Combinaisons de permissions** suspectes
- 🔍 **Chargement dynamique** de code (DexClassLoader, etc.)
- 🔍 **Fichiers haute entropie** (chiffrés/compressés)
- 🔍 **Syscalls dangereux** (execve, ptrace, etc.)
- 🔍 **Patterns shellcode** (NOP sleds, egg hunters, etc.)
- 🔍 **Désassemblage natif** ARM/ARM64/x86/x86-64
- 🔍 **Réputation VirusTotal** (70+ moteurs AV)
- 🔍 **13+ familles de malware** (trojans, spyware, ransomware, etc.)
- 🔍 **Règles YARA personnalisées** pour détection comportementale
- 🔍 **Code auto-déchiffrant** via émulation Unicorn
- 🔍 **Hooking API en temps réel** avec Frida (10+ catégories)
- 🔍 **Monitoring réseau** et fichiers pendant exécution
- 🔍 **Détection SSL Pinning** et bypass
- 🔍 **Génération PDF** avec graphiques et code couleur

## 📋 Prérequis

- Python 3.8+
- Poetry (gestionnaire de dépendances moderne) ou pip
- Outils optionnels pour analyse avancée :
  - Radare2 / Ghidra (analyse binaire avancée)
  - Frida (pour analyse dynamique en temps réel)
  - Émulateur Android / Device Android (pour tests dynamiques)
  - frida-server sur le device Android (pour instrumentation)

## 🛠️ Installation

### Option 1 : Installation avec Poetry (Recommandé) 🚀

**Poetry** offre une gestion de dépendances moderne avec résolution automatique des conflits et environnements isolés.

```bash
# 1. Cloner le repository
git clone https://github.com/NatsuGwada/Shellcode_Forensic_Android.git
cd Shellcode_Forensic_Android

# 2. Lancer l'installation interactive
./install_poetry.sh
```

Le script installera automatiquement Poetry si nécessaire et vous proposera 4 profils :

- **Basic** : Core uniquement (Androguard, YARA)
- **Standard** : + Désassemblage (Capstone) + Émulation (Unicorn)
- **Full** : Toutes les fonctionnalités (+ Frida) ⭐ **Recommandé**
- **Developer** : Full + outils de développement (pytest, black, mypy)

### Option 2 : Installation manuelle avec pip

```bash
# 1. Cloner le repository
git clone https://github.com/NatsuGwada/Shellcode_Forensic_Android.git
cd Shellcode_Forensic_Android

# 2. Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# 3. Installer les dépendances
pip install -r requirements.txt
```

### Configuration de VirusTotal (Optionnel)

Pour activer la vérification de réputation :

```bash
# Copier le template de configuration
cp config/secrets.yaml.example config/secrets.yaml

# Éditer et ajouter votre clé API
nano config/secrets.yaml  # ou vim/code
```

**Obtenir une clé API gratuite** : [VirusTotal API](https://www.virustotal.com/gui/join-us)

### Configuration de Frida (Pour analyse dynamique)

```bash
# 1. Télécharger frida-server pour votre architecture Android
# Depuis : https://github.com/frida/frida/releases

# 2. Pousser sur le device
adb push frida-server /data/local/tmp/

# 3. Rendre exécutable
adb shell "chmod 755 /data/local/tmp/frida-server"

# 4. Lancer le serveur
adb shell "/data/local/tmp/frida-server &"
```

## 📖 Utilisation

### Avec Poetry (Recommandé)

```bash
# Activer l'environnement Poetry
poetry shell

# Ou exécuter directement avec 'poetry run'
poetry run androsleuth -a sample.apk -m quick
```

### Exemples d'Analyse

#### Analyse Rapide (Statique uniquement)
```bash
# Avec Poetry
poetry run androsleuth -a sample.apk -m quick

# Avec pip/venv
python src/androsleuth.py -a sample.apk -m quick
```

#### Analyse Standard (Statique + Shellcode + YARA)
```bash
poetry run androsleuth -a sample.apk -m standard
```

#### Analyse Approfondie (Tout + VirusTotal)
```bash
poetry run androsleuth -a sample.apk -m deep
```
**Inclut** : Manifeste, Obfuscation, Statique, Shellcode, YARA, VirusTotal

#### Analyse avec Émulation (Détection auto-déchiffrement)
```bash
poetry run androsleuth -a sample.apk -m deep --emulation
```
**Détecte** : Code auto-modifiant, déchiffrement à l'exécution, packing sophistiqué

#### Analyse Dynamique avec Frida (Nécessite device Android)
```bash
poetry run androsleuth -a sample.apk --frida --duration 60
```
**Monitore** : API crypto, réseau, fichiers, SMS, localisation, chargement dynamique

#### Analyse Exhaustive (Statique + Dynamique + Émulation)
```bash
poetry run androsleuth -a sample.apk -m deep --emulation --frida --duration 120 -o reports/full_analysis
```

#### Génération de Rapports PDF
```bash
# Rapport PDF uniquement
poetry run androsleuth -a sample.apk -m standard -f pdf -o reports/analysis

# Tous les formats (HTML + JSON + PDF)
poetry run androsleuth -a sample.apk -m deep -f both -o reports/complete
```

### Options Avancées

```bash
# Rapport JSON uniquement
poetry run androsleuth -a sample.apk -f json -o reports/my_report

# Rapport PDF professionnel
poetry run androsleuth -a sample.apk -f pdf -o reports/professional

# Analyse complète avec tous les formats
poetry run androsleuth -a sample.apk -m deep -f both -o reports/malware_analysis

# Mode verbose pour debugging
poetry run androsleuth -a sample.apk -m deep -v

# Configuration personnalisée
poetry run androsleuth -a sample.apk --config my_config.yaml

# Aide complète
poetry run androsleuth --help
```

### Commandes Poetry Utiles

```bash
# Activer l'environnement virtuel
poetry shell

# Installer une nouvelle dépendance
poetry add requests

# Installer dépendances de développement
poetry add --group dev pytest

# Mettre à jour les dépendances
poetry update

# Voir les dépendances installées
poetry show

# Exécuter les tests
poetry run pytest

# Lancer le formateur de code
poetry run black src/

# Vérifier le code avec flake8
poetry run flake8 src/

# Construire le package
poetry build

# Publier sur PyPI (après configuration)
poetry publish
```

## 📁 Structure du Projet

```
Shellcode_Forensic_Android/
├── src/
│   ├── androsleuth.py          # Point d'entrée principal
│   ├── modules/                 # Modules d'analyse
│   │   ├── apk_ingestion.py         # ✅ Extraction APK
│   │   ├── manifest_analyzer.py     # ✅ Analyse manifeste
│   │   ├── obfuscation_detector.py  # ✅ Détection obfuscation
│   │   ├── static_analyzer.py       # ✅ Analyse statique
│   │   ├── shellcode_detector.py    # ✅ Analyse shellcode
│   │   ├── virustotal_checker.py    # ✅ Vérification VirusTotal
│   │   ├── yara_scanner.py          # ✅ Scan YARA
│   │   ├── emulator.py              # ✅ Émulation Unicorn
│   │   ├── frida_analyzer.py        # ✅ Analyse dynamique Frida
│   │   └── report_generator.py      # ✅ Génération de rapports
│   └── utils/                   # Utilitaires
│       ├── logger.py                # Logger avec couleurs
│       ├── entropy.py               # Calcul d'entropie
│       └── helpers.py               # Fonctions utilitaires
├── yara_rules/                  # Règles YARA personnalisées
│   ├── android_malware.yar          # Détection de malware
│   ├── android_packers.yar          # Détection de packers
│   └── README.md
├── frida_scripts/               # Scripts Frida pour hooking
│   └── README.md
├── config/
│   └── config.yaml              # Configuration principale
├── reports/                     # Rapports générés
├── samples/                     # Échantillons d'APK pour tests
├── tests/                       # Tests unitaires
├── requirements.txt             # Dépendances Python
└── README.md                    # Documentation

```

## 🔧 Configuration

Le fichier `config/config.yaml` permet de personnaliser :
- Les seuils de détection (entropie, scoring)
- Les permissions considérées comme dangereuses
- Les patterns de strings suspects
- Les poids du système de scoring
- Les formats de rapport

## 🧪 Tests

```bash
# Avec Poetry
poetry run pytest tests/ -v

# Avec coverage
poetry run pytest tests/ -v --cov=src --cov-report=html

# Avec pip/venv
pytest tests/ -v
```

## 🔒 Sécurité et Sandbox

**⚠️ Important** : AndroSleuth effectue de l'**analyse statique** par défaut, ce qui est sûr. Cependant :

### Analyse Statique (Sûr) ✅
- Extraction et parsing du manifeste
- Analyse des strings et bytecode
- Désassemblage du code natif
- Scan YARA
- **Aucune exécution de code**

### Émulation (Partiellement isolé) ⚠️
- Utilise **Unicorn Engine** (émulateur CPU)
- Exécute du code natif dans un environnement contrôlé
- Limité à 10,000 instructions par fonction
- Pas d'accès système réel
- **Recommandation** : Analyser uniquement des APK de sources fiables

### Analyse Dynamique avec Frida (Nécessite isolation) 🔴
- **INSTALLE ET EXÉCUTE l'APK** sur un device Android
- Peut exécuter du code malveillant réel
- **OBLIGATOIRE** : Utiliser un environnement isolé :
  - **Émulateur Android** (recommandé) : AVD, Genymotion
  - **Device physique dédié** : Sans données personnelles, rooté
  - **VM Android** : Android-x86 dans VirtualBox/VMware
  - **Sandbox cloud** : Cuckoo, Joe Sandbox (pour malware avancé)

### Recommandations de Sécurité 🛡️

#### Pour Analyse Statique/Émulation :
```bash
# Pas de sandbox nécessaire
poetry run androsleuth -a sample.apk -m deep --emulation
```

#### Pour Analyse Dynamique :
```bash
# 1. Utiliser un émulateur Android isolé
emulator -avd test_device -no-snapshot

# 2. Lancer frida-server sur l'émulateur
adb shell "/data/local/tmp/frida-server &"

# 3. Analyser avec timeout
poetry run androsleuth -a sample.apk --frida --duration 60

# 4. Restaurer snapshot après analyse
```

#### Configuration Sandbox Recommandée :
- ✅ **Émulateur AVD** sans Google Services
- ✅ **Réseau isolé** (pas d'accès Internet ou filtrage)
- ✅ **Snapshots** pour restauration rapide
- ✅ **Monitoring système** (tcpdump, strace)
- ✅ **Pas de données sensibles** sur le device

**Note** : L'analyse statique et l'émulation Unicorn sont suffisamment sûres pour analyser des APK suspects sans sandbox complet. Seule l'analyse dynamique avec Frida nécessite une isolation stricte.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push sur la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📝 TODO

### Complété ✅
- [x] Structure de base du projet
- [x] Interface CLI
- [x] Module d'ingestion APK
- [x] Analyseur de manifeste
- [x] Détecteur d'obfuscation
- [x] Analyseur de code statique
- [x] Intégration VirusTotal
- [x] Module d'analyse de shellcode
- [x] Système de scoring
- [x] Module d'émulation (Unicorn Engine)
- [x] Instrumentation Frida
- [x] Générateur de rapports HTML/JSON
- [x] Scanner YARA avec règles personnalisées
- [x] Gestion des dépendances avec Poetry

### En Cours 🚧
- [ ] Tests unitaires complets (coverage > 80%)
- [ ] CI/CD avec GitHub Actions
- [ ] Documentation API complète
- [ ] Interface Web (Flask/FastAPI)

### Futur 🔮
- [ ] Analyse de trafic réseau (mitmproxy)
- [ ] Détection de techniques anti-analyse
- [ ] Support multi-APK (comparaison)
- [ ] Base de données des IOCs
- [ ] Plugin pour IDA Pro / Ghidra
- [ ] Intégration avec MISP
- [ ] Containerisation Docker
- [ ] API REST pour automatisation

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 👤 Auteur

**NatsuGwada**

- GitHub: [@NatsuGwada](https://github.com/NatsuGwada)
- Repository: [Shellcode_Forensic_Android](https://github.com/NatsuGwada/Shellcode_Forensic_Android)

## ⚠️ Avertissement

Cet outil est destiné à des fins éducatives et de recherche en sécurité. Utilisez-le de manière responsable et légale. Les auteurs ne sont pas responsables de toute utilisation malveillante de cet outil.

## 🙏 Remerciements

- Androguard pour l'analyse APK
- Frida pour l'instrumentation dynamique
- Capstone pour le désassemblage
- Unicorn Engine pour l'émulation
- La communauté de la sécurité Android
