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
- ✅ **Génération de Rapports** : HTML et JSON avec visualisations
- ✅ **Scan YARA** : Détection de malware avec règles personnalisées
- ✅ **Émulation** : Unicorn Engine pour code auto-déchiffrant
- ✅ **Instrumentation Frida** : Analyse dynamique en temps réel

### 🎉 Projet Complet!
AndroSleuth est maintenant un outil d'analyse APK complet avec capacités d'analyse statique ET dynamique.

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
- 🔍 **Hooking API en temps réel** avec Frida
- 🔍 **Monitoring réseau** et fichiers
- 🔍 **Détection SSL Pinning**

## 📋 Prérequis

- Python 3.8+
- pip
- Outils optionnels pour analyse avancée :
  - Radare2 / Ghidra
  - Frida (pour analyse dynamique)
  - Émulateur Android / Device Android (pour tests dynamiques)

## 🛠️ Installation

1. Cloner le repository :
```bash
git clone https://github.com/NatsuGwada/Shellcode_Forensic_Android.git
cd Shellcode_Forensic_Android
```

2. Créer un environnement virtuel :
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows
```

3. Installer les dépendances :
```bash
pip install -r requirements.txt
```

4. (Optionnel) Configurer l'API VirusTotal :
```bash
# Créer le fichier de configuration
cp config/secrets.yaml.example config/secrets.yaml

# Éditer et ajouter votre clé API
nano config/secrets.yaml
```

Obtenez une clé API gratuite sur [VirusTotal](https://www.virustotal.com/gui/join-us)

## 📖 Utilisation

### Analyse Rapide (Statique uniquement)
```bash
python src/androsleuth.py -a sample.apk -m quick
```

### Analyse Standard (Statique + Shellcode)
```bash
python src/androsleuth.py -a sample.apk -m standard
```

### Analyse Approfondie (Tout + Dynamique)
```bash
python src/androsleuth.py -a sample.apk -m deep --frida
```
**Inclut** : Tout ci-dessus + Émulation + Frida (à venir)

### Options Avancées
```bash
# Générer uniquement un rapport JSON
python src/androsleuth.py -a sample.apk -f json -o reports/my_report

# Analyse complète avec génération de rapports
python src/androsleuth.py -a sample.apk -m deep -o reports/malware_analysis

# Analyse avec émulation (détection auto-déchiffrement)
python src/androsleuth.py -a sample.apk -m deep --emulation

# Analyse dynamique avec Frida (nécessite un device)
python src/androsleuth.py -a sample.apk --frida --duration 60

# Analyse exhaustive (statique + dynamique)
python src/androsleuth.py -a sample.apk -m deep --emulation --frida -o reports/full_analysis

# Analyse verbose avec tous les modules
python src/androsleuth.py -a sample.apk -v --all-modules

# Utiliser une configuration personnalisée
python src/androsleuth.py -a sample.apk --config my_config.yaml
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
pytest tests/ -v
```

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push sur la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📝 TODO

- [x] Structure de base du projet
- [x] Interface CLI
- [x] Module d'ingestion APK
- [x] Analyseur de manifeste
- [x] Détecteur d'obfuscation
- [x] Analyseur de code statique
- [x] Intégration VirusTotal
- [x] **Module d'analyse de shellcode**
- [x] Système de scoring
- [ ] Module d'émulation (Unicorn Engine)
- [ ] Instrumentation Frida
- [ ] Générateur de rapports HTML

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
