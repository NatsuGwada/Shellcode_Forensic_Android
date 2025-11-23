# AndroSleuth 🔍

**Advanced Android APK Forensic Analysis Tool**

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

## 🎯 Description

AndroSleuth est un outil d'analyse forensique avancé pour les fichiers APK Android. Il permet de détecter les comportements suspects, les fonctionnalités cachées, et les shellcodes potentiels dans les applications mobiles.

Sur internet, il y a plein d'applications Android disponibles sur des plateformes comme APKPure, mais on ne sait jamais si elles sont fiables ou non. Ce projet vise à fournir un outil complet d'analyse statique et dynamique pour identifier les malwares et les comportements malveillants.

## 🚀 Fonctionnalités

### ✅ Phase 1 - Actuellement Implémenté
- ✅ Structure du projet complète
- ✅ Interface CLI avec argparse
- ✅ Configuration YAML flexible
- ✅ Système de gestion des modes d'analyse (quick/standard/deep)
- ✅ **Intégration VirusTotal** : Vérification de réputation via API

### 🔄 En Développement
- **Analyse Statique**
  - Extraction et analyse du manifeste Android
  - Détection des permissions dangereuses
  - Analyse des strings suspectes
  - Détection d'obfuscation (entropie, packers)
  - Analyse des fichiers DEX et ressources

- **Analyse de Shellcode**
  - Extraction des bibliothèques natives (.so)
  - Désassemblage ARM/x86
  - Détection de patterns shellcode
  - Émulation avec Unicorn Engine

- **Analyse Comportementale (Dynamique)**
  - Instrumentation Frida
  - Hooking des API sensibles
  - Monitoring des appels système
  - Détection SSL Pinning

- **Système de Scoring**
  - Calcul du score de menace (0-100)
  - Classification des menaces
  - Génération de rapports HTML/JSON

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

### Options Avancées
```bash
# Générer uniquement un rapport JSON
python src/androsleuth.py -a sample.apk -f json -o reports/my_report

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
│   │   ├── manifest_analyzer.py
│   │   ├── static_analyzer.py
│   │   ├── shellcode_detector.py
│   │   ├── dynamic_analyzer.py
│   │   └── report_generator.py
│   └── utils/                   # Utilitaires
│       ├── logger.py
│       ├── entropy.py
│       └── helpers.py
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
- [ ] Module d'ingestion APK
- [ ] Analyseur de manifeste
- [ ] Détecteur d'obfuscation
- [ ] Analyseur de code statique
- [ ] Module d'analyse de shellcode
- [ ] Émulation de code
- [ ] Instrumentation Frida
- [ ] Système de scoring
- [ ] Générateur de rapports

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
