# AndroSleuth - Fonctionnalités Implémentées

## 📋 Vue d'ensemble

**Version actuelle** : 1.0.0 (Phases 1-5 complétées)  
**État** : Analyse statique + shellcode complète fonctionnelle  
**Date** : 23 novembre 2025

---

## ✅ Modules Implémentés

### 1. 🏗️ Infrastructure de Base
- [x] Structure de projet modulaire et extensible
- [x] Interface CLI complète avec argparse
- [x] Système de logging avec couleurs (Console + Fichiers)
- [x] Configuration YAML flexible
- [x] Gestion des erreurs robuste
- [x] Script d'installation automatique
- [x] **Intégration VirusTotal pour vérification de réputation**

### 2. 📦 Module d'Ingestion APK (`apk_ingestion.py`)
- [x] Validation de fichiers APK
- [x] Extraction complète (DEX, SO, ressources, manifeste)
- [x] Calcul de hash (MD5, SHA1, SHA256)
- [x] Extraction de métadonnées (package, version, signatures)
- [x] Gestion des fichiers temporaires
- [x] Support des APK signés (v1, v2, v3)

**Exemple d'utilisation** :
```python
ingestion = APKIngestion("app.apk")
results = ingestion.process()
# Retourne: metadata, extracted_files, hashes
```

### 3. 📄 Analyseur de Manifeste (`manifest_analyzer.py`)
- [x] Parse AndroidManifest.xml
- [x] Détection de 15+ permissions dangereuses
- [x] Analyse des Broadcast Receivers suspects
- [x] Analyse des Services (mots-clés malveillants)
- [x] Analyse des Activities et Content Providers
- [x] Détection d'anomalies de configuration :
  - Application debuggable
  - Backup autorisé
  - Trafic cleartext
- [x] Détection de combinaisons suspectes :
  - SMS + Internet
  - Localisation + Internet
  - Caméra/Micro + Internet
- [x] Calcul de score de menace (0-100)

**Permissions surveillées** :
- SEND_SMS, READ_SMS, RECEIVE_SMS
- READ_CONTACTS, CALL_PHONE
- ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION
- CAMERA, RECORD_AUDIO
- SYSTEM_ALERT_WINDOW
- REQUEST_INSTALL_PACKAGES
- Et plus...

### 4. 🔒 Détecteur d'Obfuscation (`obfuscation_detector.py`)
- [x] Détection ProGuard/R8 (analyse des noms de classes)
- [x] Calcul d'entropie Shannon sur DEX et bibliothèques natives
- [x] Détection de 10+ packers connus :
  - UPX, Bangcle, Qihoo 360
  - Baidu, Tencent, Alibaba
  - Ijiami, DexGuard, APKProtect
- [x] Analyse d'obfuscation de strings (Base64, Hex)
- [x] Détection d'usage intensif de réflexion Java
- [x] Identification de fichiers suspects (haute entropie)
- [x] Score d'obfuscation (0-100)

**Techniques détectées** :
- ProGuard/R8 obfuscation
- Commercial packers
- String encryption
- Heavy reflection usage

### 5. 🔍 Analyseur Statique (`static_analyzer.py`)
- [x] Extraction de strings depuis DEX
- [x] Détection de patterns suspects configurables
- [x] Scan d'URLs et adresses IP hardcodées
- [x] Détection de commandes shell (su, chmod, etc.)
- [x] Détection de chargement dynamique de code :
  - DexClassLoader
  - PathClassLoader
  - URLClassLoader
- [x] Analyse d'usage de code natif (JNI)
- [x] Détection d'API cryptographiques
- [x] Détection d'activité réseau
- [x] Détection d'API de réflexion Java
- [x] Classification par catégories :
  - ROOT_ACCESS
  - CRYPTOGRAPHY
  - DYNAMIC_LOADING
  - PROCESS_EXECUTION
  - NETWORK
  - SHELL_COMMAND

### 6. 🌐 Vérification VirusTotal (`virustotal_checker.py`)
- [x] Vérification de réputation via API VirusTotal v3
- [x] Lookup par hash SHA-256
- [x] Statistiques de détection (malicious/suspicious/clean)
- [x] Liste des moteurs ayant détecté l'APK
- [x] Classification automatique :
  - CLEAN (0 détections)
  - POTENTIALLY_UNWANTED (1-2 détections)
  - SUSPICIOUS (3-4 détections)
  - HIGHLY_SUSPICIOUS (5-9 détections)
  - MALICIOUS (10+ détections)
- [x] Score de réputation (0-100)
- [x] Lien direct vers le rapport VirusTotal
- [x] Support API key via :
  - Variable d'environnement `VIRUSTOTAL_API_KEY`
  - Fichier `config/secrets.yaml`
- [x] Fonction d'upload pour nouveaux fichiers

**Avantages** :
- ✅ Validation croisée avec 70+ moteurs antivirus
- ✅ Détection rapide de malwares connus
- ✅ Données communautaires de sécurité
- ✅ Historique de scan et dates

### 7. � Analyse de Shellcode (`shellcode_detector.py`)
- [x] Analyse des en-têtes ELF (32/64-bit, ARM/x86)
- [x] Détection d'architecture (ARM, ARM64, x86, x86-64)
- [x] Désassemblage avec Capstone (multi-architecture)
- [x] Détection de syscalls dangereux :
  - execve, system, fork, ptrace
  - chmod, chown, mount, setuid
  - socket, connect, bind
- [x] Détection de patterns shellcode :
  - NOP sleds (x86, ARM, ARM64)
  - Egg hunters
  - Self-modifying code
  - Network syscalls
- [x] Analyse d'entropie des sections
- [x] Extraction et analyse de strings dans .so
- [x] Détection d'instructions suspectes :
  - Appels système (syscall, svc, int)
  - Opérations cryptographiques (xor, ror, rol)
  - Contrôle de flux inhabituel
- [x] Classification par niveau de menace
- [x] Score de menace pour code natif

**Architectures supportées** :
- ✅ ARM (32-bit)
- ✅ ARM64 (64-bit)
- ✅ x86 (32-bit)
- ✅ x86-64 (64-bit)

**Patterns détectés** :
- 🔍 NOP sleds (exploits)
- 🔍 Egg hunters
- 🔍 Code auto-modifiant
- 🔍 Reverse shells
- 🔍 Syscalls malveillants

---

### 7. 📝 Génération de Rapports (`report_generator.py`)

#### Rapports HTML Interactifs
- [x] Design moderne avec gradients et animations CSS
- [x] Score global visualisé avec couleur selon risque
- [x] Sections organisées pour chaque module d'analyse
- [x] Badges colorés pour permissions et détections
- [x] Barres de progression pour scores individuels
- [x] Responsive design (mobile/desktop)
- [x] Code highlighting pour hash et données techniques

#### Rapports JSON Structurés
- [x] Format structuré pour parsing automatisé
- [x] Timestamp et métadonnées complètes
- [x] Résultats de tous les modules
- [x] Scores individuels et global
- [x] Compatible avec outils d'analyse tiers

#### Fonctionnalités des Rapports
- [x] Génération automatique avec nom unique (timestamp)
- [x] Sauvegarde dans répertoire configurable
- [x] Agrégation de tous les résultats d'analyse
- [x] Classification de risque (CLEAN to CRITICAL)
- [x] Section summary avec vue d'ensemble
- [x] Liens vers ressources externes (GitHub, VT)

#### Visualisations
- [x] Score global avec code couleur (vert → rouge)
- [x] Grilles d'information organisées
- [x] Listes de détections avec niveaux de sévérité
- [x] Badges pour catégorisation rapide
- [x] Layout moderne et professionnel

---

### 8. �️ Utilitaires (`utils/`)

#### `entropy.py`
- [x] Calcul d'entropie Shannon
- [x] Analyse par chunks
- [x] Descriptions lisibles (low/medium/high entropy)
- [x] Détection de données chiffrées/compressées

#### `helpers.py`
- [x] Calcul de hash (MD5, SHA1, SHA256)
- [x] Formatage de tailles de fichiers
- [x] Gestion de répertoires temporaires
- [x] Extraction de strings ASCII
- [x] Lecture sécurisée de fichiers
- [x] Sanitisation de noms de fichiers
- [x] Validation de fichiers

#### `logger.py`
- [x] Logs colorés (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- [x] Support console + fichiers
- [x] Mode verbose
- [x] Format personnalisé

---

## 📊 Système de Scoring

### Score Global (0-100)
Moyenne pondérée de :
1. **Score Manifeste** (max 65 points)
   - Permissions dangereuses : 25 pts
   - Receivers suspects : 15 pts
   - Services suspects : 10 pts
   - Anomalies : 15 pts

2. **Score Obfuscation** (max 100 points)
   - Packer détecté : 30 pts
   - Techniques d'obfuscation : 10 pts chacune
   - Fichiers suspects : 5 pts chacun

3. **Score Statique** (max 70 points)
   - Strings suspectes : 20 pts
   - Chargement dynamique : 25 pts
   - Code natif : 15 pts
   - Accès root : 15 pts
   - Commandes shell : 10 pts

4. **Score VirusTotal** (max 100 points)
   - CLEAN : 0 pts
   - POTENTIALLY_UNWANTED : 30 pts
   - SUSPICIOUS : 50 pts
   - HIGHLY_SUSPICIOUS : 75 pts
   - MALICIOUS : 100 pts

5. **Score Shellcode** (max 100 points)
   - Bibliothèques suspectes : 40 pts
   - Patterns shellcode : 30 pts
   - Syscalls dangereux : 30 pts

### Niveaux de Menace
- **0-30** : ✅ SAFE
- **31-50** : ⚠️ LOW
- **51-70** : ⚠️ MEDIUM
- **71-85** : 🔴 HIGH
- **86-100** : 🔴 CRITICAL

---

## 🎯 Modes d'Analyse

### Mode Quick
```bash
python src/androsleuth.py -a app.apk -m quick
```
- Analyse du manifeste uniquement
- Ultra-rapide (~5-10 secondes)
- Idéal pour triage initial

### Mode Standard (Recommandé)
```bash
python src/androsleuth.py -a app.apk -m standard
```
- Manifeste + Obfuscation + Analyse statique
- Équilibre vitesse/profondeur (~30-60 secondes)
- Analyse complète sans émulation

### Mode Deep
```bash
python src/androsleuth.py -a app.apk -m deep
```
- Tous les modules activés
- Inclut analyse de shellcode (à venir)
- Analyse exhaustive (~2-5 minutes)

---

## 📈 Statistiques du Code

- **Lignes de code Python** : ~4500+
- **Modules d'analyse** : 8 (ingestion, manifeste, obfuscation, statique, shellcode, virustotal, reports)
- **Utilitaires** : 3
- **Patterns suspects détectés** : 30+
- **Permissions surveillées** : 15+
- **Packers reconnus** : 10+
- **Moteurs antivirus** (via VT) : 70+
- **Architectures supportées** : 4 (ARM, ARM64, x86, x86-64)
- **Syscalls surveillés** : 12+
- **Formats de rapport** : 2 (HTML, JSON)

---

## ⏳ À Venir (Phases suivantes)

### Phase 7 : Émulation
- [ ] Émulation avec Unicorn Engine
- [ ] Détection d'auto-déchiffrement
- [ ] Sandbox d'exécution
- [ ] Analyse de comportement

### Phase 8 : Analyse Dynamique
- [ ] Scripts Frida
- [ ] Hooking d'API
- [ ] Monitoring réseau
- [ ] Détection SSL Pinning

### Phase 9 : Améliorations Reporting
- [ ] Graphes d'appels interactifs
- [ ] Visualisations avancées avec Plotly
- [ ] Export PDF
- [ ] Comparaison entre versions d'APK

---

## 🔗 Intégration

Le framework est conçu pour être extensible :

```python
# Ajouter un nouveau module d'analyse
class MyAnalyzer:
    def __init__(self, apk_object, config):
        self.apk = apk_object
        self.results = {}
    
    def analyze(self):
        # Votre logique
        return self.results
    
    def get_summary(self):
        return {'score': 0}

# L'intégrer dans androsleuth.py
analyzer = MyAnalyzer(apk, config)
results = analyzer.analyze()
```

---

## 📚 Dépendances Principales

- **androguard** : Parse APK et DEX
- **capstone** : Désassembleur
- **unicorn** : Émulateur CPU
- **frida** : Instrumentation dynamique
- **yara-python** : Détection de malwares
- **rich** : Interface CLI élégante
- **colorama** : Logs colorés

---

## 🏆 Points Forts

1. ✅ **Modulaire** : Architecture claire et extensible
2. ✅ **Configurable** : YAML pour tout paramétrer
3. ✅ **Robuste** : Gestion d'erreurs complète
4. ✅ **Performant** : Analyse rapide et efficace
5. ✅ **Documenté** : Code commenté, README détaillé
6. ✅ **Testable** : Structure prête pour tests unitaires

---

**Note** : Ce projet est en développement actif. Les fonctionnalités avancées (shellcode, émulation, Frida) seront ajoutées progressivement.
