# Advanced Static Analysis Features

## 📋 Vue d'ensemble

AndroSleuth intègre maintenant des capacités d'analyse statique avancées avec :
- **JADX Integration** : Décompilation Java complète
- **Advanced Permission Analysis** : Analyse matricielle des permissions
- **Component Analysis** : Analyse approfondie des composants Android
- **Anti-Analysis Detection** : Détection de techniques anti-analyse
- **Data Exfiltration Detection** : Identification de patterns d'exfiltration

## 🎯 Nouvelles Fonctionnalités

### 1. JADX Decompiler Integration

**Module**: `src/modules/jadx_decompiler.py`

#### Capacités :
- ✅ Décompilation complète du code Java
- ✅ Détection de secrets hardcodés (API keys, tokens, passwords)
- ✅ Identification d'APIs dangereuses
- ✅ Détection d'obfuscation avancée
- ✅ Analyse de complexité du code

#### Installation :
```bash
# Installation automatique
./install_jadx.sh

# Ou installation manuelle
sudo apt install jadx  # Ubuntu/Debian
brew install jadx      # macOS
```

#### Usage :
```python
from src.modules.jadx_decompiler import JADXDecompiler

# Créer l'analyseur
jadx = JADXDecompiler(apk_path="app.apk")

# Lancer l'analyse complète
results = jadx.analyze(decompile_timeout=300)

# Résultats disponibles :
# - classes_count: Nombre de classes Java
# - methods_count: Nombre de méthodes
# - hardcoded_secrets: Secrets trouvés
# - dangerous_apis: APIs dangereuses utilisées
# - obfuscation_indicators: Indicateurs d'obfuscation
# - threat_score: Score de menace (0-100)
```

#### Secrets Détectés :
- **API Keys** : `api_key`, `apikey` patterns
- **AWS Keys** : `AKIA[0-9A-Z]{16}`
- **Private Keys** : Clés RSA/EC/OpenSSH
- **Passwords** : Patterns de mots de passe
- **Tokens** : Auth tokens, JWT
- **Firebase URLs** : URLs Firebase
- **JDBC URLs** : Connexions base de données
- **Base64 Keys** : Clés encodées en Base64

#### APIs Dangereuses :
| API | Sévérité | Description |
|-----|----------|-------------|
| `Runtime.exec` | CRITICAL | Exécution de commandes |
| `DexClassLoader` | CRITICAL | Chargement dynamique de DEX |
| `ProcessBuilder` | HIGH | Création de processus |
| `Class.forName` | HIGH | Chargement dynamique de classes |
| `WebView.addJavascriptInterface` | HIGH | Interface JS (risque XSS) |
| `TrustManager` | HIGH | Gestion SSL personnalisée |

### 2. Advanced Permission Analyzer

**Module**: `src/modules/manifest_analyzer.py` (enhanced)

#### Nouvelles Capacités :
- ✅ **Groupes de permissions** : Catégorisation fonctionnelle
- ✅ **Matrice de permissions** : Analyse détaillée par permission
- ✅ **Runtime vs Install-time** : Distinction Android 6.0+
- ✅ **Détection de sur-privilèges** : Apps over-privileged
- ✅ **Combinaisons suspectes** : Patterns de malware

#### Groupes de Permissions :
```python
LOCATION      # GPS, localisation fine/grossière
CAMERA        # Accès caméra
MICROPHONE    # Enregistrement audio
CONTACTS      # Carnets d'adresses
PHONE         # État téléphone, appels
SMS           # SMS, MMS
STORAGE       # Stockage externe
CALENDAR      # Calendrier
SENSORS       # Capteurs corporels
NETWORK       # Internet, WiFi
SYSTEM        # Permissions système
```

#### Patterns de Sur-Privilèges :
1. **Spyware Pattern** : SMS + Location + Camera
2. **SMS Trojan** : Phone + SMS + Contacts
3. **Trop de groupes** : Plus de 6 groupes actifs
4. **Trop de permissions** : Plus de 15 permissions dangereuses

#### Exemple de Matrice :
```json
{
  "name": "android.permission.SEND_SMS",
  "group": "SMS",
  "protection_level": "dangerous",
  "is_dangerous": true,
  "is_runtime": true,
  "risk_score": 10
}
```

### 3. Component Analyzer

**Module**: `src/modules/component_analyzer.py` (new)

#### Analyse Complète des Composants :

##### Activities
- ✅ Activités exportées (accessibles par autres apps)
- ✅ Intent filters détaillés
- ✅ Permissions requises
- ✅ Détection d'activités suspectes (WebView, proxy, hidden)

##### Services
- ✅ Services exportés (risque élevé)
- ✅ Services foreground
- ✅ Détection de patterns malveillants (accessibility, admin, spy)

##### Broadcast Receivers
- ✅ Receivers exportés
- ✅ Intent filters (BOOT_COMPLETED, SMS_RECEIVED, etc.)
- ✅ Priorité des receivers
- ✅ Détection d'écoute d'événements sensibles

##### Content Providers
- ✅ Providers exportés (risque de fuite de données)
- ✅ Authorities
- ✅ Grant URI permissions
- ✅ Permissions de lecture/écriture

##### Deep Links & URL Schemes
- ✅ Extraction de tous les deep links
- ✅ Schemes personnalisés
- ✅ Hosts et paths
- ✅ Détection de patterns trop larges (wildcards)

##### Custom Permissions
- ✅ Permissions définies par l'app
- ✅ Niveaux de protection
- ✅ Permissions signature/system

### 4. Anti-Analysis Detection

**Module**: `src/modules/static_analyzer.py` (enhanced)

#### Techniques Détectées :

##### Anti-Debugging
```python
- Debug.isDebuggerConnected()
- TracerPid (via /proc/self/status)
- ptrace anti-debugging
- JDWP detection
- BuildConfig.DEBUG check
- ApplicationInfo.FLAG_DEBUGGABLE
```

##### Emulator Detection
```python
- Build.FINGERPRINT check
- "generic" device check
- "goldfish" emulator
- "sdk_phone" detection
- VirtualBox detection
- QEMU detection
- Genymotion detection
```

##### Root Detection
```python
- /system/app/Superuser.apk
- /system/xbin/su
- SuperSU packages
- Magisk detection
- test-keys detection
```

### 5. Packing & Obfuscation Detection

**Module**: `src/modules/static_analyzer.py` (enhanced)

#### Packers Détectés :
- 🔒 **Qihoo 360 Jiagu**
- 🔒 **Bangcle/SecNeo**
- 🔒 **Ijiami**
- 🔒 **APKProtect**
- 🔒 **DexProtector**
- 🔒 **Allatori**
- 🔒 **ProGuard**
- 🔒 **DexGuard**

#### Indicateurs d'Obfuscation :
- Strings encodées (Base64/Hex en masse)
- Multiples fichiers DEX (>2)
- Nombre excessif de bibliothèques natives (>10)
- Signatures de packers connues

### 6. Data Exfiltration Detection

**Module**: `src/modules/static_analyzer.py` (enhanced)

#### Patterns de Collecte de Données :
```python
getDeviceId()              # IMEI collection
getSubscriberId()          # IMSI collection
getSimSerialNumber()       # SIM serial
getLine1Number()           # Numéro de téléphone
getLastKnownLocation()     # Position GPS
getAllByName()             # Résolution DNS (C&C)
ContentResolver.query()    # Données privées
getInstalledPackages()     # Apps installées
getAccounts()              # Comptes utilisateur
getCellLocation()          # Position antenne
```

#### Critère d'Exfiltration :
**Collecte de données sensibles + Capacité réseau = CRITICAL**

## 📊 Scoring Amélioré

### Threat Score Calculation

Le score de menace est maintenant calculé sur plusieurs dimensions :

| Composant | Points Max | Critères |
|-----------|------------|----------|
| Permissions | 25 | Permissions dangereuses, sur-privilèges |
| Composants | 25 | Composants exportés, receivers critiques |
| Code statique | 30 | Strings suspectes, dynamic loading, natives |
| Obfuscation | 20 | Packing, anti-analyse, obfuscation |
| JADX | 30 | Secrets, APIs dangereuses, complexité |
| Exfiltration | 20 | Patterns de collecte + réseau |

**Total : Score normalisé 0-100**

### Niveaux de Risque :

| Score | Niveau | Description |
|-------|--------|-------------|
| 0-20 | ✅ SAFE | Application sécurisée |
| 21-40 | ⚠️ LOW | Risque faible, à surveiller |
| 41-60 | 🟠 MEDIUM | Risque moyen, analyse approfondie recommandée |
| 61-80 | 🔴 HIGH | Risque élevé, comportements suspects |
| 81-100 | ☠️ CRITICAL | Malware probable, blocage recommandé |

## 🚀 Utilisation

### Mode Standard (avec JADX)
```bash
# Analyse complète avec décompilation JADX
poetry run python src/androsleuth.py --apk samples/app.apk --mode deep

# Timeout JADX personnalisé (défaut: 300s)
poetry run python src/androsleuth.py --apk samples/app.apk --jadx-timeout 600
```

### Mode Sans JADX
```bash
# Si JADX n'est pas installé, l'analyse continue sans décompilation
poetry run python src/androsleuth.py --apk samples/app.apk --mode standard
```

### Rapports Générés

Les rapports incluent maintenant :
- **Permissions Matrix** : Tableau détaillé des permissions
- **Component Analysis** : Graphique des composants exportés
- **Anti-Analysis** : Liste des techniques détectées
- **JADX Results** : Secrets, APIs, obfuscation
- **Exfiltration Patterns** : Indicateurs de fuite de données

## 📈 Exemples de Résultats

### App Légitime (F-Droid)
```
Threat Score: 18/100 (SAFE)
- Permissions: 4 dangerous (LOW)
- Exported Components: 1 (Activity principale)
- Anti-Analysis: None
- JADX: No secrets, standard APIs
- Obfuscation: None
```

### App Suspecte
```
Threat Score: 72/100 (HIGH)
- Permissions: 12 dangerous (CRITICAL) - SMS+Location+Camera
- Exported Components: 8 (4 services, 3 receivers)
- Anti-Analysis: 5 techniques (debug, emulator, root)
- JADX: 3 API keys, DexClassLoader usage
- Obfuscation: ProGuard detected
- Exfiltration: getDeviceId + network
```

### Malware Confirmé
```
Threat Score: 94/100 (CRITICAL)
- Permissions: 18 dangerous (CRITICAL) - Over-privileged
- Exported Components: 12 (suspicious patterns)
- Anti-Analysis: 8 techniques (full suite)
- JADX: Private keys, C&C URLs, Runtime.exec
- Obfuscation: Jiagu packer detected
- Exfiltration: CRITICAL - SMS+Location+Contacts → Network
```

## 🔧 Configuration

### config/config.yaml

Ajoutez les sections suivantes :

```yaml
# JADX Configuration
jadx:
  enabled: true
  timeout: 300  # seconds
  deobfuscate: true
  skip_resources: true
  threads: 4

# Advanced Analysis
advanced:
  detect_anti_analysis: true
  detect_packing: true
  detect_exfiltration: true
  permission_matrix: true
  component_deep_scan: true

# Thresholds
thresholds:
  max_permissions: 15
  max_exported_components: 5
  obfuscation_threshold: 30
  exfiltration_threshold: 3
```

## 🧪 Tests

### Test des Nouveaux Modules
```bash
# Test JADX
pytest tests/test_jadx.py -v

# Test Component Analyzer
pytest tests/test_components.py -v

# Test Advanced Permissions
pytest tests/test_permissions.py -v

# Test complet
pytest tests/ -v --cov=src/modules
```

### Validation Manuelle
```bash
# Test avec APK malveillant connu
poetry run python src/androsleuth.py --apk samples/malware_sample.apk

# Comparaison avec/sans JADX
poetry run python src/androsleuth.py --apk samples/app.apk --no-jadx
poetry run python src/androsleuth.py --apk samples/app.apk --jadx
```

## 📚 Références

### JADX
- GitHub: https://github.com/skylot/jadx
- Documentation: https://github.com/skylot/jadx/wiki
- API: https://github.com/skylot/jadx/wiki/jadx-lib-usage

### Android Permissions
- Android Docs: https://developer.android.com/guide/topics/permissions/overview
- Runtime Permissions: https://developer.android.com/training/permissions/requesting
- Protection Levels: https://developer.android.com/reference/android/content/pm/PermissionInfo

### Component Security
- Android Components: https://developer.android.com/guide/components/fundamentals
- Exported Components: https://developer.android.com/guide/topics/manifest/activity-element#exported
- Deep Links: https://developer.android.com/training/app-links

### Anti-Analysis
- Evasion Techniques: https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05j-testing-resiliency-against-reverse-engineering
- OWASP MSTG: https://github.com/OWASP/owasp-mstg

## 🤝 Contribution

Pour contribuer à l'analyse statique avancée :

1. Fork le projet
2. Créer une branche (`git checkout -b feature/amazing-detection`)
3. Ajouter vos patterns/détections
4. Tester avec APKs malveillants connus
5. Commit (`git commit -m 'Add amazing detection'`)
6. Push (`git push origin feature/amazing-detection`)
7. Ouvrir une Pull Request

## 📝 Changelog

### v1.1.0 (2025-11-27)
- ✨ Added JADX integration for Java decompilation
- ✨ Advanced permission analysis with matrix
- ✨ Component analyzer (deep links, custom perms)
- ✨ Anti-analysis detection (debug, emulator, root)
- ✨ Packing & obfuscation detection (8 packers)
- ✨ Data exfiltration pattern detection
- 🐛 Fixed permission categorization
- 📚 Enhanced documentation

---

**Made with ❤️ for Android Security Research**
