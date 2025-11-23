# Guide d'utilisation de Frida avec AndroSleuth

## ✅ Ce qui fonctionne parfaitement

### 1. Analyse Statique (Sans Frida)
Tous les modules d'analyse statique sont **100% opérationnels** :

```bash
# Quick mode (8 secondes)
docker exec AndroSleuth poetry run androsleuth -a samples/fdroid.apk -m quick -f json

# Standard mode (12 secondes)  
docker exec AndroSleuth poetry run androsleuth -a samples/fdroid.apk -m standard -f json

# Deep mode avec PDF (15 secondes)
docker exec AndroSleuth poetry run androsleuth -a samples/fdroid.apk -m deep -f pdf

# Tous les formats
docker exec AndroSleuth poetry run androsleuth -a samples/fdroid.apk -m deep -f all
```

**Modules fonctionnels :**
- ✅ APK Ingestion & Validation
- ✅ Manifest Analysis (permissions, composants)
- ✅ Obfuscation Detection (ProGuard, packers, entropie)
- ✅ Static Code Analysis (strings suspects, crypto, network)
- ✅ Shellcode Detection (bibliothèques natives)
- ✅ YARA Malware Scanning (13 règles, 0 erreur)
- ✅ Report Generation (JSON, HTML, PDF)
- ✅ Threat Scoring (0-100)

**Résultats F-Droid :**
- Score: 20.2/100 (SAFE)
- Aucun malware détecté
- 2 permissions dangereuses (LOW risk)
- Rapports générés: JSON (1.7 MB), HTML (13 KB), PDF (73 KB)

---

## 🔧 Configuration Frida (En cours)

### État actuel

**✅ RÉUSSI :**
1. Module KVM chargé (`kvm-intel`)
2. `/dev/kvm` accessible (permissions 666)
3. Émulateur Android démarré avec KVM
4. Device détecté: `emulator-5554` (API 36, Android 16)
5. frida-server 17.5.1 téléchargé et installé
6. AndroSleuth détecte l'émulateur

**⚠️ BLOQUEUR ACTUEL :**
- L'émulateur API 36 n'a pas les privilèges root par défaut
- frida-server nécessite root pour instrumenter les applications
- SELinux bloque l'exécution avec permissions limitées

### Solutions possibles

#### Option A: Utiliser un AVD Rooté (Recommandé)

Créer un AVD avec une image Google APIs (pas Google Play) :

```bash
# Lister les images disponibles
sdkmanager --list | grep "system-images"

# Télécharger une image rootable (API 30 recommandé)
sdkmanager "system-images;android-30;google_apis;x86_64"

# Créer l'AVD
avdmanager create avd \
  -n "Rootable_API_30" \
  -k "system-images;android-30;google_apis;x86_64" \
  -d pixel_3a

# Démarrer l'AVD
emulator -avd Rootable_API_30 -no-snapshot-load -writable-system &

# Une fois démarré, activer root
adb root
adb remount

# Installer frida-server
adb push /tmp/frida-server /system/xbin/frida-server
adb shell "chmod 755 /system/xbin/frida-server"
adb shell "/system/xbin/frida-server &"

# Tester la connexion
poetry run python -c "import frida; print(frida.get_usb_device())"
```

#### Option B: Appareil Physique (Le plus simple)

1. **Prérequis :**
   - Téléphone Android avec USB Debugging activé
   - Téléphone rooté (Magisk recommandé)

2. **Installation :**

```bash
# Connecter le téléphone via USB
adb devices

# Vérifier root
adb shell "su -c 'id'"

# Télécharger frida-server (adapter l'architecture)
# Pour ARM64:
curl -L -o frida-server.xz \
  https://github.com/frida/frida/releases/download/17.5.1/frida-server-17.5.1-android-arm64.xz
xz -d frida-server.xz

# Installer
adb push frida-server /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

3. **Utilisation :**

```bash
# Lancer l'analyse avec Frida
poetry run androsleuth -a samples/fdroid.apk --frida --duration 120 -f pdf
```

#### Option C: Genymotion (Alternative commerciale)

```bash
# Télécharger Genymotion (gratuit pour usage personnel)
# https://www.genymotion.com/download/

# Créer un appareil virtuel avec Genymotion
# Les appareils Genymotion ont root par défaut

# Connecter via ADB
adb connect 192.168.56.101:5555

# Installer frida-server
# (mêmes commandes que ci-dessus)
```

---

## 📋 Commandes de test

### Test Frida (sans app)
```bash
# Vérifier la connexion
poetry run python -c "import frida; print(frida.get_usb_device())"

# Lister les processus
poetry run frida-ps -U

# Tester un hook simple
poetry run frida -U -n com.android.settings -l frida_scripts/crypto_hooks.js
```

### Analyse complète avec Frida
```bash
# Test rapide (60 secondes)
poetry run androsleuth -a samples/fdroid.apk --frida --duration 60 -f json

# Analyse approfondie (120 secondes, PDF)
poetry run androsleuth -a samples/fdroid.apk --frida --duration 120 -f pdf -m deep

# Mode verbose
poetry run androsleuth -a samples/fdroid.apk --frida --duration 90 -v -f all
```

### Hooks Frida disponibles

**1. Crypto Hooks** (`frida_scripts/crypto_hooks.js`) :
- Cipher (AES, DES, RSA)
- MessageDigest (SHA, MD5)
- SecretKeySpec
- KeyGenerator
- Base64 encode/decode

**2. Network Hooks** (`frida_scripts/network_hooks.js`) :
- URL connections
- HttpURLConnection
- OkHttpClient
- Socket operations
- WebView
- DNS queries

**3. File Hooks** (`frida_scripts/file_hooks.js`) :
- FileInputStream/OutputStream
- SharedPreferences
- SQLite operations
- ContentProvider queries

---

## 🎯 Résultats attendus avec Frida

Lorsque Frida est opérationnel, l'analyse capture :

### Crypto Operations
```json
{
  "crypto_operations": [
    {
      "timestamp": "2025-11-23T20:05:52.123",
      "operation": "Cipher.init",
      "algorithm": "AES/CBC/PKCS5Padding",
      "mode": "ENCRYPT_MODE",
      "key_size": 256
    }
  ]
}
```

### Network Requests
```json
{
  "network_activity": [
    {
      "timestamp": "2025-11-23T20:05:53.456",
      "method": "GET",
      "url": "https://api.example.com/data",
      "headers": {"User-Agent": "..."},
      "response_code": 200
    }
  ]
}
```

### File Operations
```json
{
  "file_operations": [
    {
      "timestamp": "2025-11-23T20:05:54.789",
      "operation": "FileOutputStream",
      "path": "/data/data/org.fdroid.fdroid/files/config.xml",
      "mode": "write"
    }
  ]
}
```

---

## 📊 Statistiques actuelles

### Analyse statique uniquement
```
✅ Tests réussis: 4/4 modes
✅ Modules fonctionnels: 8/8
✅ Formats de rapport: 3/3 (JSON, HTML, PDF)
✅ Performance: 8-18 secondes selon le mode
✅ YARA: 13 règles compilées, 0 erreur
```

### Avec Frida (après configuration)
```
Fonctionnalités additionnelles:
  - Monitoring temps réel des API calls
  - Détection de comportements cachés
  - Capture des flux réseau chiffrés
  - Analyse des opérations cryptographiques
  - Traçage des accès fichiers sensibles
```

---

## 🚀 Prochaines étapes

1. **Court terme (recommandé) :**
   - Utiliser un appareil physique rooté pour tests Frida
   - Documenter un cas d'usage complet avec malware réel
   - Créer des rapports d'exemple avec section Frida

2. **Moyen terme :**
   - Créer un AVD API 30 avec Google APIs (rootable)
   - Automatiser le setup Frida dans Docker
   - Ajouter plus de hooks (IPC, broadcasts, services)

3. **Long terme :**
   - Support Frida-based sandboxing
   - Détection automatique de comportements malveillants
   - Machine learning sur les patterns Frida

---

## 📝 Notes importantes

- **L'analyse statique est déjà très complète** (8 modules, 13 règles YARA)
- Frida est un **bonus** pour détecter les comportements runtime cachés
- Pour 90% des cas, l'analyse statique suffit
- Frida est critique pour :
  - Malware sophistiqué avec anti-analyse
  - Apps avec chargement dynamique de code
  - Trojans bancaires
  - Spyware avancé

---

## 📚 Ressources

- Frida Documentation: https://frida.re/docs/
- Frida CodeShare: https://codeshare.frida.re/
- AndroSleuth Issues: https://github.com/NatsuGwada/Shellcode_Forensic_Android/issues
- YARA Rules: https://github.com/Yara-Rules/rules

---

**Dernière mise à jour:** 23 novembre 2025  
**Version AndroSleuth:** 1.0.0  
**Version Frida:** 17.5.1  
**Statut:** Analyse statique opérationnelle ✅ | Frida en configuration ⚙️
