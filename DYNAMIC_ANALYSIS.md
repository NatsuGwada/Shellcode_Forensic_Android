# AndroSleuth - Guide d'Analyse Dynamique avec Frida

## 🎯 Vue d'ensemble

L'analyse dynamique avec Frida permet d'observer le comportement réel d'une APK pendant son exécution, en interceptant les appels API critiques.

## 📋 Prérequis

### 1. Device Android ou Émulateur
```bash
# Vérifier les devices connectés
adb devices

# Devrait afficher quelque chose comme:
# List of devices attached
# emulator-5554   device
# ou
# 1A2B3C4D5E6F    device
```

### 2. frida-server sur le Device

#### Télécharger frida-server
```bash
# Identifier l'architecture du device
adb shell getprop ro.product.cpu.abi
# Réponse typique: arm64-v8a, armeabi-v7a, x86, x86_64

# Télécharger depuis https://github.com/frida/frida/releases
# Exemple pour arm64:
wget https://github.com/frida/frida/releases/download/16.1.10/frida-server-16.1.10-android-arm64.xz
xz -d frida-server-16.1.10-android-arm64.xz
mv frida-server-16.1.10-android-arm64 frida-server
```

#### Installer sur le Device
```bash
# Pousser sur le device
adb push frida-server /data/local/tmp/

# Rendre exécutable
adb shell "chmod 755 /data/local/tmp/frida-server"

# Lancer en arrière-plan
adb shell "/data/local/tmp/frida-server &"

# Vérifier que frida-server est lancé
adb shell "ps | grep frida-server"
```

#### Alternative: Avec root
```bash
# Si le device est rooté
adb root
adb push frida-server /system/xbin/
adb shell "chmod 755 /system/xbin/frida-server"
adb shell "/system/xbin/frida-server &"
```

### 3. Frida installé localement
```bash
# Avec Poetry
poetry add frida frida-tools

# Ou avec pip
pip install frida frida-tools

# Vérifier l'installation
frida --version
```

## 🚀 Utilisation

### Mode 1: Analyse avec Device Physique

```bash
# 1. Connecter le device via USB
adb devices

# 2. Lancer frida-server sur le device (voir prérequis)

# 3. Analyser l'APK
poetry run androsleuth \
  -a sample.apk \
  --frida \
  --duration 60 \
  -o reports/dynamic_analysis

# Avec mode deep pour analyse complète
poetry run androsleuth \
  -a sample.apk \
  -m deep \
  --frida \
  --duration 120 \
  -o reports/full_analysis
```

### Mode 2: Analyse avec Émulateur

```bash
# 1. Démarrer l'émulateur Android
emulator -avd test_device -no-snapshot

# 2. Vérifier la connexion
adb devices

# 3. Installer frida-server (x86_64 pour émulateur)
# Télécharger: frida-server-16.1.10-android-x86_64
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# 4. Analyser
poetry run androsleuth -a sample.apk --frida --duration 90
```

### Mode 3: Device Spécifique (Multi-device)

```bash
# Lister les devices
adb devices
# emulator-5554   device
# 1A2B3C4D5E6F    device

# Analyser sur device spécifique
poetry run androsleuth \
  -a sample.apk \
  --frida \
  --device emulator-5554 \
  --duration 60

# Ou par ID
poetry run androsleuth \
  -a sample.apk \
  --frida \
  --device 1A2B3C4D5E6F \
  --duration 60
```

### Mode 4: Dans Docker (avec ADB forward)

```bash
# 1. Forward ADB depuis l'hôte vers le container
docker run --privileged -v /dev/bus/usb:/dev/bus/usb \
  -v $(pwd)/samples:/opt/androsleuth/samples:ro \
  -v $(pwd)/reports:/opt/androsleuth/reports:rw \
  androsleuth:latest \
  poetry run androsleuth -a samples/sample.apk --frida

# 2. Ou utiliser adb over network
adb tcpip 5555
adb connect <device_ip>:5555

docker exec -it AndroSleuth \
  poetry run androsleuth -a samples/sample.apk --frida
```

## 🎣 APIs Interceptées

AndroSleuth surveille automatiquement 10+ catégories d'API :

### 1. Cryptographie
```java
javax.crypto.Cipher.getInstance()
javax.crypto.Cipher.init()
javax.crypto.Cipher.doFinal()
java.security.MessageDigest.getInstance()
java.security.MessageDigest.digest()
```

### 2. Réseau
```java
java.net.HttpURLConnection.connect()
java.net.HttpURLConnection.getInputStream()
java.net.URL.<init>()
okhttp3.OkHttpClient.newCall()
```

### 3. Fichiers
```java
java.io.FileOutputStream.write()
java.io.FileInputStream.read()
android.content.Context.openFileOutput()
android.content.Context.openFileInput()
```

### 4. Exécution de Commandes
```java
java.lang.Runtime.exec()
java.lang.ProcessBuilder.start()
```

### 5. SMS
```java
android.telephony.SmsManager.sendTextMessage()
android.telephony.SmsManager.sendMultipartTextMessage()
```

### 6. Localisation
```java
android.location.LocationManager.requestLocationUpdates()
android.location.LocationManager.getLastKnownLocation()
```

### 7. Chargement Dynamique
```java
dalvik.system.DexClassLoader.<init>()
dalvik.system.PathClassLoader.<init>()
java.lang.Class.forName()
```

### 8. SSL Pinning
```java
javax.net.ssl.TrustManager.checkServerTrusted()
okhttp3.CertificatePinner.check()
```

### 9. Système
```java
android.app.ActivityManager.getRunningServices()
android.app.ActivityManager.killBackgroundProcesses()
java.lang.System.exit()
```

### 10. Base de Données
```java
android.database.sqlite.SQLiteDatabase.execSQL()
android.database.sqlite.SQLiteDatabase.query()
```

## 📊 Résultats de l'Analyse

### Informations Capturées

```json
{
  "frida_analysis": {
    "duration_seconds": 60,
    "app_package": "com.example.app",
    "app_launched": true,
    "total_calls": 234,
    "categories": {
      "crypto": 45,
      "network": 89,
      "file": 56,
      "exec": 2,
      "sms": 0,
      "location": 12
    },
    "suspicious_behaviors": [
      {
        "type": "crypto",
        "method": "Cipher.getInstance",
        "args": ["AES/CBC/PKCS5Padding"],
        "timestamp": "2025-11-23T17:30:45"
      },
      {
        "type": "network",
        "method": "URL.init",
        "args": ["http://suspicious-domain.com/api"],
        "timestamp": "2025-11-23T17:30:47"
      }
    ],
    "threat_indicators": [
      "Multiple encryption operations detected",
      "Network communication to suspicious domain",
      "Attempted command execution"
    ]
  }
}
```

### Rapport PDF Inclut

- **Section Frida** dédiée avec:
  - Durée de monitoring
  - Nombre total d'appels interceptés
  - Graphique par catégorie d'API
  - Liste des comportements suspects
  - Indicateurs de menace détectés

## 🔧 Dépannage

### Problème 1: "Unable to connect to device"

```bash
# Vérifier que adb voit le device
adb devices

# Vérifier que frida-server est lancé
adb shell "ps | grep frida-server"

# Relancer frida-server si nécessaire
adb shell "pkill frida-server"
adb shell "/data/local/tmp/frida-server &"

# Tester avec frida-ps
frida-ps -U
```

### Problème 2: "App not found on device"

```bash
# L'APK n'est pas installée sur le device
# AndroSleuth va automatiquement l'installer

# Si installation échoue, installer manuellement:
adb install sample.apk

# Puis réessayer l'analyse
```

### Problème 3: "frida-server version mismatch"

```bash
# Vérifier les versions
frida --version        # Version locale: 16.1.10
adb shell "/data/local/tmp/frida-server --version"  # Version device

# Si différentes, télécharger la bonne version
# Les versions doivent correspondre!
```

### Problème 4: "Permission denied"

```bash
# frida-server nécessite des permissions root sur certains devices
# Utiliser un émulateur ou rooter le device

# Ou utiliser adb root si disponible
adb root
adb shell "/data/local/tmp/frida-server &"
```

### Problème 5: "Timeout waiting for app"

```bash
# L'app met trop de temps à démarrer
# Augmenter la durée d'analyse
poetry run androsleuth -a sample.apk --frida --duration 180

# Ou lancer l'app manuellement avant l'analyse
adb shell am start -n com.example.app/.MainActivity
poetry run androsleuth -a sample.apk --frida
```

## 📈 Exemples d'Analyse

### Exemple 1: Analyse Rapide (30 secondes)

```bash
poetry run androsleuth \
  -a malware.apk \
  --frida \
  --duration 30 \
  -f pdf \
  -o reports/quick_dynamic
```

**Cas d'usage**: Vérification rapide pour détecter comportements évidents

### Exemple 2: Analyse Approfondie (5 minutes)

```bash
poetry run androsleuth \
  -a suspicious.apk \
  -m deep \
  --emulation \
  --frida \
  --duration 300 \
  -f both \
  -o reports/deep_analysis
```

**Cas d'usage**: Investigation complète avec statique + dynamique + émulation

### Exemple 3: Monitoring Long (15 minutes)

```bash
poetry run androsleuth \
  -a banking_trojan.apk \
  --frida \
  --duration 900 \
  -v \
  -o reports/long_monitoring
```

**Cas d'usage**: Observer comportement sur durée prolongée (exfiltration de données)

### Exemple 4: Multi-device

```bash
# Analyser sur émulateur
poetry run androsleuth -a app1.apk --frida --device emulator-5554

# Analyser sur device physique
poetry run androsleuth -a app2.apk --frida --device 1A2B3C4D5E6F
```

**Cas d'usage**: Comparer comportement selon device/architecture

## 🛡️ Sécurité et Isolation

### Recommandations

1. **Utiliser un émulateur dédié**
   ```bash
   # Créer un AVD pour tests
   avdmanager create avd -n malware_test -k "system-images;android-30;google_apis;x86_64"
   
   # Démarrer sans réseau
   emulator -avd malware_test -no-snapshot -no-window
   ```

2. **Device physique isolé**
   - Sans carte SIM
   - Sans données personnelles
   - Rooté si possible
   - Restaurer après chaque analyse

3. **Network monitoring**
   ```bash
   # Capturer le trafic réseau pendant l'analyse
   adb shell tcpdump -i any -w /sdcard/capture.pcap &
   
   # Analyser avec AndroSleuth
   poetry run androsleuth -a sample.apk --frida
   
   # Récupérer la capture
   adb pull /sdcard/capture.pcap
   ```

4. **Snapshot/Restore**
   ```bash
   # Sauvegarder l'état avant analyse
   emulator -avd test_device -snapshot save_before
   
   # Analyser
   poetry run androsleuth -a malware.apk --frida
   
   # Restaurer après
   emulator -avd test_device -snapshot save_before
   ```

## 🎯 Performance

| Métrique | Valeur Typique |
|----------|----------------|
| Overhead CPU | +5-15% |
| Overhead Mémoire | +50-100 MB |
| Latence ajoutée | 1-5ms par appel |
| Appels interceptés/sec | 100-1000 |
| Durée recommandée | 60-300 secondes |

## 📝 Hooks Personnalisés

AndroSleuth supporte les hooks personnalisés via scripts Frida externes.

### Créer un Hook Personnalisé

```javascript
// custom_hook.js
Java.perform(function() {
    var MyClass = Java.use("com.example.MyClass");
    
    MyClass.sensitiveMethod.implementation = function(arg1, arg2) {
        console.log("[*] MyClass.sensitiveMethod called");
        console.log("    arg1: " + arg1);
        console.log("    arg2: " + arg2);
        
        var result = this.sensitiveMethod(arg1, arg2);
        
        console.log("    result: " + result);
        return result;
    };
});
```

### Utiliser avec AndroSleuth

```bash
# Placer le script dans frida_scripts/
cp custom_hook.js frida_scripts/

# AndroSleuth chargera automatiquement tous les scripts .js
poetry run androsleuth -a sample.apk --frida
```

## 🔍 Cas d'Usage Avancés

### 1. Détecter Exfiltration de Données

```bash
# Analyser pendant 10 minutes pour capturer transmissions
poetry run androsleuth \
  -a spyware.apk \
  --frida \
  --duration 600 \
  -v
  
# Chercher dans le rapport:
# - network: URL externes
# - file: Lectures de contacts/SMS
# - crypto: Chiffrement de données
```

### 2. Bypass Detection

```bash
# Certains malwares détectent Frida
# AndroSleuth utilise des techniques d'évasion automatiques:
# - Renommage de frida-server
# - Obfuscation des imports
# - Random delays

poetry run androsleuth -a anti_frida.apk --frida
```

### 3. Timeline d'Activité

```bash
# Mode verbose pour timeline détaillée
poetry run androsleuth -a sample.apk --frida --duration 120 -v > timeline.log

# Analyse du log:
grep "network" timeline.log    # Toutes les connexions réseau
grep "crypto" timeline.log     # Toutes les opérations crypto
grep "exec" timeline.log       # Toutes les exécutions de commandes
```

## ✅ Validation

Pour tester que Frida fonctionne correctement :

```bash
# Test 1: Lister les processus
frida-ps -U

# Test 2: Tracer une app
frida-trace -U -i "open*" com.android.settings

# Test 3: Analyser une app simple avec AndroSleuth
poetry run androsleuth -a samples/fdroid.apk --frida --duration 30
```

Si tous les tests passent, l'analyse dynamique est opérationnelle ! ✨

---

**Date**: 2025-11-23  
**Module**: frida_analyzer.py  
**Hooks**: 10+ catégories d'API  
**Statut**: ✅ Production Ready
