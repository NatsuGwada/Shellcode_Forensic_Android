# Guide d'Analyse avec un Appareil Android Physique

Guide complet pour configurer un appareil Android physique et réaliser une analyse forensique approfondie avec AndroSleuth.

## Table des matières

- [Prérequis](#prérequis)
- [Configuration de l'appareil Android](#configuration-de-lappareil-android)
- [Configuration de l'environnement de développement](#configuration-de-lenvironnement-de-développement)
- [Installation et configuration d'ADB](#installation-et-configuration-dadb)
- [Vérification de la connexion](#vérification-de-la-connexion)
- [Installation de Frida sur l'appareil](#installation-de-frida-sur-lappareil)
- [Analyse en mode Deep](#analyse-en-mode-deep)
- [Dépannage](#dépannage)
- [Bonnes pratiques de sécurité](#bonnes-pratiques-de-sécurité)

---

## Prérequis

### Matériel requis
- **Appareil Android physique** (téléphone ou tablette)
  - Android 5.0 (API 21) minimum
  - Android 7.0+ (API 24+) recommandé pour Frida
  - **Rooté de préférence** pour l'analyse Frida complète
  - Au moins 2 GB de stockage libre
- **Câble USB** compatible données (pas uniquement charge)
- **Ordinateur** sous Linux/macOS/Windows avec:
  - Python 3.8+
  - Au moins 4 GB RAM
  - 10 GB d'espace disque libre

### Logiciels requis
- AndroSleuth (ce projet)
- Android SDK Platform Tools (ADB)
- Frida (pour l'analyse dynamique)
- USB Drivers (Windows uniquement)

---

## Configuration de l'appareil Android

### 1. Activer le Mode Développeur

1. Ouvrez **Paramètres** → **À propos du téléphone**
2. Appuyez **7 fois** sur **Numéro de build** (ou **Version MIUI** sur Xiaomi)
3. Message: "Vous êtes maintenant développeur !"

### 2. Activer le Débogage USB

1. Retournez à **Paramètres** → **Options pour les développeurs**
2. Activez **Débogage USB**
3. *(Recommandé)* Activez **Rester activé** (évite le verrouillage pendant l'analyse)
4. *(Optionnel)* Activez **Débogage USB (Paramètres de sécurité)** si disponible

### 3. Configuration avancée (Optionnel mais recommandé)

Pour une analyse plus approfondie:

1. **Activer l'installation depuis USB**
   - Options développeurs → **Installation via USB** ✅

2. **Désactiver les optimisations**
   - Options développeurs → **Ne pas conserver les activités** ✅
   - Cela aide à analyser le comportement réel des apps

3. **Autoriser les applications de sources inconnues** (pour Frida)
   - Paramètres → Sécurité → **Sources inconnues** ✅

### 4. Configuration du réseau (Pour l'analyse réseau)

1. Connectez l'appareil au **même réseau WiFi** que votre ordinateur
2. Notez l'adresse IP de l'appareil:
   - Paramètres → À propos → État → **Adresse IP**
   - Ou via ADB: `adb shell ip addr show wlan0`

---

## Configuration de l'environnement de développement

### Installation d'ADB (Android Debug Bridge)

#### Sur Linux (Ubuntu/Debian)

```bash
# Méthode 1: Via APT (version système)
sudo apt update
sudo apt install android-tools-adb android-tools-fastboot

# Méthode 2: SDK Platform Tools complet (recommandé)
cd ~/Downloads
wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip
unzip platform-tools-latest-linux.zip
sudo mv platform-tools /opt/
echo 'export PATH=$PATH:/opt/platform-tools' >> ~/.bashrc
source ~/.bashrc
```

#### Sur macOS

```bash
# Via Homebrew
brew install android-platform-tools

# Ou téléchargement direct
cd ~/Downloads
curl -O https://dl.google.com/android/repository/platform-tools-latest-darwin.zip
unzip platform-tools-latest-darwin.zip
sudo mv platform-tools /usr/local/
echo 'export PATH=$PATH:/usr/local/platform-tools' >> ~/.zshrc
source ~/.zshrc
```

#### Sur Windows

1. Téléchargez [SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)
2. Extrayez dans `C:\platform-tools\`
3. Ajoutez au PATH:
   - Panneau de configuration → Système → Paramètres système avancés
   - Variables d'environnement → PATH → Nouveau
   - Ajoutez: `C:\platform-tools`

### Configuration des règles udev (Linux uniquement)

Pour permettre à ADB de communiquer sans sudo:

```bash
# Créer le fichier de règles udev
sudo nano /etc/udev/rules.d/51-android.rules

# Ajoutez ces lignes (adaptez VENDOR_ID si nécessaire):
# Google Nexus/Pixel
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666", GROUP="plugdev"
# Samsung
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
# HTC
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666", GROUP="plugdev"
# Motorola
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev"
# Xiaomi
SUBSYSTEM=="usb", ATTR{idVendor}=="2717", MODE="0666", GROUP="plugdev"
# OnePlus
SUBSYSTEM=="usb", ATTR{idVendor}=="2a70", MODE="0666", GROUP="plugdev"
# Huawei
SUBSYSTEM=="usb", ATTR{idVendor}=="12d1", MODE="0666", GROUP="plugdev"

# Sauvegarder et appliquer
sudo chmod a+r /etc/udev/rules.d/51-android.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Ajoutez votre utilisateur au groupe plugdev:
```bash
sudo usermod -aG plugdev $USER
```

**⚠️ Déconnectez-vous et reconnectez-vous** pour que les changements prennent effet.

---

## Vérification de la connexion

### 1. Connexion physique via USB

```bash
# Connectez l'appareil via USB
# Vérifiez qu'ADB détecte l'appareil
adb devices
```

**Résultat attendu:**
```
List of devices attached
ABC123XYZ    device
```

Si vous voyez `unauthorized`, déverrouillez votre téléphone et acceptez la demande d'autorisation ADB.

### 2. Test de communication

```bash
# Informations sur l'appareil
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release

# Shell interactif
adb shell
# Vous devriez voir: shell@device:/ $
```

### 3. Connexion sans fil (Optionnel)

Utile pour éviter les problèmes de câble:

```bash
# 1. Connectez d'abord via USB
adb devices

# 2. Activez le mode TCP/IP sur le port 5555
adb tcpip 5555

# 3. Trouvez l'IP de l'appareil
adb shell ip addr show wlan0 | grep inet

# 4. Connectez-vous via WiFi (remplacez par votre IP)
adb connect 192.168.1.100:5555

# 5. Vérifiez la connexion
adb devices
# Vous devriez voir: 192.168.1.100:5555    device

# 6. Déconnectez le câble USB (optionnel)

# Pour revenir en USB:
adb usb
```

---

## Installation de Frida sur l'appareil

Frida est essentiel pour l'analyse dynamique en mode deep.

### 1. Vérifier l'architecture de l'appareil

```bash
adb shell getprop ro.product.cpu.abi
```

Résultats possibles:
- `arm64-v8a` → Architecture 64-bit ARM (la plus courante)
- `armeabi-v7a` → Architecture 32-bit ARM
- `x86_64` → Intel 64-bit (rare, émulateurs)
- `x86` → Intel 32-bit (rare)

### 2. Télécharger Frida Server

Visitez [Frida Releases](https://github.com/frida/frida/releases) et téléchargez la version correspondante:

```bash
# Exemple pour ARM64 (adaptez la version et l'architecture)
cd ~/Downloads
wget https://github.com/frida/frida/releases/download/16.5.2/frida-server-16.5.2-android-arm64.xz
unxz frida-server-16.5.2-android-arm64.xz
mv frida-server-16.5.2-android-arm64 frida-server
chmod +x frida-server
```

### 3. Installation sur l'appareil

#### Option A: Appareil rooté (recommandé)

```bash
# Push frida-server sur l'appareil
adb push frida-server /data/local/tmp/

# Rendre exécutable
adb shell "chmod 755 /data/local/tmp/frida-server"

# Démarrer en root
adb shell "su -c '/data/local/tmp/frida-server &'"
```

#### Option B: Appareil non-rooté (limité)

Pour les appareils non-rootés, Frida ne peut analyser que les apps debuggables:

```bash
# Push frida-server
adb push frida-server /data/local/tmp/

# Rendre exécutable
adb shell "chmod 755 /data/local/tmp/frida-server"

# Démarrer (sans root)
adb shell "/data/local/tmp/frida-server &"
```

⚠️ **Limitations sans root:**
- Analyse limitée aux apps en mode debug uniquement
- Pas d'accès aux processus système
- Certaines protections anti-analyse ne peuvent pas être contournées

### 4. Vérification de l'installation Frida

```bash
# Installer frida-tools sur votre PC
pip install frida-tools

# Vérifier la connexion
frida-ps -U
```

**Résultat attendu:** Liste des processus en cours d'exécution sur l'appareil.

### 5. Automatiser le démarrage de Frida (Root uniquement)

Créez un script pour démarrer automatiquement:

```bash
# Script de démarrage
cat > start_frida.sh << 'EOF'
#!/bin/bash
adb shell "su -c 'killall frida-server 2>/dev/null'"
adb shell "su -c '/data/local/tmp/frida-server &'"
sleep 2
frida-ps -U
EOF

chmod +x start_frida.sh
./start_frida.sh
```

---

## Analyse en mode Deep

### 1. Installation de l'APK sur l'appareil

```bash
# Installer l'APK à analyser
adb install chemin/vers/votre/app.apk

# Ou forcer la réinstallation
adb install -r chemin/vers/votre/app.apk

# Vérifier l'installation
adb shell pm list packages | grep nom.du.package
```

### 2. Lancement d'une analyse complète en mode Deep

#### Analyse Deep avec Frida (Appareil rooté)

```bash
# S'assurer que Frida tourne sur l'appareil
frida-ps -U

# Lancer l'analyse complète
poetry run python -m src.androsleuth \
  -a chemin/vers/app.apk \
  -m deep \
  --frida \
  --device <DEVICE_ID> \
  -o reports/deep_analysis \
  -v
```

**Paramètres importants:**
- `-m deep` : Mode d'analyse le plus complet
- `--frida` : Active l'analyse dynamique avec Frida
- `--device <DEVICE_ID>` : ID de l'appareil (obtenu via `adb devices`)
- `--duration 300` : Durée de l'analyse Frida en secondes (défaut: 60s)
- `-v` : Mode verbose pour voir les logs détaillés

#### Exemple complet avec tous les modules

```bash
poetry run python -m src.androsleuth \
  -a malware_suspect.apk \
  -m deep \
  --frida \
  --device ABC123XYZ \
  --duration 300 \
  -o reports/full_forensic_analysis \
  --all-modules \
  -v
```

#### Analyse sans Frida (mode statique uniquement)

Si Frida n'est pas disponible ou l'appareil non-rooté:

```bash
poetry run python -m src.androsleuth \
  -a app.apk \
  -m deep \
  -o reports/static_deep_analysis \
  -v
```

### 3. Analyse ciblée avec Frida

Pour une analyse Frida spécifique d'une app déjà installée:

```bash
# Méthode 1: Via le nom du package
poetry run python -m src.androsleuth \
  -a app.apk \
  -m standard \
  --frida \
  --device ABC123XYZ \
  --duration 180 \
  -o reports/frida_analysis

# Méthode 2: Test Frida direct
cd frida_scripts
frida -U -f com.exemple.app -l network_hooks.js
```

### 4. Analyse comportementale en temps réel

Pour capturer le comportement pendant l'utilisation:

```bash
# Terminal 1: Démarrer Frida server
adb shell "su -c '/data/local/tmp/frida-server &'"

# Terminal 2: Lancer l'analyse avec longue durée
poetry run python -m src.androsleuth \
  -a app.apk \
  -m deep \
  --frida \
  --device ABC123XYZ \
  --duration 600 \
  -o reports/behavioral_analysis \
  -v

# Terminal 3: Utilisez l'app sur l'appareil
# → Interagissez avec l'app pendant que Frida capture les actions
```

### 5. Modules d'analyse disponibles en mode Deep

| Module | Description | Nécessite Frida |
|--------|-------------|-----------------|
| **Manifest Analysis** | Permissions, composants, anomalies | Non |
| **Static Analysis** | Strings suspectes, API dangereuses | Non |
| **Obfuscation Detection** | Détection de code obfusqué | Non |
| **Shellcode Detection** | Recherche de shellcode natif | Non |
| **YARA Scanning** | Signatures de malware | Non |
| **VirusTotal Check** | Réputation en ligne | Non (API key) |
| **Frida Dynamic Analysis** | Hooks réseau, crypto, fichiers | **Oui** ✅ |
| **Emulation** | Exécution sandboxée (Unicorn) | Non |

### 6. Scripts Frida personnalisés

AndroSleuth utilise des scripts Frida prédéfinis dans `frida_scripts/`:

```bash
# Voir les scripts disponibles
ls -la frida_scripts/

# Scripts inclus:
# - network_hooks.js : Capture des connexions réseau
# - crypto_hooks.js : Interception des opérations cryptographiques
# - file_hooks.js : Surveillance des accès fichiers
```

Pour ajouter vos propres scripts:

1. Créez un fichier `.js` dans `frida_scripts/`
2. AndroSleuth le chargera automatiquement

---

## Dépannage

### Problème: "adb: device unauthorized"

**Solution:**
1. Déverrouillez l'appareil
2. Acceptez la fenêtre pop-up "Autoriser le débogage USB"
3. Cochez "Toujours autoriser depuis cet ordinateur"
4. Relancez: `adb kill-server && adb devices`

### Problème: "adb: device offline"

**Solutions:**
```bash
# Redémarrer ADB
adb kill-server
adb start-server
adb devices

# Redémarrer l'appareil
adb reboot

# Changer de câble USB
# Essayer un autre port USB
```

### Problème: "Frida: unable to connect to remote frida-server"

**Solutions:**
```bash
# 1. Vérifier que frida-server tourne
adb shell "ps | grep frida-server"

# 2. Redémarrer frida-server
adb shell "su -c 'killall frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

# 3. Vérifier la version Frida
frida --version
# Sur l'appareil:
adb shell "/data/local/tmp/frida-server --version"
# → Les versions doivent correspondre !

# 4. Port forwarding si nécessaire
adb forward tcp:27042 tcp:27042
```

### Problème: "Permission denied" lors de l'installation APK

**Solutions:**
```bash
# 1. Activer l'installation depuis USB dans les options développeur

# 2. Désinstaller l'ancienne version
adb uninstall com.package.name

# 3. Forcer la réinstallation
adb install -r -d app.apk

# 4. Si l'app est système (root requis)
adb shell "su -c 'pm uninstall com.package.name'"
```

### Problème: Analyse Frida lente ou qui bloque

**Solutions:**
1. Réduire la durée: `--duration 60`
2. Fermer les apps en arrière-plan sur l'appareil
3. Augmenter la RAM disponible (fermer apps PC)
4. Vérifier l'espace disque sur l'appareil: `adb shell df -h`

### Problème: Certificat SSL/TLS dans Frida

Pour intercepter le trafic HTTPS:

```bash
# Installer le certificat Burp/mitmproxy sur l'appareil
adb push cacert.pem /sdcard/
# Puis: Paramètres → Sécurité → Installer depuis stockage
```

---

## Bonnes pratiques de sécurité

### 1. Isolation de l'appareil d'analyse

⚠️ **N'utilisez JAMAIS votre téléphone personnel pour l'analyse de malware !**

- Utilisez un appareil dédié à l'analyse
- Effectuez un reset factory après chaque analyse suspecte
- Désactivez la synchronisation cloud (Google, Samsung, etc.)

### 2. Réseau isolé

```bash
# Créer un réseau WiFi isolé ou utiliser:
# - Mode avion + USB uniquement
# - Réseau virtuel sans accès Internet
# - VPN/Tunnel pour isoler le trafic

# Désactiver les données mobiles
adb shell "svc data disable"

# Désactiver le WiFi
adb shell "svc wifi disable"
```

### 3. Snapshot et sauvegarde

Avant chaque analyse:

```bash
# Backup complet de l'appareil
adb backup -all -f backup_avant_analyse.ab

# Restaurer si nécessaire
adb restore backup_avant_analyse.ab
```

### 4. Environnement virtuel Python

```bash
# Toujours utiliser un environnement virtuel
poetry install
poetry shell

# Ou avec venv:
python -m venv venv_androsleuth
source venv_androsleuth/bin/activate
pip install -r requirements.txt
```

### 5. Logs et preuves forensiques

Conservez tous les logs pour l'analyse légale:

```bash
# Capturer tous les logs système pendant l'analyse
adb logcat -v time > logs/logcat_$(date +%Y%m%d_%H%M%S).log &

# Générer le rapport complet
poetry run python -m src.androsleuth \
  -a suspect.apk \
  -m deep \
  --frida \
  -f all \
  -o reports/case_001_forensic
```

---

## Exemples d'utilisation avancée

### Analyse d'un APK malveillant complet

```bash
#!/bin/bash
# Script d'analyse forensique complète

APK_PATH="samples/malware_suspect.apk"
DEVICE_ID=$(adb devices | grep -w "device" | awk '{print $1}' | head -1)
OUTPUT_DIR="reports/forensic_$(date +%Y%m%d_%H%M%S)"

# 1. Vérifier la connexion
echo "🔍 Vérification de l'appareil..."
adb devices -l

# 2. Démarrer Frida
echo "🚀 Démarrage de Frida Server..."
adb shell "su -c 'killall frida-server 2>/dev/null'"
adb shell "su -c '/data/local/tmp/frida-server &'"
sleep 3

# 3. Capturer logcat
echo "📝 Capture des logs système..."
adb logcat -c
adb logcat -v time > "$OUTPUT_DIR/system_logcat.log" &
LOGCAT_PID=$!

# 4. Lancer l'analyse
echo "🔬 Analyse en cours..."
poetry run python -m src.androsleuth \
  -a "$APK_PATH" \
  -m deep \
  --frida \
  --device "$DEVICE_ID" \
  --duration 300 \
  --all-modules \
  -f all \
  -o "$OUTPUT_DIR" \
  -v

# 5. Arrêter logcat
kill $LOGCAT_PID

# 6. Collecter les informations supplémentaires
echo "📊 Collecte des informations complémentaires..."
adb shell dumpsys package com.package.name > "$OUTPUT_DIR/dumpsys_package.txt"
adb shell dumpsys activity > "$OUTPUT_DIR/dumpsys_activity.txt"
adb shell pm list packages -f > "$OUTPUT_DIR/installed_packages.txt"

echo "✅ Analyse terminée ! Rapport dans: $OUTPUT_DIR"
```

### Monitoring réseau en temps réel

```bash
# Terminal 1: tcpdump sur l'appareil (root requis)
adb shell "su -c 'tcpdump -i wlan0 -s 0 -w /sdcard/capture.pcap'"

# Terminal 2: Lancer l'analyse Frida
poetry run python -m src.androsleuth \
  -a app.apk \
  --frida \
  --device ABC123XYZ \
  --duration 180

# Terminal 3: Récupérer la capture
adb pull /sdcard/capture.pcap reports/
wireshark reports/capture.pcap
```

---

## Ressources complémentaires

### Documentation officielle
- [ADB Documentation](https://developer.android.com/studio/command-line/adb)
- [Frida Documentation](https://frida.re/docs/home/)
- [AndroSleuth README](../README.md)

### Outils complémentaires
- **APKTool**: Décompilation APK
- **JADX**: Décompilateur Java
- **Burp Suite**: Proxy HTTPS
- **Wireshark**: Analyse réseau

### Communauté
- [Frida CodeShare](https://codeshare.frida.re/)
- [Android Security Reddit](https://www.reddit.com/r/androidappsec/)

---

## Support

Pour toute question ou problème:
1. Consultez la section [Dépannage](#dépannage)
2. Ouvrez une issue sur [GitHub](https://github.com/NatsuGwada/Shellcode_Forensic_Android/issues)
3. Consultez les logs avec `-v` pour plus de détails

---

**⚠️ Avertissement légal**: N'analysez que des applications dont vous avez le droit d'analyse. L'analyse d'applications tierces sans autorisation peut être illégale dans certaines juridictions.

**Créé par**: NatsuGwada  
**Version**: 1.0.0  
**Dernière mise à jour**: 10 décembre 2025
