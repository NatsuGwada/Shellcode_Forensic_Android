#!/usr/bin/env bash

# Analyseur simple d'APK en bash
# Usage: ./apk_analyzer.sh monapp.apk

set -euo pipefail

# --- Vérifications de base ---
if [ "$#" -ne 1 ]; then
    echo "Usage : $0 fichier.apk"
    exit 1
fi

APK="$1"

if [ ! -f "$APK" ]; then
    echo "[X] Fichier introuvable : $APK"
    exit 1
fi

if [[ "$APK" != *.apk ]]; then
    echo "[!] Attention : l'extension n'est pas .apk (fichier : $APK)"
fi

echo "==============================="
echo "  ANALYSE APK : $APK"
echo "==============================="
echo

# --- Infos de base ---
echo "[+] Infos générales"
echo "    - Nom du fichier : $(basename "$APK")"
echo "    - Chemin complet : $(readlink -f "$APK" 2>/dev/null || realpath "$APK" 2>/dev/null || echo "$APK")"

if command -v stat >/dev/null 2>&1; then
    SIZE=$(stat -c "%s" "$APK" 2>/dev/null || stat -f "%z" "$APK" 2>/dev/null || echo "?")
    echo "    - Taille : $SIZE octets"
fi

if command -v sha256sum >/dev/null 2>&1; then
    echo "    - SHA256 : $(sha256sum "$APK" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    echo "    - SHA256 : $(shasum -a 256 "$APK" | awk '{print $1}')"
else
    echo "    - SHA256 : (sha256sum/shasum non disponible)"
fi

echo

# --- Structure du ZIP ---
echo "[+] Structure interne (ZIP)"
if command -v unzip >/dev/null 2>&1; then
    unzip -l "$APK" | sed '1,3d;$d' || echo "[X] Impossible de lister le contenu avec unzip"
else
    echo "[!] 'unzip' n'est pas installé, impossible de lister le contenu"
fi

echo

# --- Analyse avec aapt (si disponible) ---
if command -v aapt >/dev/null 2>&1; then
    echo "[+] Analyse avec aapt (Android SDK)"

    echo
    echo "  > dump badging (package, version, label, etc.)"
    aapt dump badging "$APK" 2>/dev/null | sed -n '1,20p' || echo "    [X] Erreur lors de aapt dump badging"

    echo
    echo "  > Package name / version"
    aapt dump badging "$APK" 2>/dev/null | grep -E "^package:" || echo "    [X] Impossible de récupérer le package"

    echo
    echo "  > Application label"
    aapt dump badging "$APK" 2>/dev/null | grep -E "^application-label" || echo "    [X] Application label introuvable"

    echo
    echo "  > Activities principales"
    aapt dump badging "$APK" 2>/dev/null | grep -E "launchable-activity" || echo "    [X] Aucune activity principale trouvée"

    echo
    echo "  > Permissions demandées"
    aapt dump permissions "$APK" 2>/dev/null || echo "    [X] Impossible de lister les permissions"

else
    echo "[!] 'aapt' n'est pas installé, analyse avancée impossible."
    echo "    → Installe le SDK Android ou 'aapt' pour extraire : package, version, permissions, activities..."
fi

echo
echo "==============================="
echo "  Analyse terminée"
echo "==============================="
