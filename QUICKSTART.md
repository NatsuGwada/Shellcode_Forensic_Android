# Quick Start Guide - AndroSleuth

## Installation Rapide

### 1. Installation automatique
```bash
chmod +x install.sh
./install.sh
```

### 2. Installation manuelle
```bash
# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/Mac

# Installer les dépendances
pip install --upgrade pip
pip install -r requirements.txt

# (Optionnel) Configurer VirusTotal
cp config/secrets.yaml.example config/secrets.yaml
# Éditer config/secrets.yaml et ajouter votre clé API
```

### 3. Configuration VirusTotal (Recommandé)

Pour activer la vérification de réputation :
1. Créez un compte gratuit sur [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Obtenez votre clé API dans votre profil
3. Ajoutez-la dans `config/secrets.yaml` :
```yaml
virustotal:
  api_key: "VOTRE_CLE_API_ICI"
```

Ou utilisez une variable d'environnement :
```bash
export VIRUSTOTAL_API_KEY="votre_cle_api"
```

## Utilisation

### Activer l'environnement virtuel
```bash
source venv/bin/activate
```

### Tests de base
```bash
# Tester les utilitaires
python tests/test_basic.py
```

### Analyser un APK

#### Mode Rapide (Analyse statique uniquement)
```bash
python src/androsleuth.py -a sample.apk -m quick
```

#### Mode Standard (Recommandé)
```bash
python src/androsleuth.py -a sample.apk -m standard
```

#### Mode Approfondi
```bash
python src/androsleuth.py -a sample.apk -m deep --all-modules
```

### Options utiles

```bash
# Générer un rapport JSON uniquement
python src/androsleuth.py -a sample.apk -f json

# Mode verbose pour plus de détails
python src/androsleuth.py -a sample.apk -v

# Conserver les fichiers temporaires
python src/androsleuth.py -a sample.apk --no-cleanup

# Spécifier un fichier de sortie
python src/androsleuth.py -a sample.apk -o reports/mon_rapport
```

## Structure des résultats

L'analyse génère :
- **Threat Score** : Score de menace global (0-100)
- **Niveau de risque** : SAFE, LOW, MEDIUM, HIGH, CRITICAL
- **Permissions dangereuses** détectées
- **Composants suspects** (receivers, services)
- **Code obfusqué** ou packers
- **Strings suspectes** et patterns malveillants
- **Chargement dynamique de code**
- **Utilisation de code natif** (.so)

## Prochaines étapes

1. ✅ Phase 1-4 : Analyse statique complète (FAIT)
2. 🔄 Phase 5 : Analyse de shellcode (EN COURS)
3. ⏳ Phase 6 : Analyse dynamique avec Frida
4. ⏳ Phase 7 : Génération de rapports HTML

## Obtenir des APK pour tests

⚠️ **Attention** : Ne testez que des APK légitimes ou des échantillons de malware dans un environnement contrôlé.

Sources légales :
- APKPure (vérifier la légitimité)
- F-Droid (open source)
- Échantillons malveillants : VirusTotal, MalwareBazaar (pour chercheurs)

## Troubleshooting

### Erreur d'installation
```bash
# Si une dépendance échoue, installer manuellement
pip install androguard
pip install frida-tools
```

### Erreur d'analyse
```bash
# Vérifier que l'APK est valide
file sample.apk
unzip -t sample.apk
```

### Logs
```bash
# Les logs sont dans le dossier logs/
cat logs/androsleuth_*.log
```

## Support

- 📖 Documentation complète : Voir README.md
- 🐛 Issues : GitHub Issues
- 💬 Questions : GitHub Discussions
