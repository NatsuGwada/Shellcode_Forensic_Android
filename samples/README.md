# Samples Directory

Place your APK files here for analysis with AndroSleuth.

## ⚠️ IMPORTANT - Avertissement de Sécurité

**NE PAS** télécharger ou analyser des APK suspects sur un système de production !

- Utilisez toujours une machine virtuelle isolée ou un conteneur
- Les fichiers APK dans ce dossier sont ignorés par git (.gitignore)
- Ne partagez jamais d'APK malveillants sans précautions appropriées

## Obtenir des échantillons de test

### Échantillons légitimes (pour tests fonctionnels)
- **F-Droid** : Applications open-source vérifiées
- **APKMirror** : Versions archivées d'applications légitimes
- Vos propres applications développées

### Échantillons malveillants (chercheurs uniquement)
- **VirusTotal** : Plateforme de partage de malwares
- **MalwareBazaar** : Base de données de malwares
- **AndroZoo** : Archive académique d'APK

## Structure recommandée

```
samples/
├── clean/          # APK légitimes pour tests
├── suspicious/     # APK potentiellement suspects
└── malware/        # Échantillons malveillants confirmés
```

## Exemple d'utilisation

```bash
# Analyser un APK dans samples/
python src/androsleuth.py -a samples/clean/example.apk

# Analyser tous les APK d'un dossier
for apk in samples/suspicious/*.apk; do
    python src/androsleuth.py -a "$apk" -o "reports/$(basename $apk)"
done
```

## Bonnes pratiques

1. ✅ Toujours vérifier la source de l'APK
2. ✅ Scanner avec VirusTotal avant analyse locale
3. ✅ Utiliser un environnement isolé
4. ✅ Documenter l'origine de chaque échantillon
5. ❌ Ne jamais installer d'APK suspect sur un appareil personnel

## Ressources

- [Android Security Wiki](https://source.android.com/security)
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/)
- [VirusTotal](https://www.virustotal.com/)

