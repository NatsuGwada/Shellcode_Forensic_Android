# Guide de Contribution - AndroSleuth

Merci de votre intérêt pour contribuer à AndroSleuth ! 🎉

## 🚀 Comment Contribuer

### 1. Fork et Clone
```bash
# Fork le projet sur GitHub
git clone https://github.com/VOTRE_USERNAME/Shellcode_Forensic_Android.git
cd Shellcode_Forensic_Android
```

### 2. Créer une branche
```bash
git checkout -b feature/ma-nouvelle-fonctionnalite
# ou
git checkout -b fix/correction-bug
```

### 3. Installer l'environnement de développement
```bash
./install.sh
source venv/bin/activate
```

### 4. Faire vos modifications
- Suivez le style de code existant
- Ajoutez des commentaires pour les parties complexes
- Créez des tests si applicable

### 5. Tester vos modifications
```bash
# Tests unitaires
python tests/test_basic.py

# Test avec un APK réel
python src/androsleuth.py -a samples/test.apk -v
```

### 6. Commit et Push
```bash
git add .
git commit -m "feat: Description claire de la fonctionnalité"
git push origin feature/ma-nouvelle-fonctionnalite
```

### 7. Créer une Pull Request
- Décrivez clairement vos changements
- Référencez les issues liées
- Attendez la revue de code

---

## 📋 Domaines de Contribution

### 🔴 Priorité Haute
- **Module d'analyse de shellcode** : Désassemblage et détection de patterns
- **Générateur de rapports HTML** : Interface web pour visualiser les résultats
- **Tests unitaires** : Couverture de code
- **Documentation** : Améliorer les commentaires et guides

### 🟡 Priorité Moyenne
- **Module d'émulation** : Unicorn Engine pour exécution sandboxée
- **Optimisations de performance** : Analyse plus rapide
- **Support de nouveaux packers** : Ajouter des signatures
- **Interface graphique** : GUI optionnelle

### 🟢 Priorité Basse
- **Scripts Frida** : Instrumentation dynamique
- **Support Docker** : Containerisation
- **CI/CD** : GitHub Actions
- **Intégrations** : VirusTotal API, etc.

---

## 🎨 Standards de Code

### Style Python
- Suivre **PEP 8**
- Utiliser **type hints** quand possible
- Docstrings pour toutes les fonctions/classes

```python
def analyze_permission(permission: str, config: dict) -> dict:
    """
    Analyze a single permission for threat level
    
    Args:
        permission: Android permission string
        config: Configuration dictionary
    
    Returns:
        dict: Analysis results with threat level
    """
    pass
```

### Nommage
- **Fichiers** : `snake_case.py`
- **Classes** : `PascalCase`
- **Fonctions** : `snake_case()`
- **Constantes** : `UPPER_CASE`

### Structure des Modules
```python
"""
Module description
Brief explanation of what this module does
"""

import standard_library
import third_party
from project import module

from ..utils.logger import get_logger

logger = get_logger()


class MyAnalyzer:
    """Class description"""
    
    def __init__(self):
        pass
    
    def analyze(self):
        """Main analysis method"""
        pass
    
    def get_summary(self):
        """Return summary dict"""
        pass
```

---

## 🧪 Tests

### Structure des Tests
```python
# tests/test_mon_module.py
import pytest
from src.modules.mon_module import MonAnalyzer

def test_basic_functionality():
    analyzer = MonAnalyzer()
    result = analyzer.analyze()
    assert result is not None

def test_edge_case():
    # Test des cas limites
    pass
```

### Exécuter les Tests
```bash
# Tous les tests
pytest tests/ -v

# Un seul fichier
pytest tests/test_mon_module.py -v

# Avec couverture
pytest tests/ --cov=src --cov-report=html
```

---

## 📝 Documentation

### README
- Tenir à jour avec les nouvelles fonctionnalités
- Ajouter des exemples d'utilisation
- Mettre à jour les badges si nécessaire

### Docstrings
- Toutes les fonctions publiques doivent avoir des docstrings
- Format Google style ou NumPy style

### CHANGELOG
Maintenir un fichier CHANGELOG.md :
```markdown
## [1.1.0] - 2025-XX-XX
### Added
- Nouvelle fonctionnalité X
### Fixed
- Correction du bug Y
### Changed
- Amélioration de Z
```

---

## 🐛 Rapporter des Bugs

### Template d'Issue
```markdown
**Description**
Description claire du bug

**Étapes pour reproduire**
1. Faire ceci
2. Puis cela
3. Observer l'erreur

**Comportement attendu**
Ce qui devrait se passer

**Comportement observé**
Ce qui se passe réellement

**Environnement**
- OS: [e.g. Ubuntu 22.04]
- Python: [e.g. 3.10.0]
- AndroSleuth version: [e.g. 1.0.0]

**Logs**
```
Coller les logs ici
```
```

---

## 💡 Proposer des Fonctionnalités

### Template d'Issue
```markdown
**Fonctionnalité proposée**
Description de la fonctionnalité

**Motivation**
Pourquoi cette fonctionnalité est utile

**Solution proposée**
Comment l'implémenter

**Alternatives considérées**
Autres approches possibles
```

---

## 🔒 Sécurité

### Rapporter une Vulnérabilité
- **NE PAS** créer d'issue publique
- Contacter directement : [créer un champ email]
- Attendre 90 jours avant divulgation publique

### Bonnes Pratiques
- Ne jamais commit de secrets (API keys, etc.)
- Utiliser `.gitignore` pour fichiers sensibles
- Valider toutes les entrées utilisateur
- Logger sans exposer de données sensibles

---

## 📜 Licence

En contribuant, vous acceptez que vos contributions soient sous licence **MIT**.

---

## 🤝 Code de Conduite

### Notre Engagement
- Être respectueux et inclusif
- Accepter les critiques constructives
- Se concentrer sur ce qui est le mieux pour la communauté
- Faire preuve d'empathie

### Comportements Inacceptables
- Langage ou images à caractère sexuel
- Harcèlement ou intimidation
- Commentaires insultants ou dégradants
- Attaques personnelles ou politiques

---

## 📞 Contact

- **Issues** : [GitHub Issues](https://github.com/NatsuGwada/Shellcode_Forensic_Android/issues)
- **Discussions** : [GitHub Discussions](https://github.com/NatsuGwada/Shellcode_Forensic_Android/discussions)
- **Email** : [À ajouter]

---

## 🎓 Ressources

### Apprendre
- [Androguard Documentation](https://androguard.readthedocs.io/)
- [Android Security Internals](https://nostarch.com/androidsecurity)
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/)

### Outils
- [APKTool](https://ibotpeaches.github.io/Apktool/)
- [Frida](https://frida.re/)
- [Radare2](https://rada.re/)

---

Merci de contribuer à rendre l'écosystème Android plus sûr ! 🛡️
