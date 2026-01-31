# HybriScope 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)

**HybriScope** est un outil d'investigation réseau "Hybrid-First" conçu pour 2026. Il fusionne la puissance du protocole moderne **RDAP** (JSON-based) avec la robustesse historique du **WHOIS** (Port 43) pour offrir les informations de noms de domaine les plus complètes et précises du marché.



---

## ✨ Proposition de Valeur
À l'ère du RGPD et de la fragmentation des données WHOIS, **HybriScope** se distingue par :
* **Intelligence Hybride :** Priorise les requêtes RDAP pour des données structurées et bascule automatiquement sur WHOIS si nécessaire.
* **Bootstrap Dynamique :** Utilise les registres de l'IANA en temps réel pour ne jamais interroger le mauvais serveur.
* **Normalisation Totale :** Peu importe la source, vous recevez un format de données unifié et propre.
* **Performance 2026 :** Architecture asynchrone pour scanner plusieurs domaines simultanément sans perte de vitesse.

---

## 🛠️ Installation

### Prérequis
* Python 3.10 ou supérieur
* Git

### Étapes
1. **Cloner le projet :**
   ```bash
   git clone https://github.com/yen-0818/HybriScope.git
   cd HybriScope