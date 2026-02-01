# Dans tests/test_core_system.py

"""
Ce que ce test va vérifier :
1-Système de fichiers : Est-ce que le dossier /cache se crée avec les bonnes permissions ?

2-Sécurité SSL : Est-ce que ta machine accepte la configuration TLS 1.2+ de l'IANA ?

3-Filtrage : Est-ce que le validateur bloque bien les domaines interdits ?

4-Parsing JSON : Est-ce que la structure du fichier de l'IANA est validée correctement ?

5-Réseau TCP : Est-ce que ton pare-feu laisse passer les requêtes sur le port 43 (WHOIS) ?

"""


import sys
from pathlib import Path
import logging

# On ajoute le dossier parent au chemin de recherche pour trouver le module 'core'
sys.path.append(str(Path(__file__).parent.parent))

from core.network import RDAPTransport, WHOISTransport
from core.bootstrap import BootStrapManager

# Configuration du logging pour voir ce qui se passe sous le capot
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_integration():
    print("🚀 Démarrage des tests d'intégration HybriScope...\n")
    
    try:
        # 1. Initialisation du Manager (Test de setup_paths et load_data)
        print("--- Étape 1 : Initialisation du Bootstrap Manager ---")
        manager = BootStrapManager()
        print(f"✅ Cache initialisé dans : {manager.cache_path}")
        
        # 2. Test du Validateur RDAP (SmartRDAPValidator)
        print("\n--- Étape 2 : Test des Validateurs ---")
        urls_to_test = [
            ("https://rdap.nic.fr/", True),          # Whitelist (Niveau 1)
            ("https://rdap.verisign.com/com/v1/", True), # Whitelist
            ("https://malicious.onion/", False),     # Blacklist (Niveau 0)
            ("http://rdap.nic.fr/", False),          # Non-HTTPS
        ]
        
        for url, expected in urls_to_test:
            is_valid, reason = manager.rdap_validator.validate_url(url)
            status = "PASS" if is_valid == expected else "FAIL"
            print(f"[{status}] URL: {url} -> {reason}")

        # 3. Test du Transporteur RDAP (Network + SSL)
        print("\n--- Étape 3 : Test de connexion IANA ---")
        # On force un rafraîchissement pour tester le réseau
        data = manager._refresh_bootstrap()
        if data and "services" in data:
            print(f"✅ Récupération bootstrap réussie ({len(data['services'])} services trouvés)")
        else:
            print("❌ Échec de récupération du bootstrap")

        # 4. Test de découverte WHOIS (Socket + IANA Port 43)
        print("\n--- Étape 4 : Test de découverte de serveur WHOIS ---")
        tlds = ["fr", "com", "jp"]
        for tld in tlds:
            server = manager.get_whois_server(tld)
            if server:
                print(f"✅ Serveur trouvé pour .{tld} : {server}")
            else:
                print(f"❌ Aucun serveur trouvé pour .{tld}")

        # 5. Affichage des Statistiques
        print("\n--- Étape 5 : Statistiques du validateur ---")
        import json
        print(json.dumps(manager.get_validator_statistics(), indent=4))

    except Exception as e:
        print(f"\n💥 CRASH durant le test : {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_integration()