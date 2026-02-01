"""
Exemples pratiques d'utilisation du ParserManager.

Ce fichier démontre différents scénarios d'utilisation réels
du ParserManager sécurisé pour HybriScope.
"""
import sys
import os

# Ajoute la racine du projet au chemin de recherche de Python
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


import logging
from parsers.manager import ParserManager

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def exemple_1_parsing_rdap_simple():
    """Exemple 1: Parsing RDAP simple."""
    print("\n" + "=" * 70)
    print("EXEMPLE 1: Parsing RDAP Simple")
    print("=" * 70)
    
    manager = ParserManager()
    
    # Données RDAP typiques
    rdap_data = {
        "objectClassName": "domain",
        "handle": "EXAMPLE-COM",
        "ldhName": "example.com",
        "events": [
            {
                "eventAction": "registration",
                "eventDate": "1995-08-14T04:00:00Z"
            },
            {
                "eventAction": "expiration",
                "eventDate": "2025-08-13T04:00:00Z"
            },
            {
                "eventAction": "last changed",
                "eventDate": "2024-08-14T04:00:00Z"
            }
        ],
        "status": [
            "client delete prohibited",
            "client transfer prohibited",
            "client update prohibited"
        ],
        "entities": [
            {
                "objectClassName": "entity",
                "handle": "376",
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]
                    ]
                ]
            }
        ]
    }
    
    # Parse
    result = manager.parse(rdap_data, 'rdap')
    
    # Affichage des résultats
    print(f"\n✓ Parsing réussi: {result.is_valid}")
    print(f"  Source: {result.source}")
    print(f"  Création: {result.creation_date}")
    print(f"  Expiration: {result.expiration_date}")
    print(f"  Registrar: {result.registrar}")
    print(f"  Status: {result.status}")
    print(f"  Erreurs: {result.errors}")
    print(f"  Warnings: {result.warnings}")


def exemple_2_parsing_whois_simple():
    """Exemple 2: Parsing WHOIS simple."""
    print("\n" + "=" * 70)
    print("EXEMPLE 2: Parsing WHOIS Simple")
    print("=" * 70)
    
    manager = ParserManager()
    
    # Données WHOIS typiques
    whois_text = """
   Domain Name: GOOGLE.COM
   Registry Domain ID: 2138514_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.markmonitor.com
   Registrar URL: http://www.markmonitor.com
   Updated Date: 2019-09-09T15:39:04Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2028-09-14T04:00:00Z
   Registrar: MarkMonitor Inc.
   Registrar IANA ID: 292
   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
   Registrar Abuse Contact Phone: +1.2086851750
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
    """
    
    # Parse
    result = manager.parse(whois_text, 'whois')
    
    # Affichage des résultats
    print(f"\n✓ Parsing réussi: {result.is_valid}")
    print(f"  Source: {result.source}")
    print(f"  Création: {result.creation_date}")
    print(f"  Expiration: {result.expiration_date}")
    print(f"  Registrar: {result.registrar}")
    print(f"  Status: {result.status}")  # ← Notez: maintenant une liste !
    print(f"  Type de status: {type(result.status)}")


def exemple_3_gestion_erreurs():
    """Exemple 3: Gestion des erreurs."""
    print("\n" + "=" * 70)
    print("EXEMPLE 3: Gestion des Erreurs")
    print("=" * 70)
    
    manager = ParserManager()
    
    # Cas 1: Type de source invalide
    print("\n--- Cas 1: Type de source invalide ---")
    result = manager.parse({}, 'ftp')  # Type invalide
    if not result.is_valid:
        print(f"✗ Erreur détectée: {result.errors[0]}")
    
    # Cas 2: Type de données incorrect pour RDAP
    print("\n--- Cas 2: Type de données incorrect ---")
    result = manager.parse("texte au lieu de dict", 'rdap')
    if not result.is_valid:
        print(f"✗ Erreur détectée: {result.errors[0]}")
    
    # Cas 3: Données trop volumineuses
    print("\n--- Cas 3: Données trop volumineuses ---")
    huge_text = "x" * 600_000  # > 500KB
    result = manager.parse(huge_text, 'whois')
    if not result.is_valid:
        print(f"✗ Erreur détectée: {result.errors[0]}")
    
    # Cas 4: Données valides mais vides
    print("\n--- Cas 4: Données vides ---")
    result = manager.parse({}, 'rdap')
    print(f"  Valide: {result.is_valid}")
    print(f"  A des données: {result.has_data()}")
    if result.warnings:
        print(f"  Warnings: {result.warnings}")


def exemple_4_uniformisation_formats():
    """Exemple 4: Uniformisation des formats RDAP/WHOIS."""
    print("\n" + "=" * 70)
    print("EXEMPLE 4: Uniformisation des Formats")
    print("=" * 70)
    
    manager = ParserManager()
    
    # RDAP: status est déjà une liste
    rdap_data = {
        "status": ["active", "clientTransferProhibited", "locked"]
    }
    
    # WHOIS: status est une chaîne unique
    whois_data = "Domain Status: clientTransferProhibited"
    
    # Parse les deux
    rdap_result = manager.parse(rdap_data, 'rdap')
    whois_result = manager.parse(whois_data, 'whois')
    
    print("\n--- Format RDAP ---")
    print(f"  Status: {rdap_result.status}")
    print(f"  Type: {type(rdap_result.status)}")
    print(f"  Nombre: {len(rdap_result.status)}")
    
    print("\n--- Format WHOIS (uniformisé) ---")
    print(f"  Status: {whois_result.status}")
    print(f"  Type: {type(whois_result.status)}")
    print(f"  Nombre: {len(whois_result.status)}")
    
    print("\n✓ Les deux formats sont maintenant cohérents (List[str])")
    
    # Traitement unifié possible
    print("\n--- Traitement unifié ---")
    for result in [rdap_result, whois_result]:
        print(f"  Source {result.source}:")
        for status in result.status:
            print(f"    - {status}")


def exemple_5_utilisation_hybridscope():
    """Exemple 5: Intégration typique dans HybriScope."""
    print("\n" + "=" * 70)
    print("EXEMPLE 5: Intégration HybriScope")
    print("=" * 70)
    
    # Simulation d'une requête HybriScope
    manager = ParserManager()
    
    # Fonction utilitaire pour traiter n'importe quelle source
    def traiter_domaine(data, source_type):
        """Traite des données de domaine peu importe la source."""
        result = manager.parse(data, source_type)
        
        if not result.is_valid:
            print(f"✗ Échec du parsing ({result.source})")
            for error in result.errors:
                print(f"  - {error}")
            return None
        
        # Extraction des informations clés
        info = {
            'source': result.source,
            'expire_dans': calculer_jours_expiration(result.expiration_date),
            'age': calculer_age_domaine(result.creation_date),
            'registrar': result.registrar,
            'protections': [s for s in result.status if 'prohibited' in s.lower()]
        }
        
        return info
    
    def calculer_jours_expiration(date_str):
        """Calcule les jours jusqu'à expiration."""
        if not date_str:
            return None
        from datetime import datetime
        try:
            exp_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            now = datetime.now(exp_date.tzinfo)
            delta = exp_date - now
            return delta.days
        except:
            return None
    
    def calculer_age_domaine(date_str):
        """Calcule l'âge du domaine en jours."""
        if not date_str:
            return None
        from datetime import datetime
        try:
            creation_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            now = datetime.now(creation_date.tzinfo)
            delta = now - creation_date
            return delta.days
        except:
            return None
    
    # Test avec RDAP
    print("\n--- Test avec source RDAP ---")
    rdap = {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-12-31T23:59:59Z"}
        ],
        "status": ["clientTransferProhibited", "active"],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]
        }]
    }
    
    info = traiter_domaine(rdap, 'rdap')
    if info:
        print(f"  Source: {info['source']}")
        print(f"  Expire dans: {info['expire_dans']} jours" if info['expire_dans'] else "  Expiration: inconnue")
        print(f"  Âge: {info['age']} jours" if info['age'] else "  Création: inconnue")
        print(f"  Registrar: {info['registrar']}")
        print(f"  Protections: {len(info['protections'])}")
    
    # Test avec WHOIS
    print("\n--- Test avec source WHOIS ---")
    whois = """
    Creation Date: 2020-01-01T00:00:00Z
    Registry Expiry Date: 2025-12-31T23:59:59Z
    Registrar: Example Registrar Inc.
    Domain Status: clientTransferProhibited
    """
    
    info = traiter_domaine(whois, 'whois')
    if info:
        print(f"  Source: {info['source']}")
        print(f"  Expire dans: {info['expire_dans']} jours" if info['expire_dans'] else "  Expiration: inconnue")
        print(f"  Registrar: {info['registrar']}")
        print(f"  Protections: {len(info['protections'])}")


def exemple_6_statistiques_monitoring():
    """Exemple 6: Utilisation des statistiques pour monitoring."""
    print("\n" + "=" * 70)
    print("EXEMPLE 6: Statistiques et Monitoring")
    print("=" * 70)
    
    manager = ParserManager(enable_metrics=True)
    
    # Simulation de plusieurs parsings
    print("\n--- Simulation de 10 parsings ---")
    
    # 5 RDAP valides
    for i in range(5):
        rdap = {
            "events": [{"eventAction": "expiration", "eventDate": f"202{i}-12-31T23:59:59Z"}],
            "status": ["active"]
        }
        manager.parse(rdap, 'rdap')
    
    # 3 WHOIS valides
    for i in range(3):
        whois = f"Registry Expiry Date: 202{i}-12-31T23:59:59Z"
        manager.parse(whois, 'whois')
    
    # 2 erreurs (types invalides)
    manager.parse("texte", 'rdap')  # Erreur
    manager.parse({}, 'invalid')    # Erreur
    
    # Récupération des statistiques
    stats = manager.get_statistics()
    
    print(f"\n--- Statistiques Globales ---")
    print(f"  Total de parsings: {stats['overall']['total_parses']}")
    print(f"  Parsings réussis: {stats['overall']['successful_parses']}")
    print(f"  Erreurs totales: {stats['overall']['total_errors']}")
    print(f"  Taux de succès: {stats['overall']['success_rate']:.1%}")
    
    print(f"\n--- Par Source ---")
    print(f"  RDAP:")
    print(f"    - Parsings: {stats['by_source']['rdap']['parses']}")
    print(f"    - Erreurs: {stats['by_source']['rdap']['errors']}")
    print(f"    - Taux: {stats['by_source']['rdap']['success_rate']:.1%}")
    
    print(f"  WHOIS:")
    print(f"    - Parsings: {stats['by_source']['whois']['parses']}")
    print(f"    - Erreurs: {stats['by_source']['whois']['errors']}")
    print(f"    - Taux: {stats['by_source']['whois']['success_rate']:.1%}")
    
    print(f"\n--- Autres Métriques ---")
    print(f"  Erreurs de validation: {stats['validation_errors']}")
    print(f"  Sources inconnues: {stats['unknown_sources']}")
    
    # Détection d'anomalies
    print(f"\n--- Analyse d'Anomalies ---")
    if stats['overall']['success_rate'] < 0.9:
        print("  ⚠️  ALERTE: Taux de succès < 90% !")
    else:
        print("  ✓ Taux de succès normal")
    
    if stats['validation_errors'] > stats['overall']['total_parses'] * 0.1:
        print("  ⚠️  ALERTE: Trop d'erreurs de validation !")
    else:
        print("  ✓ Erreurs de validation normales")


def exemple_7_conversion_dict_retrocompat():
    """Exemple 7: Rétrocompatibilité avec parse_to_dict."""
    print("\n" + "=" * 70)
    print("EXEMPLE 7: Rétrocompatibilité")
    print("=" * 70)
    
    manager = ParserManager()
    
    rdap_data = {
        "events": [{"eventAction": "expiration", "eventDate": "2025-12-31T23:59:59Z"}],
        "status": ["active"]
    }
    
    # Nouvelle méthode (recommandée)
    print("\n--- Méthode parse() (nouveau) ---")
    result = manager.parse(rdap_data, 'rdap')
    print(f"  Type: {type(result)}")
    print(f"  is_valid: {result.is_valid}")
    print(f"  has_data(): {result.has_data()}")
    
    # Ancienne méthode (rétrocompatible)
    print("\n--- Méthode parse_to_dict() (ancien, rétrocompat) ---")
    result_dict = manager.parse_to_dict(rdap_data, 'rdap', include_metadata=True)
    print(f"  Type: {type(result_dict)}")
    print(f"  Clés: {list(result_dict.keys())}")
    
    # Sans métadonnées (comme avant)
    print("\n--- Sans métadonnées (compatibilité totale) ---")
    result_dict_simple = manager.parse_to_dict(rdap_data, 'rdap', include_metadata=False)
    print(f"  Clés: {list(result_dict_simple.keys())}")
    print(f"  Contenu: {result_dict_simple}")


def exemple_8_tests_securite():
    """Exemple 8: Tests de sécurité en action."""
    print("\n" + "=" * 70)
    print("EXEMPLE 8: Tests de Sécurité")
    print("=" * 70)
    
    manager = ParserManager()
    
    # Test 1: Protection contre injections
    print("\n--- Test 1: Protection contre injections ---")
    malicious_types = [
        "rdap'; DROP TABLE domains; --",
        "whois OR 1=1",
        "<script>alert('xss')</script>",
        "../../../etc/passwd"
    ]
    
    for mal_type in malicious_types:
        result = manager.parse({}, mal_type)
        print(f"  Type malveillant: {mal_type[:30]}...")
        print(f"    Bloqué: {not result.is_valid}")
    
    # Test 2: Protection DoS
    print("\n--- Test 2: Protection DoS ---")
    
    # Texte énorme
    huge = "x" * 600_000
    result = manager.parse(huge, 'whois')
    print(f"  Texte de 600KB: Bloqué = {not result.is_valid}")
    
    # Dict profond
    deep = {"a": {}}
    current = deep["a"]
    for i in range(20):
        current["b"] = {}
        current = current["b"]
    result = manager.parse(deep, 'rdap')
    print(f"  JSON très profond: Géré = {result is not None}")
    
    # Test 3: Type confusion
    print("\n--- Test 3: Protection type confusion ---")
    wrong_types = [123, None, [], True, 3.14]
    
    for wrong in wrong_types:
        result = manager.parse(wrong, 'rdap')
        print(f"  Type {type(wrong).__name__}: Bloqué = {not result.is_valid}")


def exemple_9_cas_reels():
    """Exemple 9: Cas d'utilisation réels variés."""
    print("\n" + "=" * 70)
    print("EXEMPLE 9: Cas Réels Variés")
    print("=" * 70)
    
    manager = ParserManager()
    
    # Cas 1: .com (RDAP complet)
    print("\n--- Cas 1: Domaine .com (RDAP) ---")
    com_rdap = {
        "events": [
            {"eventAction": "registration", "eventDate": "2015-03-15T08:30:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-03-15T08:30:00Z"}
        ],
        "status": ["client delete prohibited", "client transfer prohibited"],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"]]]
        }]
    }
    
    result = manager.parse(com_rdap, 'rdap')
    print(f"  Valide: {result.is_valid}")
    print(f"  Registrar: {result.registrar}")
    print(f"  Status: {len(result.status)} status")
    
    # Cas 2: .fr (WHOIS)
    print("\n--- Cas 2: Domaine .fr (WHOIS) ---")
    fr_whois = """
    domain: example.fr
    status: ACTIVE
    hold: NO
    holder-c: ANO00-FRNIC
    admin-c: ANO00-FRNIC
    tech-c: ANO00-FRNIC
    zone-c: NFC1-FRNIC
    nsl-id: NSL1-FRNIC
    registrar: AFNIC
    Expiry Date: 2025-12-31
    created: 1995-01-01
    """
    
    result = manager.parse(fr_whois, 'whois')
    print(f"  Valide: {result.is_valid}")
    print(f"  Création: {result.creation_date}")
    print(f"  Expiration: {result.expiration_date}")
    
    # Cas 3: Données partielles
    print("\n--- Cas 3: Données partielles ---")
    partial = {"events": []}
    result = manager.parse(partial, 'rdap')
    print(f"  Valide: {result.is_valid}")
    print(f"  A des données: {result.has_data()}")
    print(f"  Warnings: {result.warnings}")


# Fonction principale
def main():
    """Exécute tous les exemples."""
    print("\n" + "=" * 70)
    print(" " * 15 + "EXEMPLES PRATIQUES - PARSER MANAGER")
    print("=" * 70)
    
    exemples = [
        exemple_1_parsing_rdap_simple,
        exemple_2_parsing_whois_simple,
        exemple_3_gestion_erreurs,
        exemple_4_uniformisation_formats,
        exemple_5_utilisation_hybridscope,
        exemple_6_statistiques_monitoring,
        exemple_7_conversion_dict_retrocompat,
        exemple_8_tests_securite,
        exemple_9_cas_reels
    ]
    
    for i, exemple in enumerate(exemples, 1):
        try:
            exemple()
        except Exception as e:
            print(f"\n⚠️  Erreur dans exemple {i}: {e}")
    
    print("\n" + "=" * 70)
    print(" " * 20 + "FIN DES EXEMPLES")
    print("=" * 70)


if __name__ == '__main__':
    main()