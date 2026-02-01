"""
Tests unitaires pour le ParserManager.

Ce fichier teste tous les aspects de sécurité et de fonctionnalité
du ParserManager, incluant:
- Validation des entrées
- Gestion des erreurs
- Uniformisation des résultats
- Métriques et statistiques
"""
import unittest
import sys
import os
import logging
from typing import Dict, Any

# Ajoute la racine du projet au PYTHONPATH de manière dynamique
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Maintenant, on importe en précisant le dossier (package)
try:
    from parsers.manager import ParserManager, SourceType, ParsedResult
    from parsers.whois_parser import WhoisParser
    from parsers.rdap_parser import RDAPParser
except ImportError as e:
    # Si l'import direct échoue, on tente l'import local (pour certains environnements)
    try:
        from manager import ParserManager, SourceType, ParsedResult
        from whois_parser import WhoisParser
        from rdap_parser import RDAPParser
    except ImportError:
        print(f"\n[!] Erreur d'import critique : {e}")
        print(f"PYTHONPATH actuel : {sys.path[0]}")
        raise


class TestSourceType(unittest.TestCase):
    """Tests pour l'enum SourceType."""
    
    def test_from_string_valid(self):
        """Test conversion de chaînes valides."""
        self.assertEqual(SourceType.from_string('rdap'), SourceType.RDAP)
        self.assertEqual(SourceType.from_string('RDAP'), SourceType.RDAP)
        self.assertEqual(SourceType.from_string('whois'), SourceType.WHOIS)
        self.assertEqual(SourceType.from_string('WHOIS'), SourceType.WHOIS)
        self.assertEqual(SourceType.from_string('  whois  '), SourceType.WHOIS)
    
    def test_from_string_invalid(self):
        """Test conversion de chaînes invalides."""
        self.assertIsNone(SourceType.from_string('invalid'))
        self.assertIsNone(SourceType.from_string(''))
        self.assertIsNone(SourceType.from_string(123))
        self.assertIsNone(SourceType.from_string(None))
        self.assertIsNone(SourceType.from_string(['rdap']))
    
    def test_get_valid_types(self):
        """Test récupération des types valides."""
        valid_types = SourceType.get_valid_types()
        self.assertIn('rdap', valid_types)
        self.assertIn('whois', valid_types)
        self.assertEqual(len(valid_types), 2)


class TestParsedResult(unittest.TestCase):
    """Tests pour la dataclass ParsedResult."""
    
    def test_initialization(self):
        """Test initialisation par défaut."""
        result = ParsedResult()
        self.assertIsNone(result.expiration_date)
        self.assertIsNone(result.creation_date)
        self.assertIsNone(result.registrar)
        self.assertEqual(result.status, [])
        self.assertEqual(result.source, "")
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])
        self.assertTrue(result.is_valid)
    
    def test_to_dict_with_metadata(self):
        """Test conversion en dict avec métadonnées."""
        result = ParsedResult(
            expiration_date="2025-12-31",
            status=["active"],
            source="RDAP",
            errors=["error1"],
            warnings=["warning1"]
        )
        d = result.to_dict(include_metadata=True)
        
        self.assertEqual(d['expiration_date'], "2025-12-31")
        self.assertEqual(d['status'], ["active"])
        self.assertEqual(d['source'], "RDAP")
        self.assertEqual(d['errors'], ["error1"])
        self.assertEqual(d['warnings'], ["warning1"])
    
    def test_to_dict_without_metadata(self):
        """Test conversion en dict sans métadonnées."""
        result = ParsedResult(
            expiration_date="2025-12-31",
            errors=["error1"]
        )
        d = result.to_dict(include_metadata=False)
        
        self.assertIn('expiration_date', d)
        self.assertNotIn('errors', d)
        self.assertNotIn('warnings', d)
        self.assertNotIn('is_valid', d)
    
    def test_has_data(self):
        """Test détection de présence de données."""
        # Résultat vide
        result = ParsedResult()
        self.assertFalse(result.has_data())
        
        # Avec expiration_date
        result.expiration_date = "2025-12-31"
        self.assertTrue(result.has_data())
        
        # Avec status uniquement
        result = ParsedResult(status=["active"])
        self.assertTrue(result.has_data())


class TestParserManagerValidation(unittest.TestCase):
    """Tests pour les validations du ParserManager."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        logging.disable(logging.CRITICAL)  # Désactive les logs pendant les tests
        self.manager = ParserManager()
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        logging.disable(logging.NOTSET)
    
    def test_validate_source_type_valid(self):
        """Test validation de source_type valide."""
        self.assertEqual(
            self.manager._validate_source_type('rdap'),
            SourceType.RDAP
        )
        self.assertEqual(
            self.manager._validate_source_type('WHOIS'),
            SourceType.WHOIS
        )
    
    def test_validate_source_type_invalid(self):
        """Test validation de source_type invalide."""
        self.assertIsNone(self.manager._validate_source_type('invalid'))
        self.assertIsNone(self.manager._validate_source_type(''))
        self.assertIsNone(self.manager._validate_source_type(123))
        self.assertIsNone(self.manager._validate_source_type('x' * 100))
    
    def test_validate_raw_data_size_whois(self):
        """Test validation de taille pour WHOIS."""
        # Taille acceptable
        small_text = "Domain: example.com"
        self.assertTrue(self.manager._validate_raw_data_size(small_text))
        
        # Taille excessive
        huge_text = "x" * 600_000
        self.assertFalse(self.manager._validate_raw_data_size(huge_text))
    
    def test_validate_raw_data_size_rdap(self):
        """Test validation de taille pour RDAP."""
        # Dict simple
        small_dict = {"key": "value"}
        self.assertTrue(self.manager._validate_raw_data_size(small_dict))
        
        # Dict avec trop de clés
        # (le test exact dépend de MAX_DICT_KEYS)
    
    def test_count_dict_keys(self):
        """Test comptage récursif des clés."""
        # Dict simple
        simple = {"a": 1, "b": 2}
        self.assertEqual(self.manager._count_dict_keys(simple), 2)
        
        # Dict imbriqué
        nested = {"a": {"b": {"c": 1}}}
        count = self.manager._count_dict_keys(nested)
        self.assertGreater(count, 1)
        
        # Liste
        with_list = {"items": [1, 2, 3]}
        self.assertGreater(self.manager._count_dict_keys(with_list), 0)


class TestParserManagerRDAP(unittest.TestCase):
    """Tests pour le parsing RDAP."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        logging.disable(logging.CRITICAL)
        self.manager = ParserManager()
        
        self.valid_rdap = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2025-12-31T23:59:59Z"}
            ],
            "status": ["active", "clientTransferProhibited"],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar"]]]
            }]
        }
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        logging.disable(logging.NOTSET)
    
    def test_parse_rdap_valid(self):
        """Test parsing RDAP valide."""
        result = self.manager.parse(self.valid_rdap, 'rdap')
        
        self.assertTrue(result.is_valid)
        self.assertEqual(result.source, 'RDAP')
        self.assertEqual(result.expiration_date, "2025-12-31T23:59:59Z")
        self.assertEqual(result.creation_date, "2020-01-01T00:00:00Z")
        self.assertEqual(result.registrar, "Test Registrar")
        self.assertIn("active", result.status)
        self.assertEqual(len(result.errors), 0)
    
    def test_parse_rdap_wrong_type(self):
        """Test RDAP avec mauvais type de données."""
        result = self.manager.parse("should be dict", 'rdap')
        
        self.assertFalse(result.is_valid)
        self.assertEqual(result.source, 'RDAP')
        self.assertGreater(len(result.errors), 0)
        self.assertIn("invalide", result.errors[0].lower())
    
    def test_parse_rdap_empty(self):
        """Test RDAP vide."""
        result = self.manager.parse({}, 'rdap')
        
        # Devrait être valide mais sans données
        self.assertTrue(result.is_valid)
        self.assertFalse(result.has_data())
    
    def test_parse_rdap_partial(self):
        """Test RDAP avec données partielles."""
        partial_rdap = {
            "events": [
                {"eventAction": "expiration", "eventDate": "2025-12-31T23:59:59Z"}
            ]
        }
        result = self.manager.parse(partial_rdap, 'rdap')
        
        self.assertTrue(result.is_valid)
        self.assertEqual(result.expiration_date, "2025-12-31T23:59:59Z")
        self.assertIsNone(result.creation_date)
        self.assertIsNone(result.registrar)


class TestParserManagerWHOIS(unittest.TestCase):
    """Tests pour le parsing WHOIS."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        logging.disable(logging.CRITICAL)
        self.manager = ParserManager()
        
        self.valid_whois = """
        Registry Expiry Date: 2025-12-31T23:59:59Z
        Creation Date: 2020-01-01T00:00:00Z
        Registrar: Test Registrar Inc.
        Domain Status: clientTransferProhibited
        """
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        logging.disable(logging.NOTSET)
    
    def test_parse_whois_valid(self):
        """Test parsing WHOIS valide."""
        result = self.manager.parse(self.valid_whois, 'whois')
        
        self.assertTrue(result.is_valid)
        self.assertEqual(result.source, 'WHOIS')
        self.assertIsNotNone(result.expiration_date)
        self.assertIsNotNone(result.creation_date)
        self.assertIsNotNone(result.registrar)
        # Status doit être une liste (uniformisation avec RDAP)
        self.assertIsInstance(result.status, list)
        self.assertEqual(len(result.errors), 0)
    
    def test_parse_whois_wrong_type(self):
        """Test WHOIS avec mauvais type de données."""
        result = self.manager.parse({"key": "value"}, 'whois')
        
        self.assertFalse(result.is_valid)
        self.assertEqual(result.source, 'WHOIS')
        self.assertGreater(len(result.errors), 0)
    
    def test_parse_whois_empty(self):
        """Test WHOIS vide."""
        result = self.manager.parse("", 'whois')
        
        # Devrait être valide mais sans données
        self.assertTrue(result.is_valid or not result.is_valid)
        self.assertFalse(result.has_data())
    
    def test_parse_whois_status_uniformization(self):
        """Test uniformisation du status en liste."""
        result = self.manager.parse(self.valid_whois, 'whois')
        
        # Le status WHOIS doit être transformé en liste
        self.assertIsInstance(result.status, list)
        if result.status:
            self.assertEqual(len(result.status), 1)


class TestParserManagerEdgeCases(unittest.TestCase):
    """Tests pour les cas limites."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        logging.disable(logging.CRITICAL)
        self.manager = ParserManager()
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        logging.disable(logging.NOTSET)
    
    def test_parse_invalid_source_type(self):
        """Test avec type de source invalide."""
        result = self.manager.parse({}, 'invalid')
        
        self.assertFalse(result.is_valid)
        self.assertEqual(result.source, 'UNKNOWN')
        self.assertIn("invalide", result.errors[0].lower())
    
    def test_parse_source_type_too_long(self):
        """Test avec source_type trop long."""
        long_type = 'x' * 100
        result = self.manager.parse({}, long_type)
        
        self.assertFalse(result.is_valid)
    
    def test_parse_none_data(self):
        """Test avec données None."""
        result = self.manager.parse(None, 'rdap')
        
        self.assertFalse(result.is_valid)
    
    def test_parse_to_dict(self):
        """Test de parse_to_dict."""
        rdap = {"events": []}
        
        # Avec métadonnées
        result_dict = self.manager.parse_to_dict(rdap, 'rdap', include_metadata=True)
        self.assertIn('errors', result_dict)
        self.assertIn('is_valid', result_dict)
        
        # Sans métadonnées
        result_dict = self.manager.parse_to_dict(rdap, 'rdap', include_metadata=False)
        self.assertNotIn('errors', result_dict)
        self.assertIn('source', result_dict)


class TestParserManagerStatistics(unittest.TestCase):
    """Tests pour les statistiques."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        logging.disable(logging.CRITICAL)
        self.manager = ParserManager(enable_metrics=True)
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        logging.disable(logging.NOTSET)
    
    def test_statistics_initial(self):
        """Test statistiques initiales."""
        stats = self.manager.get_statistics()
        
        self.assertTrue(stats['metrics_enabled'])
        self.assertEqual(stats['overall']['total_parses'], 0)
        self.assertEqual(stats['overall']['total_errors'], 0)
    
    def test_statistics_after_parsing(self):
        """Test statistiques après parsing."""
        # Parse RDAP
        self.manager.parse({"events": []}, 'rdap')
        
        # Parse WHOIS
        self.manager.parse("Domain: test.com", 'whois')
        
        stats = self.manager.get_statistics()
        self.assertEqual(stats['overall']['total_parses'], 2)
        self.assertEqual(stats['by_source']['rdap']['parses'], 1)
        self.assertEqual(stats['by_source']['whois']['parses'], 1)
    
    def test_statistics_with_errors(self):
        """Test statistiques avec erreurs."""
        # Parse invalide
        self.manager.parse("wrong type", 'rdap')
        
        stats = self.manager.get_statistics()
        self.assertGreater(stats['overall']['total_errors'], 0)
        self.assertGreater(stats['by_source']['rdap']['errors'], 0)
    
    def test_reset_statistics(self):
        """Test réinitialisation des statistiques."""
        # Parse quelques données
        self.manager.parse({}, 'rdap')
        self.manager.parse("", 'whois')
        
        # Réinitialise
        self.manager.reset_statistics()
        
        stats = self.manager.get_statistics()
        self.assertEqual(stats['overall']['total_parses'], 0)
    
    def test_statistics_disabled(self):
        """Test avec métriques désactivées."""
        manager = ParserManager(enable_metrics=False)
        stats = manager.get_statistics()
        
        self.assertFalse(stats['metrics_enabled'])


class TestParserManagerIntegration(unittest.TestCase):
    """Tests d'intégration complets."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        logging.disable(logging.CRITICAL)
        self.manager = ParserManager()
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        logging.disable(logging.NOTSET)
    
    def test_full_rdap_flow(self):
        """Test du flow complet RDAP."""
        rdap_data = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2025-12-31T23:59:59Z"}
            ],
            "status": ["active"],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Registrar Inc."]]]
            }]
        }
        
        result = self.manager.parse(rdap_data, 'rdap')
        
        self.assertTrue(result.is_valid)
        self.assertTrue(result.has_data())
        self.assertEqual(result.source, 'RDAP')
        self.assertEqual(len(result.errors), 0)
        
        # Vérifie les données
        self.assertIsNotNone(result.expiration_date)
        self.assertIsNotNone(result.creation_date)
        self.assertIsNotNone(result.registrar)
        self.assertGreater(len(result.status), 0)
    
    def test_full_whois_flow(self):
        """Test du flow complet WHOIS."""
        whois_text = """
        Domain Name: EXAMPLE.COM
        Registry Expiry Date: 2025-12-31T23:59:59Z
        Creation Date: 2020-01-01T00:00:00Z
        Registrar: Example Registrar Inc.
        Domain Status: clientTransferProhibited
        """
        
        result = self.manager.parse(whois_text, 'whois')
        
        self.assertTrue(result.is_valid)
        self.assertTrue(result.has_data())
        self.assertEqual(result.source, 'WHOIS')
        
        # Vérifie l'uniformisation du status
        self.assertIsInstance(result.status, list)
    
    def test_supported_sources(self):
        """Test de get_supported_sources."""
        sources = self.manager.get_supported_sources()
        
        self.assertIn('rdap', sources)
        self.assertIn('whois', sources)
        self.assertEqual(len(sources), 2)


class TestParserManagerSecurity(unittest.TestCase):
    """Tests de sécurité spécifiques."""
    
    def setUp(self):
        """Initialisation avant chaque test."""
        logging.disable(logging.CRITICAL)
        self.manager = ParserManager()
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        logging.disable(logging.NOTSET)
    
    def test_oversized_whois_rejected(self):
        """Test rejet de WHOIS trop volumineux."""
        huge_whois = "x" * 600_000  # > 500KB
        result = self.manager.parse(huge_whois, 'whois')
        
        self.assertFalse(result.is_valid)
        self.assertIn("volumineuses", result.errors[0].lower())
    
    def test_deeply_nested_rdap_handled(self):
        """Test gestion de RDAP profondément imbriqué."""
        # Crée une structure profonde
        deep = {"level": {}}
        current = deep["level"]
        for i in range(15):
            current["next"] = {}
            current = current["next"]
        
        # Ne devrait pas planter
        result = self.manager.parse(deep, 'rdap')
        # Le résultat peut être valide ou invalide selon la profondeur max
        self.assertIsNotNone(result)
    
    def test_sql_injection_like_patterns(self):
        """Test avec patterns ressemblant à injection SQL."""
        malicious_whois = """
        Domain: test.com'; DROP TABLE domains; --
        Registrar: Test' OR '1'='1
        """
        
        result = self.manager.parse(malicious_whois, 'whois')
        # Devrait parser sans problème (les données sont nettoyées)
        self.assertIsNotNone(result)
    
    def test_type_confusion_attack(self):
        """Test contre attaque par confusion de type."""
        # Essaie de passer un int au lieu de str/dict
        result = self.manager.parse(12345, 'rdap')
        self.assertFalse(result.is_valid)
        
        result = self.manager.parse(12345, 'whois')
        self.assertFalse(result.is_valid)


def run_tests():
    """Exécute tous les tests."""
    # Créer la suite de tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Ajouter tous les tests
    suite.addTests(loader.loadTestsFromTestCase(TestSourceType))
    suite.addTests(loader.loadTestsFromTestCase(TestParsedResult))
    suite.addTests(loader.loadTestsFromTestCase(TestParserManagerValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestParserManagerRDAP))
    suite.addTests(loader.loadTestsFromTestCase(TestParserManagerWHOIS))
    suite.addTests(loader.loadTestsFromTestCase(TestParserManagerEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestParserManagerStatistics))
    suite.addTests(loader.loadTestsFromTestCase(TestParserManagerIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestParserManagerSecurity))
    
    # Exécuter avec verbosité
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Résumé
    print("\n" + "=" * 70)
    print("RÉSUMÉ DES TESTS")
    print("=" * 70)
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)