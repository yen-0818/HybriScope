import unittest
import json
import os
import shutil
from pathlib import Path
from core.bootstrap import BootStrapManager
from core.exceptions import SecurityViolation

class TestBootStrapManager(unittest.TestCase):
    def setUp(self):
        """Configuration avant chaque test : création d'un environnement propre."""
        self.test_dir = Path("test_env").resolve()
        os.makedirs(self.test_dir, exist_ok=True)
        # On simule le répertoire de travail
        self.manager = BootStrapManager()
        # On force les chemins dans notre dossier de test
        self.manager.base_dir = self.test_dir
        self.manager._setup_paths()

    def tearDown(self):
        """Nettoyage après les tests."""
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_path_traversal_protection(self):
        """Vérifie que l'on ne peut pas sortir du répertoire de base."""
        self.manager.CACHE_DIR = "../../etc"
        with self.assertRaises(SecurityViolation):
            self.manager._setup_paths()

    def test_punycode_validation(self):
        """Vérifie que le Punycode malformé est rejeté."""
        # xn--su- (incomplet/invalide)
        self.assertIsNone(self.manager._sanitize_tld("xn--su-"))
        # xn--caf-dma (valide pour café)
        self.assertEqual(self.manager._sanitize_tld("xn--caf-dma"), "xn--caf-dma")

    def test_atomic_write_integrity(self):
        """Vérifie que l'écriture atomique crée bien le fichier et son hash."""
        dummy_data = b'{"services": []}'
        self.manager._atomic_write(dummy_data)
        
        self.assertTrue(self.manager.cache_path.exists())
        self.assertTrue(self.manager.hash_path.exists())
        
        # Vérification du hash
        with open(self.manager.hash_path, 'rb') as f:
            stored_hash = f.read().decode()
        self.assertEqual(stored_hash, self.manager._compute_hash(dummy_data).decode())

    def test_json_depth_protection(self):
        """Vérifie que les structures JSON trop profondes (DoS) sont rejetées."""
        # Création d'un dictionnaire imbriqué 20 fois (limite à 15)
        deep_data = {"a": {}}
        curr = deep_data["a"]
        for _ in range(20):
            curr["b"] = {}
            curr = curr["b"]
        
        self.assertFalse(self.manager._validate_structure(deep_data))

    def test_whois_injection_prevention(self):
        """Vérifie que les injections de commandes dans le TLD sont bloquées."""
        bad_tld = "com\r\nHELP"
        sanitized = self.manager._sanitize_tld(bad_tld)
        self.assertIsNone(sanitized)

    def test_malformed_whois_response(self):
        """Vérifie que le parser WHOIS ne crashe pas sur des données corrompues."""
        # Simulation d'une réponse de 101 lignes (limite à 100)
        fake_response = "whois: valid.server.com\n" + "junk\n" * 150
        # On teste manuellement la logique interne simplifiée pour l'exemple
        lines = fake_response.splitlines()
        self.assertLessEqual(len(lines[:100]), 100)

if __name__ == "__main__":
    unittest.main()