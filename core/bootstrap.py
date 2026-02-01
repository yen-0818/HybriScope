"""
Gestionnaire de Bootstrap RDAP avec validation intelligente
"""

import os
import json
import time
import urllib.request
import urllib.error
import ssl
import socket
import re
import hashlib
import hmac
import logging
from pathlib import Path
from typing import Optional, Dict, Set, Any, List
from urllib.parse import urlparse

from .validators import SmartRDAPValidator, WHOISServerValidator
from .exceptions import SecurityViolation, ValidationError, NetworkError

from .network import RDAPTransport, WHOISTransport

# Configuration du logging (Point 10)
logger = logging.getLogger(__name__)

class BootStrapManager:
     
    """
    Gestionnaire de Bootstrap RDAP de l'IANA
    
    Fonctionnalités:
    - Téléchargement et mise en cache du bootstrap IANA
    - Validation multi-niveaux des URLs RDAP
    - Découverte de serveurs WHOIS
    - Vérification d'intégrité (SHA-256)
    - Protection contre les attaques (TOCTOU, symlinks, etc.)
    """
     
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    CACHE_DIR = "cache"
    CACHE_FILENAME = "bootstrap_dns.json"
    CACHE_HASH_FILENAME = "bootstrap_dns.json.sha256"

    # Constantes de sécurité 
    CACHE_DURATION = 86400 # 24 heures
    TIMEOUT = 10
    MAX_RESPONSE_SIZE = 2 * 1024 * 1024 # 2 MB
    MAX_WHOIS_RESPONSE = 65536 # 64 KB
    MAX_JSON_DEPTH = 15
    MIN_RATE_LIMIT = 2.0  # secondes
    
    # Regex pour TLD et serveurs
    TLD_PATTERN = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.I)
    SERVER_PATTERN = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.I)


    def __init__(self):
        self._last_request_time = 0.0
        self.base_dir = Path.cwd().resolve()

        # On utilise les transporteurs officiels (qui intègrent déjà les validateurs)
        self.rdap_transport = RDAPTransport()
        self.whois_transport = WHOISTransport()

        # Initialiser les validateurs
        self.rdap_validator = SmartRDAPValidator(logger_instance=logger)
        self.whois_validator = WHOISServerValidator(logger_instance=logger)

        # Configuration des chemins
        self._setup_paths()

         # Chargement des données
        self.data = self._load_data()
    
    def _compute_hash(self, data: bytes) -> bytes:
        """Calcule le hash SHA-256 et le retourne sous forme de bytes (UTF-8)."""
        if not isinstance(data, bytes):
            # Sécurité au cas où des données non-bytes arriveraient
            data = str(data).encode('utf-8')
        
        # .hexdigest() donne un str, on ajoute .encode() pour obtenir des bytes
        return hashlib.sha256(data).hexdigest().encode('utf-8')

    def _setup_paths(self):
        """Configure et sécurise les chemins de cache"""
        cache_dir = (self.base_dir / self.CACHE_DIR).resolve()
        try:
            cache_dir.relative_to(self.base_dir)
        except ValueError:
            logger.critical("Tentative de Path Traversal bloquée sur le cache.")
            raise SecurityViolation("Chemin de cache invalide")
        
        os.makedirs(cache_dir, mode=0o755, exist_ok=True)

        self.cache_path = cache_dir / self.CACHE_FILENAME
        self.hash_path = cache_dir / self.CACHE_HASH_FILENAME

    def _safe_read(self, path: Path) -> Optional[bytes]:
        """
        Lecture sécurisée d'un fichier avec protection TOCTOU
        
        Args:
            path: Chemin du fichier
        
        Returns:
            Contenu du fichier en bytes ou None
        """
        if not path.exists() or path.is_symlink():
            return None
        
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY)
            stat = os.fstat(fd)
            # Vérifier taille
            if stat.st_size == 0 or stat.st_size > self.MAX_RESPONSE_SIZE:
                os.close(fd)
                return None
            
            # Utiliser fdopen qui prend ownership du FD
            with os.fdopen(fd, 'rb') as f: 
                return f.read(self.MAX_RESPONSE_SIZE)
            
        except Exception as e:
            if fd is not None:
                try: os.close(fd)
                except: pass
            logger.debug(f"Erreur lecture sécurisée {path}: {e}")
            return None

    def _load_data(self) -> Optional[Dict[str, Any]]:
        """Charge les données depuis le cache ou télécharge"""
        if not self.cache_path.exists():
            return self._refresh_bootstrap()

        # Vérifier l'âge du cache
        try:
            mtime = self.cache_path.stat().st_mtime
            if (time.time() - mtime) >= self.CACHE_DURATION:
                logger.info("Cache expiré, mise à jour...")
                return self._refresh_bootstrap()
        except OSError:
            return self._refresh_bootstrap()
        
        # Lire et valider le cache
        raw = self._safe_read(self.cache_path)
        stored_hash = self._safe_read(self.hash_path)

        if not raw or not stored_hash:
            return self._refresh_bootstrap()

        # Vérification d'intégrité (timing-safe)
        current_hash = self._compute_hash(raw)
        if not hmac.compare_digest(current_hash, stored_hash.strip()):
            logger.warning("Corruption cache détectée (Hash mismatch)")
            return self._refresh_bootstrap()

        # Parser et valider
        try:
            data = json.loads(raw.decode('utf-8'))
            if self._validate_structure(data):
                logger.info("Bootstrap chargé depuis le cache")
                return data
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Erreur parsing cache: {e}")

        return self._refresh_bootstrap()
    
    
    def _validate_structure(self, data: Any) -> bool:
        """
        Validation structurelle complète du bootstrap
        
        Args:
            data: Données JSON à valider
        
        Returns:
            True si valide, False sinon
        """
        # Validation profondeur (itérative)
        def check_depth(obj):
            stack = [(obj, 0)]
            while stack:
                current, depth = stack.pop()
                if depth > self.MAX_JSON_DEPTH:
                    return False
                if isinstance(current, dict):
                    for value in current.values():
                        stack.append((value, depth + 1))
                elif isinstance(current, list):
                    for item in current:
                        stack.append((item, depth + 1))
            return True

        if not isinstance(data, dict) or not check_depth(data):
            return False

        # Validation structure RDAP
        services = data.get('services')
        if not isinstance(services, list) or len(services) > 2000:
            return False
        
        discovered_domains: Set[str] = set()
        valid_services_count = 0

        for service in services:
            if not isinstance(service, list) or len(service) < 2: continue
            tlds, urls = service[0], service[1]
            if not isinstance(tlds, list) or not isinstance(urls, list): continue
            if len(tlds) > 1000 or len(urls) > 10:
                logger.warning(f"Entrée suspecte ignorée : trop de TLDs ({len(tlds)}) ou d'URLs ({len(urls)})")
                continue
            
            # Valider TLDs
            if not all(isinstance(t, str) and len(t) <= 63 for t in tlds): continue
            # Valider URLs avec contexte
            context_tld = tlds[0] if tlds else None
            for url in urls:
                if not isinstance(url, str):
                    continue
                is_valid, reason = self.rdap_validator.validate_url(url, context_tld)

                if is_valid:
                    # Si l'URL est valide, on l'ajoute à nos stats
                    try:
                        # Collecter les domaines validés
                        parsed = urlparse(url)
                        if parsed.hostname:
                            discovered_domains.add(parsed.hostname.lower())
                    except:
                        pass
                    valid_services_count += 1
                else:
                    # MODIFICATION ICI : On logue l'erreur mais on ne retourne pas False
                    # Cela permet d'ignorer le HTTP de certains TLDs (ex: .kg)
                    logger.warning(f"URL ignorée dans le bootstrap IANA: {url} - {reason}")
                
        if valid_services_count > 0:
            logger.info(f"Bootstrap validé : {len(discovered_domains)} domaines RDAP identifiés.")
            return True
    
        logger.error("Le bootstrap IANA ne contient aucune URL valide.")
        return False
                    
    
    def _atomic_write(self, data: bytes):
        """Écriture atomique du cache"""
        ts = int(time.time() * 1000)
        pid = os.getpid()

        tmp_cache = self.cache_path.with_name(f"{self.cache_path.name}.{pid}.{ts}.tmp")
        tmp_hash = self.hash_path.with_name(f"{self.hash_path.name}.{pid}.{ts}.tmp")
        
        try:
            # Écrire données
            with open(tmp_cache, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            
            # Écriture hash
            with open(tmp_hash, 'wb') as f:
                f.write(self._compute_hash(data))
                f.flush()
                os.fsync(f.fileno())
            
            # Remplacement atomique
            os.replace(tmp_cache, self.cache_path)
            os.replace(tmp_hash, self.hash_path)

            logger.info("Cache mis à jour avec succès")

        except OSError as e:
            logger.error(f"Échec écriture atomique: {e}")
            raise
        finally:
             # Nettoyage
            for p in [tmp_cache, tmp_hash]:
                try: 
                    if p.exists(): p.unlink()
                except: pass

    def _refresh_bootstrap(self) -> Optional[Dict[str, Any]]:
        """Télécharge et met à jour le bootstrap"""
        now = time.time()
        elapsed = now - self._last_request_time

        # Protection contre time warp
        if elapsed < 0:
            self._last_request_time = now
            elapsed = 0
        # Rate limiting
        if elapsed < self.MIN_RATE_LIMIT:
            time.sleep(self.MIN_RATE_LIMIT - elapsed)

        try:
            # 2. Délégation totale au transporteur
            # Le transporteur fait : Validation URL + SSL + Timeout + Read Max Size
            data = self.rdap_transport.fetch(self.BOOTSTRAP_URL)
            self._last_request_time = time.time()

            # 3. Validation de la structure spécifique à IANA
            if self._validate_structure(data):
                # On reconvertit en bytes uniquement pour le cache local
                raw_json = json.dumps(data).encode('utf-8')
                self._atomic_write(raw_json)
                logger.info("Bootstrap IANA mis à jour avec succès")
                return data
            else:
                logger.error("Structure du bootstrap IANA invalide ou corrompue")
                
        except NetworkError as e:
            logger.error(f"Erreur réseau lors de la mise à jour IANA: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue: {type(e).__name__}")
            
        return None
    
    def get_rdap_url(self, tld: str) -> Optional[str]:
        """
        Récupère l'URL RDAP pour un TLD
        
        Args:
            tld: TLD à rechercher
        
        Returns:
            URL RDAP ou None
        """
        tld_clean = self._sanitize_tld(tld)
        if not tld_clean or not self.data:
            return None
        
        services = self.data.get('services', [])
        for service in services:
            if len(service) >= 2 and isinstance(service[0], list):
                if tld_clean in service[0]:
                    urls = service[1]
                    if isinstance(urls, list):
                        for url in urls:
                            is_valid, _ = self.rdap_validator.validate_url(url, tld_clean)
                            if is_valid:
                                return url
        return None
    
    def get_whois_server(self, tld: str) -> Optional[str]:
        """
        Découvre le serveur WHOIS pour un TLD
        
        Args:
            tld: TLD à rechercher
        
        Returns:
            Serveur WHOIS ou None
        """
        tld_clean = self._sanitize_tld(tld)
        if not tld_clean: return None

        try:
            response_text = self.whois_transport.query("whois.iana.org", tld_clean)
            for line in response_text.splitlines()[:100]:
                line = line.strip()
                if not line or len(line) > 500: 
                    continue
                if line.lower().startswith('whois:'):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        srv = parts[1].strip().lower()
                        
                        # 3. Validation via le validateur intégré au transporteur
                        is_valid, reason = self.whois_transport.validator.validate_server(srv)
                        if is_valid:
                            return srv
                        else:
                            logger.debug(f"Serveur WHOIS suggéré par IANA rejeté: {srv} ({reason})")

        except NetworkError as e:
            logger.debug(f"Échec de la découverte WHOIS pour {tld_clean}: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue lors de la découverte WHOIS: {type(e).__name__}")

        # 4. Fallback intelligent (toujours validé)
        fallback = f"whois.nic.{tld_clean}"
        is_valid, _ = self.whois_transport.validator.validate_server(fallback)
        
        if is_valid:
            logger.info(f"Utilisation du fallback WHOIS pour {tld_clean}: {fallback}")
            return fallback
            
        return None
    
    def _sanitize_tld(self, tld: str) -> Optional[str]:
        """
        Nettoie et valide un TLD
        
        Args:
            tld: TLD à valider
        
        Returns:
            TLD nettoyé ou None
        """
        if not isinstance(tld, str): return None
        tld_clean = tld.lower().strip().lstrip('.')
        
        if not tld_clean or len(tld_clean) > 63:
            return None
        
        # Validation punycode
        if tld_clean.startswith('xn--'):
            try:
                tld_clean.encode('ascii').decode('idna')
            except (UnicodeError, UnicodeDecodeError): return None
            
        return tld_clean if self.TLD_PATTERN.match(tld_clean) else None
    
    def get_validator_statistics(self) -> Dict[str, Any]:
        """
        Retourne les statistiques du validateur RDAP
        
        Returns:
            Dictionnaire contenant:
            - total_validations: Nombre total de validations
            - cache_hits: Nombre de hits cache
            - cache_size: Taille actuelle du cache
            - cache_hit_rate: Taux de hit du cache (%)
            - level_X_accepts/rejections: Compteurs par niveau
        
        Example:
            >>> manager = BootStrapManager()
            >>> stats = manager.get_validator_statistics()
            >>> print(stats)
            {
                'total_validations': 150,
                'cache_hits': 45,
                'cache_size': 120,
                'cache_hit_rate': 30.0,
                'level_1_accepts': 80,
                'level_2_accepts': 25,
                ...
            }
        """
        return self.rdap_validator.get_statistics()
    

    

    

    