import socket
import ssl
import urllib.request
import urllib.error
import logging
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from .exceptions import NetworkError

# Importation de tes validateurs intelligents
from .validators import SmartRDAPValidator, WHOISServerValidator

logger = logging.getLogger(__name__)

class BaseTransport:
    """Logique commune : Timeouts, Rate Limiting et Taille Max."""
    TIMEOUT = 10
    CHUNK_TIMEOUT = 5
    MAX_SIZE = 1024 * 1024  # 1 MB
    MAX_REQUESTS_PER_MINUTE = 10
    USER_AGENT = "HybriScope/2.0"

    def __init__(self):
        self._rate_limiter = defaultdict(list)

    def _check_rate_limit(self, identifier: str):
        """Vérifie si on ne bombarde pas un serveur (protection contre le ban)."""
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)
        self._rate_limiter[identifier] = [ts for ts in self._rate_limiter[identifier] if ts > cutoff]
        
        if len(self._rate_limiter[identifier]) >= self.MAX_REQUESTS_PER_MINUTE:
            raise NetworkError(f"Rate limit atteint pour {identifier}. Attendez 1 min.")
        self._rate_limiter[identifier].append(now)

class RDAPTransport(BaseTransport):
    """Transporteur RDAP utilisant le SmartRDAPValidator."""
    
    def __init__(self):
        super().__init__()
        self.validator = SmartRDAPValidator()  # Injection du cerveau
        self.context = ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def fetch(self, url: str) -> Dict[str, Any]:
        import json
        
        # 1. VALIDATION via le module validator.py
        is_valid, reason = self.validator.validate_url(url)
        if not is_valid:
            logger.error(f"Validation RDAP rejetée : {reason}")
            raise NetworkError(f"URL non autorisée : {reason}")

        # 2. RATE LIMITING
        hostname = urllib.parse.urlparse(url).hostname
        self._check_rate_limit(hostname)

        # 3. EXÉCUTION
        req = urllib.request.Request(url, headers={'User-Agent': self.USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.TIMEOUT, context=self.context) as resp:
                raw_data = resp.read(self.MAX_SIZE)
                return json.loads(raw_data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Erreur réseau RDAP sur {hostname}: {type(e).__name__}")
            raise NetworkError(f"Erreur de connexion RDAP")

class WHOISTransport(BaseTransport):
    """Transporteur WHOIS utilisant le WHOISServerValidator."""

    def __init__(self):
        super().__init__()
        self.validator = WHOISServerValidator() # Injection du cerveau

    def query(self, server: str, query: str) -> str:
        # 1. VALIDATION du serveur
        is_valid, reason = self.validator.validate_server(server)
        if not is_valid:
            raise NetworkError(f"Serveur WHOIS invalide : {reason}")

        # 2. VALIDATION de la requête (on garde la regex de base ici par simplicité)
        if not query.replace('.', '').replace('-', '').isalnum():
            raise NetworkError("Caractères interdits dans la requête WHOIS")

        # 3. RATE LIMITING
        self._check_rate_limit(server)

        # 4. EXÉCUTION (Socket TCP)
        try:
            with socket.create_connection((server, 43), timeout=self.TIMEOUT) as s:
                s.sendall(f"{query}\r\n".encode('ascii'))
                response = b""
                while len(response) < self.MAX_SIZE:
                    s.settimeout(self.CHUNK_TIMEOUT)
                    chunk = s.recv(4096)
                    if not chunk: break
                    response += chunk
                return response.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Erreur WHOIS sur {server}: {type(e).__name__}")
            raise NetworkError("Échec de la requête WHOIS")