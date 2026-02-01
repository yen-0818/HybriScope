"""
Validateurs intelligents pour les URLs RDAP et serveurs WHOIS
"""

import re
import logging
import hashlib
from typing import Optional, Set, Dict, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SmartRDAPValidator:
    """
    Validateur RDAP avec approche multi-niveaux
    
    Niveaux de validation :
    - Niveau 0 : Blacklist (rejet immédiat)
    - Niveau 1 : Whitelist haute confiance
    - Niveau 2 : Patterns de confiance (regex)
    - Niveau 3 : Registrars connus
    - Niveau 4 : Validation contextuelle (avec TLD)
    - Niveau 5 : Rejet par défaut (principe du moindre privilège)
    """
    
    # Niveau 1 : Whitelist Haute Confiance
    TRUSTED_DOMAINS: Set[str] = {
        # Infrastructure IANA officielle
        'rdap.iana.org',
        'data.iana.org',
        
        # Registres gTLD majeurs
        'rdap.verisign.com',              # .com, .net
        'rdap.afilias-srs.net',           # .org, .info
        'rdap.identitydigital.services',  # Identity Digital (300+ TLDs)
        'rdap.centralnic.com',            # .xyz, .online, etc.
        'rdap.nic.google',                # Google Registry
        'rdap.registry.google',           # Google Registry alt
        'rdap.nic.amazonregistry.com',    # Amazon
        'rdap.godaddy.com',               # GoDaddy Registry
        'rdap.donuts.co',                 # Donuts (legacy)
        
        # Opérateurs multi-TLD
        'rdap.publicinterestregistry.org', # PIR (.org)
        'rdap.pir.org',                    # PIR alt
        'rdap.neustar.biz',                # Neustar
        'rdap.registryservices.com',       # Registry Services
        
        # ccTLD majeurs (Top 30)
        'rdap.nic.uk',         # Royaume-Uni
        'rdap.nominet.uk',     # UK alt
        'rdap.nic.fr',         # France
        'rdap.denic.de',       # Allemagne
        'rdap.dns.be',         # Belgique
        'rdap.nic.ch',         # Suisse
        'rdap.nic.it',         # Italie
        'rdap.nic.nl',         # Pays-Bas
        'rdap.nic.es',         # Espagne
        'rdap.nic.ca',         # Canada
        'rdap.nic.au',         # Australie
        'rdap.jprs.jp',        # Japon
        'rdap.kr',             # Corée du Sud
        'rdap.nic.in',         # Inde
        'rdap.registro.br',    # Brésil
        'rdap.nic.cn',         # Chine
        'rdap.nic.ru',         # Russie
        'rdap.nic.mx',         # Mexique
        'rdap.nic.se',         # Suède
        'rdap.nic.pl',         # Pologne
        'rdap.nic.tr',         # Turquie
        'rdap.nic.za',         # Afrique du Sud
        'rdap.nic.ar',         # Argentine
        'rdap.nic.cl',         # Chili
        'rdap.nic.nz',         # Nouvelle-Zélande
        'rdap.nic.sg',         # Singapour
        'rdap.nic.at',         # Autriche
        'rdap.nic.dk',         # Danemark
        'rdap.nic.no',         # Norvège
        'rdap.nic.fi',         # Finlande
    }
    
    # Niveau 2 : Patterns validés
    TRUSTED_PATTERNS = [
        r'^rdap\.nic\.[a-z]{2,3}$',              # ccTLD standard : rdap.nic.jp
        r'^rdap\.nic\.[a-z]{2}\.[a-z]{2}$',      # Sous-domaines : rdap.nic.co.uk
        r'^rdap\.registry\.google$',              # Google variants
        r'^rdap\.[a-z0-9-]+\.verisign\.com$',    # Verisign subdomains
        r'^rdap-pilot\.verisign\.com$',           # Verisign pilot
        r'^rdap\.nic\.[a-z0-9-]+\.ar$',          # Argentine patterns
        r'^rdap\d*\.nic\.[a-z]+$',               # Patterns avec numéros (rdap2.nic.fr)
        r'^rdap\.[a-z]{2,3}$',                   # Format court (rdap.kr)
    ]
    
    # Niveau 3 : Registrars connus
    KNOWN_REGISTRARS = {
        'donuts.co',
        'identity-digital.services',
        'identitydigital.services',
        'centralnic.com',
        'afilias-srs.net',
        'neustar.biz',
        'nic.google',
        'registry.google',
        'amazonregistry.com',
        'registryservices.com',
        'publicinterestregistry.org',
        'pir.org',
        'verisign.com',
    }
    
    # Niveau 0 : Patterns interdits (blacklist)
    FORBIDDEN_PATTERNS = [
        r'.*\.onion$',                             # Tor
        r'.*localhost.*',                          # Localhost
        r'.*127\.0\.0\.1.*',                       # Loopback
        r'.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*', # IP directe
        r'.*\.local$',                             # mDNS
        r'.*\.internal$',                          # Réseaux internes
        r'.*\.test$',                              # Domaine test
        r'.*\.example$',                           # Domaine exemple
        r'.*\.invalid$',                           # Domaine invalide (RFC 2606)
    ]
    
    # Configuration du cache
    CACHE_TTL = timedelta(hours=24)
    MAX_CACHE_SIZE = 10000

    def __init__(self, logger_instance: Optional[logging.Logger] = None):
        """
        Initialise le validateur RDAP
        
        Args:
            logger_instance: Instance de logger personnalisée (optionnel)
        """
        self.logger = logger_instance or logger
        self._validation_cache: Dict[str, Tuple[bool, str, datetime]] = {}
        self._stats = {
            'total_validations': 0,
            'cache_hits': 0,
            'level_0_rejections': 0,  # Blacklist
            'level_1_accepts': 0,      # Whitelist
            'level_2_accepts': 0,      # Patterns
            'level_3_accepts': 0,      # Registrars
            'level_4_accepts': 0,      # Contexte
            'level_5_rejections': 0,   # Défaut
        }
    
    def validate_url(self, url: str, tld: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validation multi-niveaux d'une URL RDAP
        
        Args:
            url: URL à valider
            tld: TLD associé pour validation contextuelle (optionnel)
        
        Returns:
            (is_valid, reason): Tuple (booléen de validation, raison)
        """
        self._stats['total_validations'] += 1
        
        if not url or not isinstance(url, str):
            return False, "URL invalide ou vide"
        
        # Vérification cache
        cache_key = self._get_cache_key(url, tld)
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            self._stats['cache_hits'] += 1
            return cached_result
        
        # Validation de base
        if not url.startswith('https://'):
            result = (False, "Protocole non-HTTPS")
            self._cache_result(cache_key, result)
            return result
        
        if len(url) > 500:
            result = (False, "URL trop longue (>500 caractères)")
            self._cache_result(cache_key, result)
            return result
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname or len(hostname) > 253:
                result = (False, "Hostname invalide ou trop long")
                self._cache_result(cache_key, result)
                return result
            
            hostname = hostname.lower()
            
            # NIVEAU 0 : Blacklist (rejet immédiat)
            for pattern in self.FORBIDDEN_PATTERNS:
                if re.match(pattern, hostname):
                    self._stats['level_0_rejections'] += 1
                    result = (False, f"Pattern interdit détecté")
                    self._cache_result(cache_key, result)
                    return result
            
            # NIVEAU 1 : Whitelist haute confiance
            if hostname in self.TRUSTED_DOMAINS:
                self._stats['level_1_accepts'] += 1
                result = (True, "Domaine de confiance (whitelist)")
                self._cache_result(cache_key, result)
                return result
            
            # NIVEAU 2 : Patterns de confiance
            for pattern in self.TRUSTED_PATTERNS:
                if re.match(pattern, hostname):
                    self._stats['level_2_accepts'] += 1
                    result = (True, f"Pattern de confiance validé")
                    self._cache_result(cache_key, result)
                    return result
            
            # NIVEAU 3 : Validation par registrar connu
            parts = hostname.split('.')
            if len(parts) >= 3:
                registrar = '.'.join(parts[-2:])
                if registrar in self.KNOWN_REGISTRARS:
                    if parts[0].startswith('rdap'):
                        self._stats['level_3_accepts'] += 1
                        result = (True, f"Registrar connu: {registrar}")
                        self._cache_result(cache_key, result)
                        return result
            
            # NIVEAU 4 : Validation contextuelle (si TLD fourni)
            if tld:
                tld_lower = tld.lower().lstrip('.')
                
                # Pattern: rdap.nic.{tld}
                if hostname == f"rdap.nic.{tld_lower}":
                    self._stats['level_4_accepts'] += 1
                    result = (True, f"Pattern TLD-spécifique: rdap.nic.{tld_lower}")
                    self._cache_result(cache_key, result)
                    return result
                
                # Pattern: rdap.{tld}
                if hostname == f"rdap.{tld_lower}":
                    self._stats['level_4_accepts'] += 1
                    result = (True, f"Pattern TLD direct: rdap.{tld_lower}")
                    self._cache_result(cache_key, result)
                    return result
                
                # Pattern: rdap.registry.{tld}
                if hostname == f"rdap.registry.{tld_lower}":
                    self._stats['level_4_accepts'] += 1
                    result = (True, f"Pattern registry TLD: rdap.registry.{tld_lower}")
                    self._cache_result(cache_key, result)
                    return result
            
            # NIVEAU 5 : Rejet par défaut (principe du moindre privilège)
            self._stats['level_5_rejections'] += 1
            self.logger.warning(f"URL RDAP rejetée (non reconnue): {hostname}")
            result = (False, f"Domaine non reconnu: {hostname}")
            self._cache_result(cache_key, result)
            return result
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la validation URL: {e}")
            result = (False, f"Erreur de parsing: {type(e).__name__}")
            self._cache_result(cache_key, result)
            return result
    
    def _get_cache_key(self, url: str, tld: Optional[str]) -> str:
        """Génère une clé de cache unique"""
        key_data = f"{url}|{tld or ''}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _get_from_cache(self, key: str) -> Optional[Tuple[bool, str]]:
        """Récupère un résultat depuis le cache"""
        if key in self._validation_cache:
            is_valid, reason, timestamp = self._validation_cache[key]
            if datetime.now() - timestamp < self.CACHE_TTL:
                return (is_valid, reason)
            else:
                # Entrée expirée
                del self._validation_cache[key]
        return None
    
    def _cache_result(self, key: str, result: Tuple[bool, str]):
        """Met en cache un résultat de validation"""
        self._validation_cache[key] = (*result, datetime.now())
        
        # Nettoyage périodique
        if len(self._validation_cache) > self.MAX_CACHE_SIZE:
            self._cleanup_cache()
    
    def _cleanup_cache(self):
        """Nettoie les entrées expirées du cache"""
        now = datetime.now()
        expired_keys = [
            k for k, (_, _, ts) in self._validation_cache.items()
            if now - ts >= self.CACHE_TTL
        ]
        
        for k in expired_keys:
            del self._validation_cache[k]
        
        self.logger.debug(f"Cache nettoyé: {len(expired_keys)} entrées supprimées")
    
    def add_trusted_domain(self, domain: str, source: str = "manual"):
        """
        Ajoute dynamiquement un domaine à la whitelist
        
        Args:
            domain: Domaine à ajouter
            source: Source de l'ajout (pour logging)
        """
        domain_lower = domain.lower()
        
        if self._is_valid_hostname(domain_lower):
            self.TRUSTED_DOMAINS.add(domain_lower)
            self.logger.info(f"Domaine ajouté à la whitelist ({source}): {domain_lower}")
        else:
            self.logger.warning(f"Tentative d'ajout d'un hostname invalide: {domain}")
    
    def _is_valid_hostname(self, hostname: str) -> bool:
        """Valide le format d'un hostname"""
        if not hostname or len(hostname) > 253:
            return False
        
        pattern = re.compile(
            r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
            re.IGNORECASE
        )
        return bool(pattern.match(hostname))
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Retourne les statistiques de validation
        
        Returns:
            Dictionnaire des statistiques
        """
        return {
            **self._stats,
            'cache_size': len(self._validation_cache),
            'cache_hit_rate': (
                self._stats['cache_hits'] / self._stats['total_validations'] * 100
                if self._stats['total_validations'] > 0 else 0
            )
        }
    
    def clear_cache(self):
        """Vide complètement le cache de validation"""
        self._validation_cache.clear()
        self.logger.info("Cache de validation vidé")


class WHOISServerValidator:
    """Validateur pour les serveurs WHOIS"""
    
    # Pattern strict pour FQDN
    SERVER_PATTERN = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
        re.IGNORECASE
    )
    
    def __init__(self, logger_instance: Optional[logging.Logger] = None):
        self.logger = logger_instance or logger
    
    def validate_server(self, server: str) -> Tuple[bool, str]:
        """
        Valide un nom de serveur WHOIS
        
        Args:
            server: Nom du serveur à valider
        
        Returns:
            (is_valid, reason): Tuple (booléen, raison)
        """
        if not server or not isinstance(server, str):
            return False, "Serveur invalide ou vide"
        
        server_lower = server.lower().strip()
        
        # Vérifications de base
        if len(server_lower) < 4 or len(server_lower) > 253:
            return False, "Longueur invalide (4-253 caractères)"
        
        # Caractères interdits
        if server_lower.startswith('.') or server_lower.endswith('.'):
            return False, "Points au début/fin interdits"
        
        if server_lower.startswith('-') or server_lower.endswith('-'):
            return False, "Tirets au début/fin interdits"
        
        if '..' in server_lower or '--' in server_lower:
            return False, "Caractères doubles interdits"
        
        # Validation pattern global
        if not self.SERVER_PATTERN.match(server_lower):
            return False, "Format FQDN invalide"
        
        # Validation des labels
        labels = server_lower.split('.')
        for label in labels:
            if len(label) == 0 or len(label) > 63:
                return False, f"Label invalide: {label}"
            
            if label.startswith('-') or label.endswith('-'):
                return False, f"Label avec tirets interdits: {label}"
        
        # Le TLD doit être alphabétique (min 2 lettres)
        tld = labels[-1]
        if not re.match(r'^[a-z]{2,}$', tld):
            return False, f"TLD invalide: {tld}"
        
        return True, "Serveur WHOIS valide"