import re
from typing import Dict, Optional, List
import logging
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ParseResult:
    """Résultat structuré du parsing WHOIS."""
    expiration_date: Optional[str] = None
    creation_date: Optional[str] = None
    registrar: Optional[str] = None
    status: Optional[str] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []

class WhoisParser:
    """Transforme le texte brut WHOIS en dictionnaire de chaînes sécurisé."""
    
    # Limites de sécurité
    MAX_INPUT_SIZE = 100_000  # 100KB max
    MAX_LINE_LENGTH = 1000
    REGEX_TIMEOUT = 1.0  # 1 seconde max par regex
    MAX_MATCH_LENGTH = 500  # Longueur max d'une valeur extraite
    
    # Patterns compilés avec limites
    PATTERNS = {
        'expiration_date': [
            re.compile(r"Registry Expiry Date:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE),
            re.compile(r"Expiration Date:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE),
            re.compile(r"Expiry Date:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE),
            re.compile(r"expires:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE)
        ],
        'creation_date': [
            re.compile(r"Creation Date:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE),
            re.compile(r"Registered on:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE),
            re.compile(r"created:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE)
        ],
        'registrar': [
            re.compile(r"Registrar:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE),
            re.compile(r"registrar:\s*(.{1,200}?)(?:\n|$)", re.IGNORECASE)
        ],
        'status': [
            re.compile(r"Domain Status:\s*([\w\-]{1,100})(?:\s|$)", re.IGNORECASE),
            re.compile(r"Status:\s*([\w\-]{1,100})(?:\s|$)", re.IGNORECASE)
        ]
    }
    
    # Caractères interdits dans les valeurs extraites
    FORBIDDEN_CHARS = re.compile(r'[<>\"\'`;&|$()]')
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialise le parser avec un logger optionnel."""
        self.logger = logger or logging.getLogger(__name__)
    
    def _validate_input(self, raw_text: str) -> bool:
        """Valide l'entrée avant le parsing."""
        if not isinstance(raw_text, str):
            self.logger.warning("Input n'est pas une chaîne de caractères")
            return False
        
        if len(raw_text) > self.MAX_INPUT_SIZE:
            self.logger.warning(f"Input trop large: {len(raw_text)} octets")
            return False
        
        # Vérifie les lignes anormalement longues (potentiel DoS)
        lines = raw_text.split('\n')
        for i, line in enumerate(lines[:100]):  # Vérifie seulement les 100 premières lignes
            if len(line) > self.MAX_LINE_LENGTH:
                self.logger.warning(f"Ligne {i} trop longue: {len(line)} caractères")
                return False
        
        return True
    
    def _sanitize_value(self, value: str) -> Optional[str]:
        """Nettoie et valide une valeur extraite."""
        if not value:
            return None
        
        # Retire les espaces excessifs
        value = ' '.join(value.split())
        
        # Limite la longueur
        if len(value) > self.MAX_MATCH_LENGTH:
            self.logger.warning(f"Valeur tronquée: {len(value)} caractères")
            value = value[:self.MAX_MATCH_LENGTH]
        
        # Vérifie les caractères dangereux
        if self.FORBIDDEN_CHARS.search(value):
            self.logger.warning(f"Caractères suspects détectés dans: {value[:50]}")
            # Option 1: Rejeter complètement
            # return None
            # Option 2: Nettoyer (plus permissif)
            value = self.FORBIDDEN_CHARS.sub('', value)
        
        # Retire les caractères de contrôle
        value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t')
        
        return value.strip() if value.strip() else None
    
    def _safe_regex_search(self, pattern: re.Pattern, text: str) -> Optional[re.Match]:
        """Exécute une recherche regex avec protection contre ReDoS."""
        try:
            # Note: Python n'a pas de timeout natif pour regex
            # Pour une protection complète, utilisez le module 'regex' avec timeout
            # import regex
            # return regex.search(pattern, text, timeout=self.REGEX_TIMEOUT)
            
            return pattern.search(text)
        except Exception as e:
            self.logger.error(f"Erreur regex: {e}")
            return None
    
    def parse(self, raw_text: str) -> ParseResult:
        """
        Parse le texte WHOIS de manière sécurisée.
        
        Args:
            raw_text: Texte brut WHOIS
            
        Returns:
            ParseResult avec les données extraites et erreurs éventuelles
        """
        result = ParseResult()
        
        # Validation de l'entrée
        if not self._validate_input(raw_text):
            result.errors.append("Validation de l'entrée échouée")
            return result
        
        # Normalise le texte (retire les retours chariot Windows)
        raw_text = raw_text.replace('\r\n', '\n')
        
        # Parse chaque champ
        for key, patterns in self.PATTERNS.items():
            value = None
            for pattern in patterns:
                match = self._safe_regex_search(pattern, raw_text)
                if match and match.group(1):
                    raw_value = match.group(1)
                    value = self._sanitize_value(raw_value)
                    if value:
                        break
            
            setattr(result, key, value)
        
        # Log si aucune donnée n'a été extraite (potentiel scan malveillant)
        if all(getattr(result, field) is None 
               for field in ['expiration_date', 'creation_date', 'registrar', 'status']):
            self.logger.info("Aucune donnée WHOIS extraite du texte fourni")
            result.errors.append("Aucune donnée valide trouvée")
        
        return result
    
    def parse_to_dict(self, raw_text: str) -> Dict[str, Optional[str]]:
        """
        Version compatible avec l'ancienne interface.
        
        Args:
            raw_text: Texte brut WHOIS
            
        Returns:
            Dictionnaire avec les champs extraits
        """
        result = self.parse(raw_text)
        return {
            'expiration_date': result.expiration_date,
            'creation_date': result.creation_date,
            'registrar': result.registrar,
            'status': result.status
        }

