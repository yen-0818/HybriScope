"""
Manager sécurisé pour orchestrer les parsers WHOIS et RDAP.

Ce module fournit une interface unifiée pour parser des données de domaine
provenant de différentes sources (WHOIS et RDAP), avec validation robuste,
gestion d'erreurs complète et métriques de monitoring.
"""

import logging
from typing import Dict, Any, Union, Optional, List
from enum import Enum
from dataclasses import dataclass, field

# Import des parsers locaux
try:
    from .whois_parser import WhoisParser, ParseResult as WhoisParseResult
except ImportError:
    from whois_parser import WhoisParser, ParseResult as WhoisParseResult

try:
    from .rdap_parser import RDAPParser, RDAPParseResult
except ImportError:
    from rdap_parser import RDAPParser, RDAPParseResult


logger = logging.getLogger(__name__)


class SourceType(Enum):
    """Types de sources de données supportés."""
    RDAP = "rdap"
    WHOIS = "whois"
    
    @classmethod
    def from_string(cls, value: str) -> Optional['SourceType']:
        """
        Convertit une chaîne en SourceType de manière sécurisée.
        
        Args:
            value: Chaîne à convertir
            
        Returns:
            SourceType correspondant ou None si invalide
        """
        if not isinstance(value, str):
            return None
        
        value_lower = value.lower().strip()
        for source_type in cls:
            if source_type.value == value_lower:
                return source_type
        return None
    
    @classmethod
    def get_valid_types(cls) -> List[str]:
        """Retourne la liste des types valides."""
        return [st.value for st in cls]


@dataclass
class ParsedResult:
    """
    Résultat unifié du parsing avec métadonnées complètes.
    
    Cette structure uniformise les résultats des différents parsers
    et ajoute des métadonnées pour le monitoring et le debugging.
    """
    expiration_date: Optional[str] = None
    creation_date: Optional[str] = None
    registrar: Optional[str] = None
    status: List[str] = field(default_factory=list)
    source: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_valid: bool = True
    
    def to_dict(self, include_metadata: bool = True) -> Dict[str, Any]:
        """
        Convertit le résultat en dictionnaire.
        
        Args:
            include_metadata: Si True, inclut errors/warnings/is_valid
            
        Returns:
            Dictionnaire avec les données parsées
        """
        base_dict = {
            'expiration_date': self.expiration_date,
            'creation_date': self.creation_date,
            'registrar': self.registrar,
            'status': self.status,
            'source': self.source
        }
        
        if include_metadata:
            base_dict.update({
                'errors': self.errors,
                'warnings': self.warnings,
                'is_valid': self.is_valid
            })
        
        return base_dict
    
    def has_data(self) -> bool:
        """Vérifie si au moins une donnée utile a été extraite."""
        return any([
            self.expiration_date,
            self.creation_date,
            self.registrar,
            len(self.status) > 0
        ])


class ParserManager:
    """
    Orchestrateur sécurisé des parsers WHOIS et RDAP.
    
    Ce gestionnaire:
    - Valide les entrées avant parsing
    - Route les données vers le bon parser
    - Uniformise les résultats
    - Collecte des métriques
    - Gère les erreurs de manière robuste
    
    Examples:
        >>> manager = ParserManager()
        >>> result = manager.parse(rdap_data, 'rdap')
        >>> if result.is_valid:
        ...     print(f"Expiration: {result.expiration_date}")
        ... else:
        ...     print(f"Erreurs: {result.errors}")
    """
    
    # Limites de sécurité
    MAX_RAW_STRING_SIZE = 500_000  # 500KB max pour WHOIS brut
    MAX_DICT_KEYS = 1000  # Limite pour les dictionnaires RDAP
    MAX_SOURCE_TYPE_LENGTH = 50  # Longueur max du type de source
    MAX_RECURSION_DEPTH = 10  # Profondeur max pour compter les clés
    
    def __init__(self, 
                 whois_parser: Optional[WhoisParser] = None,
                 rdap_parser: Optional[RDAPParser] = None,
                 logger_instance: Optional[logging.Logger] = None,
                 enable_metrics: bool = True):
        """
        Initialise le gestionnaire de parsers.
        
        Args:
            whois_parser: Instance personnalisée de WhoisParser (optionnel)
            rdap_parser: Instance personnalisée de RDAPParser (optionnel)
            logger_instance: Instance de logger personnalisée (optionnel)
            enable_metrics: Active/désactive la collecte de métriques
        """
        self.logger = logger_instance or logger
        self.enable_metrics = enable_metrics
        
        # Initialisation des parsers
        self.whois_parser = whois_parser or WhoisParser(logger=self.logger)
        self.rdap_parser = rdap_parser or RDAPParser(logger=self.logger)
        
        # Métriques
        self._parse_count = {'rdap': 0, 'whois': 0, 'unknown': 0}
        self._error_count = {'rdap': 0, 'whois': 0, 'validation': 0}
        self._warning_count = {'rdap': 0, 'whois': 0}
        
        self.logger.info("ParserManager initialisé avec succès")
    
    def _validate_source_type(self, source_type: str) -> Optional[SourceType]:
        """
        Valide et convertit le type de source.
        
        Args:
            source_type: Type de source à valider
            
        Returns:
            SourceType validé ou None si invalide
        """
        if not isinstance(source_type, str):
            self.logger.error(
                f"source_type invalide: type {type(source_type).__name__} "
                f"au lieu de str"
            )
            self._increment_metric('error_count', 'validation')
            return None
        
        # Limite la longueur pour éviter les abus
        if len(source_type) > self.MAX_SOURCE_TYPE_LENGTH:
            self.logger.error(
                f"source_type trop long: {len(source_type)} caractères "
                f"(max: {self.MAX_SOURCE_TYPE_LENGTH})"
            )
            self._increment_metric('error_count', 'validation')
            return None
        
        # Convertit en enum
        validated = SourceType.from_string(source_type)
        if validated is None:
            valid_types = SourceType.get_valid_types()
            self.logger.error(
                f"Type de source inconnu: '{source_type}'. "
                f"Valeurs acceptées: {valid_types}"
            )
            self._increment_metric('error_count', 'validation')
        
        return validated
    
    def _validate_raw_data_size(self, raw_data: Union[str, Dict[str, Any]]) -> bool:
        """
        Vérifie que les données ne sont pas excessivement grandes.
        
        Args:
            raw_data: Données à valider
            
        Returns:
            True si la taille est acceptable, False sinon
        """
        try:
            if isinstance(raw_data, str):
                # Validation pour WHOIS (texte brut)
                size = len(raw_data.encode('utf-8'))
                if size > self.MAX_RAW_STRING_SIZE:
                    self.logger.warning(
                        f"Données WHOIS trop volumineuses: {size} octets "
                        f"(max: {self.MAX_RAW_STRING_SIZE})"
                    )
                    return False
            
            elif isinstance(raw_data, dict):
                # Validation pour RDAP (JSON)
                total_keys = self._count_dict_keys(raw_data)
                if total_keys > self.MAX_DICT_KEYS:
                    self.logger.warning(
                        f"Trop de clés dans le dictionnaire RDAP: {total_keys} "
                        f"(max: {self.MAX_DICT_KEYS})"
                    )
                    return False
            
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la validation de taille: {e}")
            return False
    
    def _count_dict_keys(self, obj: Any, current_depth: int = 0) -> int:
        """
        Compte récursivement le nombre de clés dans un dictionnaire.
        
        Args:
            obj: Objet à analyser
            current_depth: Profondeur actuelle de récursion
            
        Returns:
            Nombre total de clés
        """
        if current_depth > self.MAX_RECURSION_DEPTH:
            return 0
        
        count = 0
        if isinstance(obj, dict):
            count = len(obj)
            # Limite à 100 valeurs par niveau pour éviter DoS
            for value in list(obj.values())[:100]:
                count += self._count_dict_keys(value, current_depth + 1)
        elif isinstance(obj, list):
            # Limite à 100 items pour éviter DoS
            for item in obj[:100]:
                count += self._count_dict_keys(item, current_depth + 1)
        
        return count
    
    def _increment_metric(self, metric_type: str, source: str):
        """Incrémente un compteur de métrique de manière sécurisée."""
        if not self.enable_metrics:
            return
        
        try:
            metric_dict = getattr(self, f'_{metric_type}', None)
            if metric_dict and source in metric_dict:
                metric_dict[source] += 1
        except Exception as e:
            self.logger.debug(f"Erreur lors de l'incrémentation des métriques: {e}")
    
    def _parse_rdap(self, raw_data: Dict[str, Any]) -> ParsedResult:
        """
        Parse les données RDAP de manière sécurisée.
        
        Args:
            raw_data: Dictionnaire JSON RDAP
            
        Returns:
            ParsedResult unifié
        """
        result = ParsedResult(source='RDAP')
        
        try:
            # Validation stricte du type
            if not isinstance(raw_data, dict):
                result.is_valid = False
                error_msg = (
                    f"Données RDAP invalides: attendu dict, "
                    f"reçu {type(raw_data).__name__}"
                )
                result.errors.append(error_msg)
                self.logger.error(error_msg)
                self._increment_metric('error_count', 'rdap')
                return result
            
            # Parse avec le parser RDAP
            rdap_result: RDAPParseResult = self.rdap_parser.parse(raw_data)
            
            # Transfert des données vers le format unifié
            result.expiration_date = rdap_result.expiration_date
            result.creation_date = rdap_result.creation_date
            result.registrar = rdap_result.registrar
            result.status = rdap_result.status if rdap_result.status else []
            result.errors = rdap_result.errors.copy()
            result.warnings = rdap_result.warnings.copy()
            
            # Marque comme invalide si des erreurs critiques
            if rdap_result.errors:
                result.is_valid = False
                self._increment_metric('error_count', 'rdap')
            
            # Compte les warnings
            if rdap_result.warnings:
                self._increment_metric('warning_count', 'rdap')
            
            # Statistiques
            self._increment_metric('parse_count', 'rdap')
            
            # Log si aucune donnée utile extraite
            if not result.has_data():
                self.logger.info("Aucune donnée utile extraite du JSON RDAP")
            
        except Exception as e:
            result.is_valid = False
            error_msg = f"Erreur fatale lors du parsing RDAP: {str(e)[:200]}"
            result.errors.append(error_msg)
            self.logger.error(error_msg, exc_info=True)
            self._increment_metric('error_count', 'rdap')
        
        return result
    
    def _parse_whois(self, raw_data: str) -> ParsedResult:
        """
        Parse les données WHOIS de manière sécurisée.
        
        Args:
            raw_data: Texte brut WHOIS
            
        Returns:
            ParsedResult unifié
        """
        result = ParsedResult(source='WHOIS')
        
        try:
            # Validation stricte du type
            if not isinstance(raw_data, str):
                result.is_valid = False
                error_msg = (
                    f"Données WHOIS invalides: attendu str, "
                    f"reçu {type(raw_data).__name__}"
                )
                result.errors.append(error_msg)
                self.logger.error(error_msg)
                self._increment_metric('error_count', 'whois')
                return result
            
            # Parse avec le parser WHOIS
            whois_result: WhoisParseResult = self.whois_parser.parse(raw_data)
            
            # Transfert des données vers le format unifié
            result.expiration_date = whois_result.expiration_date
            result.creation_date = whois_result.creation_date
            result.registrar = whois_result.registrar
            
            # Uniformisation du statut en liste (comme RDAP)
            # Ceci est crucial pour l'uniformisation des formats
            if whois_result.status:
                result.status = [whois_result.status]
            else:
                result.status = []
            
            result.errors = whois_result.errors.copy()
            
            # WHOIS parser n'a pas de warnings par défaut, on les ajoute si présents
            if hasattr(whois_result, 'warnings') and whois_result.warnings:
                result.warnings = whois_result.warnings.copy()
                self._increment_metric('warning_count', 'whois')
            
            # Marque comme invalide si des erreurs critiques
            if whois_result.errors:
                result.is_valid = False
                self._increment_metric('error_count', 'whois')
            
            # Statistiques
            self._increment_metric('parse_count', 'whois')
            
            # Log si aucune donnée utile extraite
            if not result.has_data():
                self.logger.info("Aucune donnée utile extraite du texte WHOIS")
            
        except Exception as e:
            result.is_valid = False
            error_msg = f"Erreur fatale lors du parsing WHOIS: {str(e)[:200]}"
            result.errors.append(error_msg)
            self.logger.error(error_msg, exc_info=True)
            self._increment_metric('error_count', 'whois')
        
        return result
    
    def parse(self, 
              raw_data: Union[str, Dict[str, Any]], 
              source_type: str) -> ParsedResult:
        """
        Point d'entrée unique pour le parsing sécurisé.
        
        Cette méthode:
        1. Valide le type de source
        2. Valide la taille des données
        3. Route vers le bon parser
        4. Uniformise le résultat
        5. Collecte des métriques
        
        Args:
            raw_data: Texte brut (WHOIS) ou Dictionnaire (RDAP)
            source_type: 'rdap' ou 'whois'
            
        Returns:
            ParsedResult avec les données parsées et métadonnées
            
        Examples:
            >>> manager = ParserManager()
            >>> # Parsing RDAP
            >>> rdap_data = {"events": [...], "entities": [...]}
            >>> result = manager.parse(rdap_data, 'rdap')
            >>> if result.is_valid:
            ...     print(f"Domaine expire le: {result.expiration_date}")
            >>> 
            >>> # Parsing WHOIS
            >>> whois_text = "Registry Expiry Date: 2025-12-31..."
            >>> result = manager.parse(whois_text, 'whois')
            >>> print(f"Status: {result.status}")
        """
        # Validation du type de source
        validated_source = self._validate_source_type(source_type)
        if validated_source is None:
            return ParsedResult(
                is_valid=False,
                errors=[f"Type de source invalide: '{source_type}'"],
                source='UNKNOWN'
            )
        
        # Validation de la taille des données
        if not self._validate_raw_data_size(raw_data):
            return ParsedResult(
                is_valid=False,
                errors=["Données trop volumineuses pour être traitées en sécurité"],
                source=validated_source.value.upper()
            )
        
        # Routing vers le bon parser
        try:
            if validated_source == SourceType.RDAP:
                return self._parse_rdap(raw_data)
            elif validated_source == SourceType.WHOIS:
                return self._parse_whois(raw_data)
            else:
                # Ne devrait jamais arriver grâce à l'enum, mais filet de sécurité
                self.logger.error(f"Source type non géré: {validated_source}")
                self._increment_metric('parse_count', 'unknown')
                return ParsedResult(
                    is_valid=False,
                    errors=[f"Type de source non supporté: {validated_source}"],
                    source=validated_source.value.upper()
                )
        except Exception as e:
            # Filet de sécurité final pour toute erreur imprévue
            error_msg = f"Erreur fatale lors de l'aiguillage du parsing: {str(e)[:200]}"
            self.logger.critical(error_msg, exc_info=True)
            return ParsedResult(
                is_valid=False,
                errors=[error_msg],
                source=validated_source.value.upper() if validated_source else 'UNKNOWN'
            )
    
    def parse_to_dict(self, 
                      raw_data: Union[str, Dict[str, Any]], 
                      source_type: str,
                      include_metadata: bool = True) -> Dict[str, Any]:
        """
        Version rétrocompatible qui retourne un dictionnaire.
        
        Args:
            raw_data: Texte brut (WHOIS) ou Dictionnaire (RDAP)
            source_type: 'rdap' ou 'whois'
            include_metadata: Si True, inclut errors/warnings/is_valid
            
        Returns:
            Dictionnaire avec les données parsées
        """
        result = self.parse(raw_data, source_type)
        return result.to_dict(include_metadata=include_metadata)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Retourne des statistiques détaillées sur l'utilisation du parser.
        
        Returns:
            Dictionnaire avec les métriques collectées
            
        Examples:
            >>> manager = ParserManager()
            >>> # ... après plusieurs appels à parse()
            >>> stats = manager.get_statistics()
            >>> print(f"Taux de succès: {stats['overall']['success_rate']:.2%}")
            >>> print(f"RDAP parsés: {stats['by_source']['rdap']['parses']}")
        """
        if not self.enable_metrics:
            return {"metrics_enabled": False}
        
        total_parses = sum(self._parse_count.values())
        total_errors = sum(self._error_count.values())
        total_warnings = sum(self._warning_count.values())
        
        # Calcul du taux de succès
        success_rate = (
            (total_parses - total_errors) / total_parses 
            if total_parses > 0 else 0
        )
        
        return {
            'metrics_enabled': True,
            'overall': {
                'total_parses': total_parses,
                'total_errors': total_errors,
                'total_warnings': total_warnings,
                'success_rate': success_rate,
                'successful_parses': total_parses - total_errors
            },
            'by_source': {
                'rdap': {
                    'parses': self._parse_count['rdap'],
                    'errors': self._error_count['rdap'],
                    'warnings': self._warning_count['rdap'],
                    'success_rate': (
                        (self._parse_count['rdap'] - self._error_count['rdap']) / 
                        self._parse_count['rdap']
                        if self._parse_count['rdap'] > 0 else 0
                    )
                },
                'whois': {
                    'parses': self._parse_count['whois'],
                    'errors': self._error_count['whois'],
                    'warnings': self._warning_count['whois'],
                    'success_rate': (
                        (self._parse_count['whois'] - self._error_count['whois']) / 
                        self._parse_count['whois']
                        if self._parse_count['whois'] > 0 else 0
                    )
                }
            },
            'validation_errors': self._error_count['validation'],
            'unknown_sources': self._parse_count['unknown']
        }
    
    def reset_statistics(self):
        """Réinitialise tous les compteurs de statistiques."""
        self._parse_count = {'rdap': 0, 'whois': 0, 'unknown': 0}
        self._error_count = {'rdap': 0, 'whois': 0, 'validation': 0}
        self._warning_count = {'rdap': 0, 'whois': 0}
        self.logger.info("Statistiques du ParserManager réinitialisées")
    
    def get_supported_sources(self) -> List[str]:
        """
        Retourne la liste des sources supportées.
        
        Returns:
            Liste des types de sources valides
        """
        return SourceType.get_valid_types()