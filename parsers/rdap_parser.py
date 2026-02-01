from typing import Dict, Any, Optional, List, Union
import logging
from dataclasses import dataclass, field
from datetime import datetime
import re

@dataclass
class RDAPParseResult:
    """Résultat structuré du parsing RDAP."""
    expiration_date: Optional[str] = None
    creation_date: Optional[str] = None
    status: List[str] = field(default_factory=list)
    registrar: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class RDAPParser:
    """Extrait les champs clés d'un JSON RDAP de manière sécurisée."""
    
    # Limites de sécurité
    MAX_JSON_DEPTH = 10
    MAX_ARRAY_SIZE = 1000
    MAX_STRING_LENGTH = 1000
    MAX_STATUS_COUNT = 50
    MAX_ENTITIES_COUNT = 100
    MAX_EVENTS_COUNT = 100
    MAX_VCARD_ITEMS = 100
    
    # Validation des formats
    ISO8601_PATTERN = re.compile(
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$'
    )
    VALID_EVENT_ACTIONS = {
        'registration', 'expiration', 'last changed', 'deletion',
        'reinstantiation', 'transfer', 'locked', 'unlocked'
    }
    VALID_ROLES = {
        'registrant', 'administrative', 'technical', 'abuse',
        'billing', 'registrar', 'reseller', 'sponsor', 'proxy', 'notifications'
    }
    FORBIDDEN_CHARS = re.compile(r'[<>\"\'`;&|$\x00-\x1f\x7f-\x9f]')
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialise le parser avec un logger optionnel."""
        self.logger = logger or logging.getLogger(__name__)
        self._depth_counter = 0
    
    def _validate_input(self, data: Any) -> bool:
        """Valide que l'entrée est un dictionnaire valide."""
        if not isinstance(data, dict):
            self.logger.warning(f"Input n'est pas un dictionnaire: {type(data)}")
            return False
        
        # Vérifie la profondeur JSON
        if not self._check_depth(data):
            self.logger.warning("JSON trop profond détecté")
            return False
        
        return True
    
    def _check_depth(self, obj: Any, current_depth: int = 0) -> bool:
        """Vérifie récursivement la profondeur du JSON."""
        if current_depth > self.MAX_JSON_DEPTH:
            return False
        
        if isinstance(obj, dict):
            return all(
                self._check_depth(v, current_depth + 1) 
                for v in list(obj.values())[:self.MAX_ARRAY_SIZE]
            )
        elif isinstance(obj, list):
            return all(
                self._check_depth(item, current_depth + 1) 
                for item in obj[:self.MAX_ARRAY_SIZE]
            )
        
        return True
    
    def _sanitize_string(self, value: Any, max_length: Optional[int] = None) -> Optional[str]:
        """Nettoie et valide une chaîne de caractères."""
        if value is None:
            return None
        
        if not isinstance(value, str):
            self.logger.warning(f"Valeur n'est pas une chaîne: {type(value)}")
            return None
        
        # Limite la longueur
        max_len = max_length or self.MAX_STRING_LENGTH
        if len(value) > max_len:
            self.logger.warning(f"Chaîne tronquée: {len(value)} -> {max_len}")
            value = value[:max_len]
        
        # Retire les espaces excessifs
        value = ' '.join(value.split())
        
        # Vérifie les caractères dangereux
        if self.FORBIDDEN_CHARS.search(value):
            self.logger.warning(f"Caractères suspects détectés: {value[:50]}")
            value = self.FORBIDDEN_CHARS.sub('', value)
        
        # Retire les caractères de contrôle
        value = ''.join(
            char for char in value 
            if ord(char) >= 32 or char in '\n\t'
        )
        
        return value.strip() if value.strip() else None
    
    def _validate_date(self, date_str: Optional[str]) -> Optional[str]:
        """Valide qu'une date est au format ISO 8601."""
        if not date_str:
            return None
        
        date_str = self._sanitize_string(date_str, 100)
        if not date_str:
            return None
        
        if not self.ISO8601_PATTERN.match(date_str):
            self.logger.warning(f"Format de date invalide: {date_str}")
            return None
        
        # Validation supplémentaire: parse la date
        try:
            # Essaie plusieurs formats courants
            for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ', 
                       '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f%z']:
                try:
                    datetime.strptime(date_str.replace('+00:00', 'Z'), fmt.replace('%z', 'Z'))
                    return date_str
                except ValueError:
                    continue
            
            # Si aucun format ne fonctionne mais regex OK, accepte quand même
            return date_str
        except Exception as e:
            self.logger.warning(f"Erreur parsing date {date_str}: {e}")
            return None
    
    def _safe_get(self, data: Dict[str, Any], key: str, 
                  expected_type: type, default: Any = None) -> Any:
        """Récupère une valeur de manière sécurisée avec vérification de type."""
        try:
            value = data.get(key, default)
            if value is None:
                return default
            
            if not isinstance(value, expected_type):
                self.logger.warning(
                    f"Type inattendu pour '{key}': {type(value)} au lieu de {expected_type}"
                )
                return default
            
            return value
        except Exception as e:
            self.logger.error(f"Erreur lors de l'accès à '{key}': {e}")
            return default
    
    def _find_event(self, data: Dict[str, Any], event_action: str, 
                    result: RDAPParseResult) -> Optional[str]:
        """Trouve un événement par son action de manière sécurisée."""
        # Valide l'action
        if event_action not in self.VALID_EVENT_ACTIONS:
            self.logger.warning(f"Action d'événement inconnue: {event_action}")
            result.warnings.append(f"Action d'événement non standard: {event_action}")
        
        events = self._safe_get(data, 'events', list, [])
        
        # Limite le nombre d'événements
        if len(events) > self.MAX_EVENTS_COUNT:
            self.logger.warning(f"Trop d'événements: {len(events)}")
            result.warnings.append(f"Liste d'événements tronquée à {self.MAX_EVENTS_COUNT}")
            events = events[:self.MAX_EVENTS_COUNT]
        
        for event in events:
            if not isinstance(event, dict):
                self.logger.warning(f"Événement invalide (non-dict): {type(event)}")
                continue
            
            action = self._safe_get(event, 'eventAction', str)
            if action == event_action:
                date = self._safe_get(event, 'eventDate', str)
                return self._validate_date(date)
        
        return None
    
    def _find_registrar(self, data: Dict[str, Any], 
                        result: RDAPParseResult) -> Optional[str]:
        """Trouve le registrar de manière sécurisée."""
        entities = self._safe_get(data, 'entities', list, [])
        
        # Limite le nombre d'entités
        if len(entities) > self.MAX_ENTITIES_COUNT:
            self.logger.warning(f"Trop d'entités: {len(entities)}")
            result.warnings.append(f"Liste d'entités tronquée à {self.MAX_ENTITIES_COUNT}")
            entities = entities[:self.MAX_ENTITIES_COUNT]
        
        for entity in entities:
            if not isinstance(entity, dict):
                self.logger.warning(f"Entité invalide (non-dict): {type(entity)}")
                continue
            
            roles = self._safe_get(entity, 'roles', list, [])
            
            # Vérifie si 'registrar' est dans les rôles
            if not any(role == 'registrar' for role in roles if isinstance(role, str)):
                continue
            
            # Extrait le nom de la vCard
            name = self._extract_vcard_name(entity, result)
            if name:
                return name
        
        return None
    
    def _extract_vcard_name(self, entity: Dict[str, Any], 
                            result: RDAPParseResult) -> Optional[str]:
        """Extrait le nom d'une vCard de manière sécurisée."""
        vcard_array = self._safe_get(entity, 'vcardArray', list, [])
        
        # Vérifie la structure de base de vCard: ["vcard", [...]]
        if len(vcard_array) < 2:
            return None
        
        # Le premier élément doit être "vcard"
        if not isinstance(vcard_array[0], str) or vcard_array[0].lower() != 'vcard':
            self.logger.warning("Format vCard invalide")
            return None
        
        # Le second élément doit être une liste
        if not isinstance(vcard_array[1], list):
            self.logger.warning("vCard[1] n'est pas une liste")
            return None
        
        vcard_items = vcard_array[1]
        
        # Limite le nombre d'items
        if len(vcard_items) > self.MAX_VCARD_ITEMS:
            self.logger.warning(f"Trop d'items vCard: {len(vcard_items)}")
            result.warnings.append(f"vCard tronquée à {self.MAX_VCARD_ITEMS} items")
            vcard_items = vcard_items[:self.MAX_VCARD_ITEMS]
        
        for item in vcard_items:
            # Chaque item doit être une liste avec au moins 4 éléments
            if not isinstance(item, list) or len(item) < 4:
                continue
            
            # item[0] est le type (ex: "fn" pour formatted name)
            if not isinstance(item[0], str):
                continue
            
            # Cherche le "fn" (formatted name)
            if item[0].lower() == 'fn':
                # item[3] contient la valeur
                name = item[3] if len(item) > 3 else None
                
                if isinstance(name, str):
                    sanitized = self._sanitize_string(name, 200)
                    if sanitized:
                        return sanitized
                elif isinstance(name, list) and len(name) > 0:
                    # Parfois le nom est dans une liste
                    first_name = name[0] if isinstance(name[0], str) else None
                    if first_name:
                        sanitized = self._sanitize_string(first_name, 200)
                        if sanitized:
                            return sanitized
        
        return None
    
    def _extract_status(self, data: Dict[str, Any], 
                        result: RDAPParseResult) -> List[str]:
        """Extrait et valide les statuts du domaine."""
        status_list = self._safe_get(data, 'status', list, [])
        
        if not status_list:
            return []
        
        # Limite le nombre de statuts
        if len(status_list) > self.MAX_STATUS_COUNT:
            self.logger.warning(f"Trop de statuts: {len(status_list)}")
            result.warnings.append(f"Liste de statuts tronquée à {self.MAX_STATUS_COUNT}")
            status_list = status_list[:self.MAX_STATUS_COUNT]
        
        validated_statuses = []
        for status in status_list:
            if isinstance(status, str):
                sanitized = self._sanitize_string(status, 100)
                if sanitized:
                    validated_statuses.append(sanitized)
            else:
                self.logger.warning(f"Statut non-string ignoré: {type(status)}")
        
        return validated_statuses
    
    def parse(self, data: Dict[str, Any]) -> RDAPParseResult:
        """
        Parse les données RDAP de manière sécurisée.
        
        Args:
            data: Dictionnaire JSON RDAP
            
        Returns:
            RDAPParseResult avec les données extraites et erreurs éventuelles
        """
        result = RDAPParseResult()
        
        # Validation de l'entrée
        if not self._validate_input(data):
            result.errors.append("Validation de l'entrée échouée")
            return result
        
        try:
            # Extraction des événements
            result.expiration_date = self._find_event(data, 'expiration', result)
            result.creation_date = self._find_event(data, 'registration', result)
            
            # Extraction du statut
            result.status = self._extract_status(data, result)
            
            # Extraction du registrar
            result.registrar = self._find_registrar(data, result)
            
            # Log si aucune donnée n'a été extraite
            if (not result.expiration_date and not result.creation_date 
                and not result.status and not result.registrar):
                self.logger.info("Aucune donnée RDAP extraite")
                result.warnings.append("Aucune donnée valide trouvée")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing RDAP: {e}", exc_info=True)
            result.errors.append(f"Erreur de parsing: {str(e)[:200]}")
        
        return result
    
    def parse_to_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Version compatible avec l'ancienne interface.
        
        Args:
            data: Dictionnaire JSON RDAP
            
        Returns:
            Dictionnaire avec les champs extraits
        """
        result = self.parse(data)
        return {
            'expiration_date': result.expiration_date,
            'creation_date': result.creation_date,
            'status': result.status,
            'registrar': result.registrar
        }
