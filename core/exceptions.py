"""
Exceptions personnalisées pour le module HybriScope
"""


class HybriScopeError(Exception):
    """Classe de base pour toutes les exceptions HybriScope"""
    pass


class SecurityViolation(HybriScopeError):
    """Violation de sécurité détectée"""
    pass


class NetworkError(HybriScopeError):
    """Erreur réseau lors d'une opération"""
    pass


class ValidationError(HybriScopeError):
    """Erreur de validation des données"""
    pass


class CacheError(HybriScopeError):
    """Erreur liée au cache"""
    pass