from abc import ABC, abstractmethod

class BasePlugin(ABC):
    """
    Clase maestra que define cómo debe comportarse cualquier integración
    (CrowdStrike, Trellix, etc) para funcionar en el Dashboard.
    """

    def __init__(self, credentials):
        """
        Recibe las credenciales desencriptadas (diccionario)
        EJ: {'api_url: '...', 'client_id': '...'}
        """
        self.credentials = credentials

    @property
    @abstractmethod
    def nombre(self):
        """Nombre legible del plugin (Ej: 'CrowdStrike Falson')"""
        pass

    @property
    @abstractmethod
    def slug(self):
        """Identificador único para la DB (EJ: 'crowdstrike')"""
        pass

    @staticmethod
    @abstractmethod
    def get_form_fields():
        """
        Define qué campos debe llenar el Admin en la configuración.
        Debe retornar una lista de diccionarios.
        Ej: [{'name': 'api_key', 'label': 'API Key', 'type': 'password'}]
        """
        pass

    @abstractmethod
    def test_connection(self):
        """
        Verifica si las credenciales son válidas.
        Retorna: (Booleano, Mensaje) -> (True, "Conectado") o (False, "Error 401")
        """
        pass

    @abstractmethod
    def run_checks(self):
        """
        Ejecuta la lógica principal de revisión.
        Debe retornar un diccionario estandarizado:
        {
            'status': 'online' | 'warning' | 'error',
            'message': 'Resumen corto (Ej: 3 usuarios sin MFA)',
            'details': [
                {'check': 'Agentes', 'status': 'ok', 'text': '100% Cobertura'},
                {'check': 'MFA', 'status': 'fail', 'text': '2 Admins sin MFA'}
            ]
        }
        """
        pass