import random
from app.checklist.plugins.base import BasePlugin

class DemoPlugin(BasePlugin):
    nombre = "Simulador de prueba"
    slug = "demo_plugin"

    @staticmethod
    def get_form_fields():
        return [
            {'name': 'dummy_url', 'label': 'URL Ficticia', 'type': 'text', 'placeholder': 'https://api.demo.com'},
            {'name': 'dummy_key', 'label': 'Clave Ficticia', 'type': 'password', 'placeholder': '12345'}
        ]
    
    def test_connection(self):
        if self.credentials.get('dummy_key') == 'error':
            return False, "Simulacion de fallo de conexión"
        return True, "Conexión simulada exitosa"
    
    def run_checks(self):
        servicio_ok = random.choice([True, True, False])
        licencias_usadas = random.randint(50, 120)

        detalles = []

        if servicio_ok:
            detalles.append({'check': 'Estado del Servicio', 'status': 'ok', 'text': 'Operativo'})
            estado_global = 'online'
            msg_global = "Todo operando normal"
        else:
            detalles.append({'check': 'Estado del Servicio', 'status': 'fail', 'text': 'Latencia alta detectada'})
            estado_global = 'warning'
            msg_global = "Problemas de latencia"

        if licencias_usadas > 100:
            detalles.append({'check': 'Licencias', 'status': 'warning', 'text': f'Exceso de uso ({licencias_usadas}%)'})
            if estado_global == 'online': 
                estado_global = 'warning'
                msg_global = "Licencias excedidas"
        else:
            detalles.append({'check': 'Licencias', 'status': 'ok', 'text': f'En rango ({licencias_usadas}%)'})

        return {
            'status': estado_global,
            'message': msg_global,
            'details': detalles
        }