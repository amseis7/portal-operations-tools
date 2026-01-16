# app/checklist/plugins/fortiedr.py
import requests
from requests.auth import HTTPBasicAuth
from app.checklist.plugins.base import BasePlugin

class FortiEDRPlugin(BasePlugin):
    nombre = "Fortinet FortiEDR"
    slug = "fortiedr"

    @staticmethod
    def get_form_fields():
        return [
            {
                'name': 'base_url', 
                'label': 'Console URL', 
                'type': 'text', 
                'placeholder': 'https://console.fortiedr.cloud'
            },
            {
                'name': 'api_user', 
                'label': 'API User', 
                'type': 'text', 
                'placeholder': 'org Name\\User'
            },
            {
                'name': 'api_pass', 
                'label': 'Password / API Key', 
                'type': 'password', 
                'placeholder': 'Contraseña del usuario API'
            }
        ]

    def _get_auth(self):
        # FortiEDR usa Basic Auth estándar
        return HTTPBasicAuth(
            self.credentials.get('api_user'), 
            self.credentials.get('api_pass')
        )

    def test_connection(self):
        base_url = self.credentials.get('base_url', '').rstrip('/')
        # Endpoint ligero para probar: Listar colectores (limitado a 1)
        url = f"{base_url}/management-rest/inventory/list-collectors"
        
        try:
            # params={'itemsPerPage': 1} es estándar en FortiEDR 5.x+
            r = requests.get(url, auth=self._get_auth(), params={'itemsPerPage': 1}, timeout=10, verify=True)
            
            if r.status_code == 200:
                return True, "Conexión a FortiEDR exitosa"
            elif r.status_code == 401:
                return False, "Error 401: Usuario o contraseña incorrectos"
            elif r.status_code == 403:
                return False, "Error 403: Permisos insuficientes (Role)"
            else:
                return False, f"Error API: {r.status_code}"
        except Exception as e:
            return False, f"Error de red: {str(e)}"

    def run_checks(self):
        base_url = self.credentials.get('base_url', '').rstrip('/')
        auth = self._get_auth()
        
        detalles = []
        estado_global = 'online'
        mensajes_globales = []

        # --- CHECK 1: EVENTOS PENDIENTES (Alertas) ---
        # Buscamos eventos que NO han sido manejados (State = Unhandled)
        url_events = f"{base_url}/management-rest/events/list-events"
        # Filtros: state="Unhandled" y severidad alta
        # Nota: La API de FortiEDR a veces requiere filtros en el body o query params según versión.
        # Probamos query params estándar.
        params_events = {
            'state': 'Unhandled',
            'severity': 'Critical,High', # Ajustar según necesidad
            'itemsPerPage': 10 # Solo queremos saber si hay
        }

        try:
            r = requests.get(url_events, auth=auth, params=params_events, timeout=15)
            
            if r.status_code == 200:
                events = r.json() # Devuelve una lista []
                count_alerts = len(events)
                
                if count_alerts > 0:
                    detalles.append({
                        'check': 'Eventos Activos', 
                        'status': 'fail', 
                        'text': f'{count_alerts} incidentes sin resolver'
                    })
                    mensajes_globales.append(f"{count_alerts} Alertas")
                    estado_global = 'offline'
                else:
                    detalles.append({
                        'check': 'Eventos Activos', 
                        'status': 'ok', 
                        'text': '0 Incidentes Pendientes'
                    })
            else:
                detalles.append({'check': 'API Eventos', 'status': 'warning', 'text': f'Error {r.status_code}'})

        except Exception as e:
            detalles.append({'check': 'API Eventos', 'status': 'fail', 'text': 'Fallo de conexión'})

        # --- CHECK 2: ESTADO DE COLECTORES (Agentes) ---
        # Buscamos agentes desconectados o con error
        url_collectors = f"{base_url}/management-rest/inventory/list-collectors"
        
        try:
            # Traemos todos (cuidado si son miles, idealmente filtrar por estado si la API lo permite)
            # FortiEDR API permite filtrar por 'state' en algunas versiones.
            r_col = requests.get(url_collectors, auth=auth, params={'itemsPerPage': 100}, timeout=15)
            
            if r_col.status_code == 200:
                collectors = r_col.json()
                total = len(collectors)
                offline = 0
                
                for col in collectors:
                    # Estados: 'Running', 'Disconnected', 'Degraded'
                    state = col.get('state', 'Unknown')
                    if state != 'Running':
                        offline += 1

                if offline > 0:
                    detalles.append({
                        'check': 'Colectores', 
                        'status': 'warning', 
                        'text': f'{offline} no están Running / {total}'
                    })
                    mensajes_globales.append(f"{offline} Agentes Offline")
                    if estado_global != 'offline': estado_global = 'warning'
                else:
                    detalles.append({
                        'check': 'Colectores', 
                        'status': 'ok', 
                        'text': 'Todos en ejecución (Running)'
                    })

        except Exception:
            pass # Si falla inventario, no rompemos todo el check

        # --- RESULTADO FINAL ---
        if not mensajes_globales:
            msg_final = "FortiEDR Operativo"
        else:
            msg_final = "Revisar: " + ", ".join(mensajes_globales)

        return {
            'status': estado_global,
            'message': msg_final,
            'details': detalles
        }