import requests
from app.checklist.plugins.base import BasePlugin

class VisionOnePlugin(BasePlugin):
    nombre = "Trend Micro Vision One"
    slug = "trend_micro_v1"

    @staticmethod
    def get_form_fields():
        return [
            {
                'name': 'api_url', 
                'label': 'URL de API (Base)', 
                'type': 'text', 
                'placeholder': 'Ej: https://api.us-1.xdr.trendmicro.com'
            },
            {
                'name': 'api_token', 
                'label': 'Authentication Token', 
                'type': 'password', 
                'placeholder': 'Token Bearer largo generado en la consola'
            }
        ]

    def _get_headers(self):
        return {
            'Authorization': f"Bearer {self.credentials.get('api_token')}",
            'Content-Type': 'application/json;charset=utf-8'
        }

    def test_connection(self):
        # Probamos conectividad listando solo 1 alerta cualquiera
        base_url = self.credentials.get('api_url', '').rstrip('/')
        url = f"{base_url}/v3.0/workbench/alerts?limit=1"
        
        try:
            r = requests.get(url, headers=self._get_headers(), timeout=10)
            if r.status_code == 200:
                return True, "Conexión a Vision One exitosa"
            elif r.status_code == 401:
                return False, "Error 401: Token inválido o expirado"
            else:
                return False, f"Error API: {r.status_code} - {r.text[:100]}"
        except Exception as e:
            return False, f"Error de conexión: {str(e)}"

    def run_checks(self):
        base_url = self.credentials.get('api_url', '').rstrip('/')
        detalles = []
        estado_global = 'online'
        mensajes_globales = []

        # --- CHECK: ALERTAS DEL WORKBENCH (CRÍTICAS/ALTAS) ---
        # Documentación: https://automation.trendmicro.com/xdr/api-v3/tag/Workbench-Alerts
        # Filtramos por:
        # - severity: high, critical
        # - status: new, inProgress (ignoramos las cerradas)
        # Nota: La API de TM usa query params específicos o filtros odata.
        
        # Endpoint directo
        endpoint = f"{base_url}/v3.0/workbench/alerts"
        
        # Parámetros de consulta
        params = {
            'limit': 50, # Miramos las últimas 50
            'status': 'New,InProgress', # Solo lo que requiere atención
            'severity': 'high,critical'
        }

        try:
            r = requests.get(endpoint, headers=self._get_headers(), params=params, timeout=15)
            
            if r.status_code == 200:
                data = r.json()
                items = data.get('items', [])
                count_critical = len(items)

                if count_critical > 0:
                    detalles.append({
                        'check': 'Workbench Alerts', 
                        'status': 'fail', 
                        'text': f'{count_critical} incidentes críticos activos'
                    })
                    mensajes_globales.append(f"{count_critical} Alertas")
                    estado_global = 'offline' # Rojo inmediato
                else:
                    detalles.append({
                        'check': 'Workbench Alerts', 
                        'status': 'ok', 
                        'text': 'Sin incidentes críticos pendientes'
                    })
            else:
                detalles.append({'check': 'API Workbench', 'status': 'warning', 'text': f'Error {r.status_code}'})
                if estado_global != 'offline': estado_global = 'warning'

        except Exception as e:
            return {'status': 'error', 'message': f'Excepción: {str(e)}'}

        # --- RESULTADO FINAL ---
        if not mensajes_globales:
            msg_final = "Vision One Seguro"
        else:
            msg_final = "Atención: " + ", ".join(mensajes_globales)

        return {
            'status': estado_global,
            'message': msg_final,
            'details': detalles
        }