from app.checklist.plugins.base import BasePlugin
try:
    #Intentamos importar la libreria oficial
    from falconpy import Hosts, Detects
except ImportError:
    Hosts = None
    Detects = None

class CrowdStrikePlugin(BasePlugin):
    nombre = "CrowdStrike Falco"
    slug = "crowdstrike"

    @staticmethod
    def get_form_fields():
        return [
            {
                'name': 'client_id',
                'label': 'Client ID',
                'type': 'password',
                'placeholder': 'Copiar desde API Client y Keys'
            },
            {
                'name': 'client_secret',
                'label': 'Client Secret',
                'type': 'password',
                'placeholder': 'El secreto generado'
            },
            {
                'name': 'base_url',
                'label': 'Nube (Base URL)',
                'type': 'text',
                'placeholder': 'us-1, us-2, eu-1'
            }
        ]
    
    def _get_credentials(self):
        """Helper para limpiar y preparar credenciales"""
        return {
            'client_id': self.credentials.get('client_id', '').strip(),
            'client_secret': self.credentials.get('client_secret', '').strip(),
            'base_url': self.credentials.get('base_url', 'us-1').strip()
        }
    
    def test_connection(self):
        if not Hosts:
            return False, "Librería 'crowdstrike-falconpy' no instalada en el servidor."

        creds = self._get_credentials()
        
        # Intentamos listar 1 host solo para probar autenticación
        falcon = Hosts(client_id=creds['client_id'],
                       client_secret=creds['client_secret'],
                       base_url=creds['base_url'])
        
        # Llamada ligera
        response = falcon.query_devices_by_filter(limit=1)
        
        if response['status_code'] == 200:
            return True, "Conexión exitosa con API Falcon"
        else:
            # Extraer error legible
            errores = response.get('body', {}).get('errors', [])
            msg = errores[0].get('message') if errores else "Error desconocido"
            return False, f"Error API: {msg}"

    def run_checks(self):
        if not Hosts:
            return {'status': 'error', 'message': 'Falta librería python'}

        creds = self._get_credentials()
        detalles = []
        estado_global = 'online'
        mensajes_globales = []

        # --- 1. INSTANCIAS DE LA API ---
        falcon_detects = Detects(client_id=creds['client_id'], client_secret=creds['client_secret'], base_url=creds['base_url'])
        falcon_hosts = Hosts(client_id=creds['client_id'], client_secret=creds['client_secret'], base_url=creds['base_url'])

        # --- CHECK A: DETECCIONES CRÍTICAS NUEVAS ---
        # Filtro: status='new' Y severity es High(3) o Critical(4)
        filtro_detects = "status:'new' + severity:>='3'"
        res_detects = falcon_detects.query_detects(filter=filtro_detects)
        
        if res_detects['status_code'] == 200:
            total_nuevas = len(res_detects.get('body', {}).get('resources', []))
            
            if total_nuevas > 0:
                detalles.append({
                    'check': 'Alertas Nuevas', 
                    'status': 'fail', 
                    'text': f'{total_nuevas} Críticas/Altas sin revisar'
                })
                estado_global = 'offline' # Rojo directo
                mensajes_globales.append(f"{total_nuevas} Alertas")
            else:
                detalles.append({
                    'check': 'Alertas Nuevas', 
                    'status': 'ok', 
                    'text': '0 Pendientes'
                })
        else:
            detalles.append({'check': 'Alertas', 'status': 'warning', 'text': 'Error consultando API'})

        # --- CHECK B: AGENTES INACTIVOS (Últimos 7 días) ---
        # Filtro: last_seen menor a hace 7 días (calculado por la API si filtramos inversamente)
        # Mejor estrategia: Contar total vs Contar offline reciente
        # Para simplificar, buscaremos hosts que no se han visto en 4 días
        filtro_offline = "last_seen:<'now-4d'"
        res_offline = falcon_hosts.query_devices_by_filter(filter=filtro_offline)
        
        if res_offline['status_code'] == 200:
            offline_list = res_offline.get('body', {}).get('resources', [])
            count_offline = len(offline_list)
            
            if count_offline > 0:
                detalles.append({
                    'check': 'Agentes Offline (+4d)', 
                    'status': 'warning', 
                    'text': f'{count_offline} desconectados'
                })
                if estado_global != 'offline': estado_global = 'warning'
                mensajes_globales.append(f"{count_offline} Offline")
            else:
                detalles.append({
                    'check': 'Agentes Offline', 
                    'status': 'ok', 
                    'text': 'Todos reportando'
                })

        # --- RESULTADO FINAL ---
        if not mensajes_globales:
            msg_final = "Plataforma Saludable"
        else:
            msg_final = "Atención: " + ", ".join(mensajes_globales)

        return {
            'status': estado_global,
            'message': msg_final,
            'details': detalles
        }