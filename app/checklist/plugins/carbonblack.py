import requests
import time
from app.checklist.plugins.base import BasePlugin

class CarbonBlackPlugin(BasePlugin):
    nombre = "Carbon Black Cloud"
    slug = "carbon_black"

    @staticmethod
    def get_form_fields():
        return [
            {
                'name': 'base_url', 
                'label': 'Dashboard URL', 
                'type': 'text', 
                'placeholder': 'Ej: defense-prod05.conferdeploy.net'
            },
            {
                'name': 'org_key', 
                'label': 'Org Key', 
                'type': 'text', 
                'placeholder': 'Ej: 7123456'
            },
            {
                'name': 'api_id', 
                'label': 'API ID', 
                'type': 'text', 
                'placeholder': 'Custom Access Level ID'
            },
            {
                'name': 'api_secret', 
                'label': 'API Secret Key', 
                'type': 'password', 
                'placeholder': 'Secret Key'
            }
        ]

    def _get_headers(self):
        api_secret = self.credentials.get('api_secret', '')
        api_id = self.credentials.get('api_id', '')
        token = f"{api_secret}/{api_id}"
        return {
            "Content-Type": "application/json",
            "X-Auth-Token": token
        }

    def _get_base_url(self):
        raw_url = self.credentials.get('base_url', '').strip()
        raw_url = raw_url.replace("https://", "").replace("http://", "").rstrip("/")
        return f"https://{raw_url}"

    # --- CHEQUEO 1: DISPONIBILIDAD DEL SITIO (Web Check) ---
    def _check_platform_availability(self, base_url):
        # Hacemos un request simple a la raíz o login para ver si responde 200
        start = time.time()
        try:
            # Usamos un endpoint público o la raíz
            r = requests.get(base_url, timeout=10)
            latency = round((time.time() - start) * 1000, 2)
            
            if r.status_code < 500: # 200, 302, 401 son respuestas de "Vivo"
                return True, f"Online ({latency}ms)"
            else:
                return False, f"Error HTTP {r.status_code}"
        except Exception as e:
            return False, "Unreachable"

    # --- CHEQUEO 2: USUARIOS SIN MFA (Gobernanza) ---
    def _check_users_mfa(self, base_url, org_key, headers):
        issues = []
        try:
            # API v6 Users (Requiere permisos de 'Settings' -> 'Users' -> 'Read')
            url = f"{base_url}/app/services/v6/orgs/{org_key}/users"
            
            r = requests.get(url, headers=headers, timeout=10)
            
            if r.status_code == 200:
                data = r.json()
                users = data.get('results', [])
                
                for u in users:
                    # Buscamos si 2FA está activo
                    # Nota: La llave exacta depende de la versión, usualmente 'two_factor_auth_enabled'
                    # Si no existe la llave, asumimos True para no generar ruido falso
                    mfa_enabled = u.get('two_factor_auth_enabled', True) 
                    
                    if not mfa_enabled:
                        issues.append({
                            'user': f"{u.get('first_name')} {u.get('last_name')}",
                            'role': u.get('email', 'Sin Email') # Usamos columna 'role' para mostrar email
                        })
            elif r.status_code == 403:
                print("DEBUG: La API Key no tiene permisos para leer Usuarios (Users Read).")
                # No fallamos todo el plugin, pero no podemos auditar MFA
            
        except Exception as e:
            print(f"Error CB Users: {e}")
        
        return issues

    # --- CHEQUEO 3: SALUD DE CONECTIVIDAD (Infraestructura) ---
    def _check_sensor_health(self, base_url, org_key, headers):
        issues = []
        stats = {"active": 0, "inactive": 0}
        
        try:
            # Buscamos dispositivos para ver cuándo fue su último contacto
            url = f"{base_url}/app/services/v6/orgs/{org_key}/devices/_search"
            payload = {
                "criteria": { "status": ["ACTIVE", "INACTIVE"] }, # No nos importan virus, solo estado
                "rows": 1000 # Muestra grande
            }
            
            r = requests.post(url, headers=headers, json=payload, timeout=15)
            
            if r.status_code == 200:
                devices = r.json().get('results', [])
                
                for d in devices:
                    status = d.get('status', 'UNKNOWN')
                    last_contact = d.get('last_contact_time', None)
                    name = d.get('name', 'Unknown Device')
                    
                    if status == 'ACTIVE':
                        stats['active'] += 1
                    elif status == 'INACTIVE':
                        stats['inactive'] += 1
                        
                    # Chequeo específico: Sensores en error (Dereigstered / Error)
                    if d.get('sensor_states') and 'DRIVER_INIT_ERROR' in d.get('sensor_states'):
                        issues.append({
                            'component': f"Sensor: {name}",
                            'state': "Falla de Driver (Driver Error)"
                        })

                # Si hay demasiados inactivos (> 50%), es un problema de plataforma
                total = stats['active'] + stats['inactive']
                if total > 0 and (stats['inactive'] / total) > 0.5:
                     issues.append({
                        'component': 'Salud General Sensores',
                        'state': f"Alerta: {stats['inactive']} inactivos de {total} totales"
                     })
                     
        except Exception as e:
            print(f"Error Sensor Health: {e}")
            
        return issues, stats

    def run_checks(self):
        base_url = self._get_base_url()
        org_key = self.credentials.get('org_key')
        headers = self._get_headers()

        if not org_key: return 'offline', 'Falta Org Key', {}

        # 1. Disponibilidad Web
        web_ok, web_msg = self._check_platform_availability(base_url)
        
        # 2. MFA Compliance (Tabla Amarilla)
        mfa_issues = self._check_users_mfa(base_url, org_key, headers)
        
        # 3. Sensor Health (Tabla Roja - Infra)
        infra_issues, stats = self._check_sensor_health(base_url, org_key, headers)
        
        # Si la web está caída, es crítico de infraestructura
        if not web_ok:
            infra_issues.insert(0, {'component': 'Dashboard Web', 'state': web_msg})

        # --- CONSTRUCCIÓN DEL REPORTE ---
        detalles_json = {
            "mfa_alertas": mfa_issues,
            "infra_alertas": infra_issues,
            "cloud_status": f"{web_msg} | Sensores Activos: {stats.get('active', 0)}",
        }

        # --- SEMÁFORO ---
        estado = 'success'
        mensajes = []

        # Rojo: Dashboard caído o Problemas de Infra Masivos
        if not web_ok or len(infra_issues) > 0:
            estado = 'warning' # Warning porque quizas es solo 1 sensor, 'offline' si web_ok es false
            if not web_ok: estado = 'offline'
            mensajes.append("Falla de Plataforma")

        # Amarillo: Usuarios sin MFA
        if mfa_issues:
            if estado == 'success': estado = 'warning'
            mensajes.append(f"{len(mfa_issues)} Admin sin MFA")

        if not mensajes:
            mensaje_final = "Plataforma Estable"
        else:
            mensaje_final = " / ".join(mensajes)

        return estado, mensaje_final, detalles_json

    def test_connection(self):
        try:
            # Prueba simple de autenticación
            base_url = self._get_base_url()
            org_key = self.credentials.get('org_key')
            headers = self._get_headers()
            
            # Intentamos leer 1 usuario solo para validar token y permisos
            url = f"{base_url}/app/services/v6/orgs/{org_key}/users"
            r = requests.get(url, headers=headers, timeout=5)
            
            if r.status_code == 200:
                return True, "Conexión y Permisos OK"
            elif r.status_code == 403:
                return False, "Conecta pero falta permiso 'Users Read'"
            else:
                return False, f"Error HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)