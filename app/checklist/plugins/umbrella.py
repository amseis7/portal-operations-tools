import requests
from requests.auth import HTTPBasicAuth
from app.checklist.plugins.base import BasePlugin

class UmbrellaPlugin(BasePlugin):
    """
    Plugin para monitorear el estado de Cisco Umbrella.
    Verifica:
    1. Usuarios sin Multi-Factor Authentication (MFA).
    2. Estado de Virtual Appliances (VAs).
    3. Estado de Active Directory Connectors.
    4. Estado de Domain Controllers.
    """
    nombre = "Cisco Umbrella"
    slug = "cisco_umbrella"

    # --- CONSTANTES ---
    TIMEOUT = 10
    URL_TOKEN = "https://api.umbrella.com/auth/v2/token"
    URL_USERS = "https://api.umbrella.com/admin/v2/users"
    URL_VAs = "https://api.umbrella.com/deployments/v2/virtualappliances"

    # Estados considerados "Saludables" por la API
    # Nota: Algunos pueden venir como diccionarios stringificados
    VALID_STATES = {'working', 'ok', 'active', 'green', 'success'}
    
    # Indicadores positivos dentro de un string de diccionario (ej: "{'syncing': 'yes'}")
    POSITIVE_DICT_INDICATORS = ["'syncing': 'yes'", "'connectedtoconnector': 'yes'"]

    @staticmethod
    def get_form_fields():
        return [
            {
                'name': 'api_key', 
                'label': 'Management API Key', 
                'type': 'text', 
                'placeholder': 'Key ID (Admin API)'
            },
            {
                'name': 'api_secret', 
                'label': 'Key Secret', 
                'type': 'password', 
                'placeholder': 'Key Secret'
            }
        ]

    def _get_token(self):
        """Obtiene el token OAuth2 usando credenciales del plugin."""
        try:
            k = self.credentials.get('api_key', '')
            s = self.credentials.get('api_secret', '')
            print(f"DEBUG: Intentando Auth con Key: '{k[:5]}...' y Secret: '{s[:5]}...'")
            
            r = requests.post(
                self.URL_TOKEN, 
                auth=HTTPBasicAuth(k, s),
                data={'grant_type': 'client_credentials'},
                timeout=self.TIMEOUT
            )
            
            if r.status_code == 200:
                return r.json().get('access_token')
            
            print(f"Error Umbrella Auth: {r.status_code} - {r.text}")
        except Exception as e:
            print(f"Excepción Umbrella Auth: {e}")
        
        return None

    def test_connection(self):
        """Prueba de conectividad requerida por BasePlugin."""
        token = self._get_token()
        if token:
             return True, "Autenticación Exitosa (Token Recibido)"
        return False, "Fallo de Autenticación. Revisa credenciales."

    def _check_mfa(self, headers):
        """Identifica usuarios administrativos sin 2FA habilitado."""
        issues = []
        try:
            r = requests.get(self.URL_USERS, headers=headers, timeout=self.TIMEOUT)
            
            if r.status_code == 200:
                data = r.json()
                users = data.get('data', []) if isinstance(data, dict) else data

                for u in users:
                    # 'twoFactorEnable' suele ser booleano
                    if not u.get('twoFactorEnable', True): 
                        issues.append({
                            'user': u.get('email', 'Desconocido'),
                            'role': u.get('role', 'N/A')
                        })
            else:
                print(f"Error API Users: {r.status_code}")
        except Exception as e:
            print(f"Error MFA Check: {e}")
        
        return issues

    def _validate_item_state(self, item, item_type):
        """
        Analiza el estado de un componente (VA, Connector, DC) y determina si es saludable.
        Retorna (estado_final, lista_de_fallos)
        """
        raw_state = item.get('state')
        raw_health = item.get('health')
        fallos = []
        
        # 1. Validación de Diccionarios (Estructura compleja)
        if isinstance(raw_state, dict):
            # Caso común: estado es un objeto con propiedades específicas
            if str(raw_state.get('syncing', '')).lower() in ['no', 'error', 'failed']:
                fallos.append(f"Sync: {raw_state.get('syncing')}")
        
        # 2. Validación de Strings (Estado simple o representación de dict)
        else:
            state_str = str(raw_state if raw_state else 'Unknown').lower()
            health_str = str(raw_health if raw_health else 'Unknown').lower()

            # Verificación especial: ¿Es un string que parece un diccionario positivo?
            is_fake_dict_ok = any(ind in state_str for ind in self.POSITIVE_DICT_INDICATORS)

            if not is_fake_dict_ok:
                # Regla Específica para Virtual Appliances
                if item_type in ['VA', 'virtual_appliance']:
                    if not any(x in state_str for x in self.VALID_STATES) and \
                       not any(x in health_str for x in self.VALID_STATES):
                        fallos.append(f"Estado/Salud: {raw_state or raw_health}")
                # Regla Genérica
                else:
                    if not any(x in state_str for x in self.VALID_STATES):
                        fallos.append(f"Estado: {raw_state}")

        # 3. Validaciones de Raíz (Propiedades fuera del objeto 'state')
        if str(item.get('syncing', '')).lower() in ['no', 'error']:
            fallos.append("Error Sincronización")
            
        if str(item.get('connectedToConnector', '')).lower() in ['no', 'never']:
            fallos.append("Sin Conexión al Conector")

        # Determinación final
        return ('Error' if fallos else 'OK'), fallos

    def _check_infra(self, headers):
        """Obtiene y clasifica la infraestructura (VAs, Connectors, DCs)."""
        issues = []
        summary = {
            'vas': {'total': 0, 'active': 0, 'status': 'OK', 'details': []},
            'ad_connectors': {'total': 0, 'active': 0, 'status': 'OK', 'details': []},
            'domain_controllers': {'total': 0, 'active': 0, 'status': 'OK', 'details': []},
            'cloud_status': 'Unknown'
        }
        
        try:
            r = requests.get(self.URL_VAs, headers=headers, timeout=self.TIMEOUT)
            
            if r.status_code == 200:
                summary['cloud_status'] = 'OK'
                items = r.json()

                for item in items:
                    item_type = item.get('type')
                    nombre = item.get('name', 'Desconocido')
                    
                    # Mapeo de Tipos API -> Claves Resumen
                    target_key = None
                    if item_type in ['VA', 'virtual_appliance']:
                        target_key = 'vas'
                    elif item_type == 'connector':
                        target_key = 'ad_connectors'
                    elif item_type == 'domain_controller':
                        target_key = 'domain_controllers'
                    
                    if target_key:
                        summary[target_key]['total'] += 1
                        
                        # Validar Item
                        estado_item, fallos_item = self._validate_item_state(item, item_type)

                        if estado_item == 'OK':
                            summary[target_key]['active'] += 1
                        else:
                            summary[target_key]['status'] = 'Warning'
                            issues.append({
                                'component': f"{item_type}: {nombre}", 
                                'state': ", ".join(fallos_item)
                            })

                        # Guardar detalle para el modal
                        summary[target_key]['details'].append({
                            'name': nombre,
                            'state': estado_item,
                            'issues': ", ".join(fallos_item) if fallos_item else "OK",
                            'type': item_type,
                            'raw_state': str(item.get('state'))
                        })
            else:
                summary['cloud_status'] = f"API Error {r.status_code}"

        except Exception as e:
            print(f"Error Infra Check: {e}")
            issues.append({'component': 'Error Plugin Infra', 'state': str(e)})
            summary['cloud_status'] = 'Error'
        
        return issues, summary

    def run_checks(self):
        """Ejecuta el ciclo completo de validación."""
        token = self._get_token()
        if not token:
            return 'offline', 'Error de Autenticación (Token)', {}

        headers = {'Authorization': f'Bearer {token}'}
        
        # 1. Ejecutar revisiones
        mfa_issues = self._check_mfa(headers)
        infra_issues, infra_summary = self._check_infra(headers)
        
        # 2. Estructura de Resultados
        detalles_json = {
            "mfa_alertas": mfa_issues,
            "infra_alertas": infra_issues,
            "infra_summary": infra_summary,
            "total_mfa": len(mfa_issues),
            "total_infra": len(infra_issues)
        }

        # 3. Lógica de Semáforo (Estado Global)
        estado = 'success'
        mensajes = []

        if infra_issues:
            estado = 'offline' 
            mensajes.append(f"{len(infra_issues)} Fallas de Infra")
        
        if mfa_issues:
            # Si ya está offline (rojo), no lo bajamos a warning (amarillo)
            if estado != 'offline': 
                estado = 'warning'
            mensajes.append(f"{len(mfa_issues)} Usuarios sin MFA")

        if not mensajes:
            mensaje_final = "🟢 Plataforma Saludable"
        else:
            mensaje_final = " / ".join(mensajes)

        return estado, mensaje_final, detalles_json