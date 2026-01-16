import requests
from requests.auth import HTTPBasicAuth

# --- CONFIGURACIÓN ---
# 1. Ve a Admin > API Keys
# 2. Tu llave debe tener el SCOPE: "Managed Providers" o "admin.customers:read"
client_id = "0120f9c3aa264c94b3e5fd73c2bf9544"       # Pega aquí tu Key ID
client_secret = "cc1d64ddf96c4beb9d2f5b3ac62e7d93" # Pega aquí tu Key Secret

# --- PASO 1: Obtener el Token (Autenticación OAuth 2.0) ---
auth_url = "https://api.umbrella.com/auth/v2/token"

print("1. Solicitando Token de acceso...")
response = requests.post(
    auth_url,
    auth=HTTPBasicAuth(client_id, client_secret),
    data={"grant_type": "client_credentials"}
)

if response.status_code != 200:
    print(f"❌ Error fatal obteniendo token: {response.status_code}")
    print(response.json())
    exit()

# --- 1.2 Inspección del Token ---
if response.status_code == 200:
    data = response.json()
    print("✅ Token obtenido exitosamente.")
    print(f"🔑 Scopes (Permisos) detectados: {data.get('scope', 'No especificado en respuesta')}\n")
    access_token = data.get("access_token")
else:
    print(f"❌ Error fatal obteniendo token: {response.status_code}")
    print(response.text)
    exit()

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

# --- PASO 2: Prueba de Endpoints (Discovery) ---

# --- PASO 2: Explorando Nuevas Oportunidades ---

print("2. Explorando endpoints para nuevas funcionalidades...")

# Oportunidad A: Roaming Computers (Agentes instalados en laptops)
# Es vital saber si los agentes están activos y syncing.
try:
    print("\n   👉 Check Roaming Computers (deployments/v2/roamingcomputers):")
    url_rc = "https://api.umbrella.com/deployments/v2/roamingcomputers?limit=1"
    r_rc = requests.get(url_rc, headers=headers)
    if r_rc.status_code == 200:
        items = r_rc.json()
        print(f"      ✅ ACCESO CONFIRMADO. Se encontraron {len(items)} agentes de muestra.")
        if len(items) > 0:
            print(f"      Ejemplo de dato: {items[0].get('name')} - Status: {items[0].get('status')}")
    else:
        print(f"      ❌ Sin acceso a Roaming Computers ({r_rc.status_code})")
except Exception as e:
    print(f"      ⚠️ Error: {e}")

# Oportunidad B: Resumen de Seguridad (Bloqueos vs Permitidos)
# Usamos la API de reportes para ver el volumen de las últimas 24hs
try:
    print("\n   👉 Check Security Summary (reports/v2/total-requests):")
    # Pedimos datos agrupados por 'decision' (blocked vs allowed)
    url_rep = "https://api.umbrella.com/reports/v2/total-requests?from=-1days&to=now&namer=decision"
    r_rep = requests.get(url_rep, headers=headers)
    
    if r_rep.status_code == 200:
        data = r_rep.json()
        print(f"      ✅ ACCESO CONFIRMADO a Reportes.")
        print(f"      Datos crudos: {data}")
    else:
        print(f"      ❌ Sin acceso a Reportes de Seguridad ({r_rep.status_code})")
except Exception as e:
    print(f"      ⚠️ Error: {e}")

print("\n--- RECOMENDACIÓN ---")
print("Si las pruebas de arriba salieron con ✅, podemos implementar:")
print("1. 'Agentes Roaming': Ver cuántos están 'Protected' vs 'Inactive'.")
print("2. 'Nivel de Amenaza': Mostrar cuántos ataques se bloquearon hoy.")