TOOLS = {
    'csirt': {
        'titulo': 'Gestión CSIRT',
        'descripcion': 'Web scraping y alertas de seguridad.',
        'icono': 'bi-shield-lock',       # Icono de Bootstrap
        'endpoint': 'csirt.index',       # A dónde redirige
        'color': 'primary'               # Color del botón
    },
    'virustotal': {
        'titulo': 'Análisis IoC',
        'descripcion': 'Análisis de IoC con VirusTotal.',
        'icono': 'bi-bug',
        'endpoint': 'virustotal.index',
        'color': 'danger'
    },
    'checklist': {
        'titulo': 'Checklist',
        'descripcion': 'Revisión de plataformas clientes.',
        'icono': 'bi-check2-square',
        'endpoint': 'checklist.index',
        'color': 'success'
    },
    'credentials': {
        'titulo': 'Credenciales',
        'descripcion': 'Almacenamiento seguro de credenciales.',
        'icono': 'bi-key',
        'endpoint': 'credentials.index',
        'color': 'warning'
    }
    # ¡AQUÍ AGREGAS LA PRÓXIMA HERRAMIENTA CON UNA SOLA LÍNEA!
}