from app.checklist.plugins.demo import DemoPlugin

AVAILABLE_PLUGINS = {
    'demo_plugin': DemoPlugin
}

def get_plugin_class(slug):
    """Retorna la CLASE del plugin según su slug"""
    return AVAILABLE_PLUGINS.get(slug)