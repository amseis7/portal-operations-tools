from app.checklist.plugins.demo import DemoPlugin
from app.checklist.plugins.crowdstrike import CrowdStrikePlugin
from app.checklist.plugins.umbrella import UmbrellaPlugin
from app.checklist.plugins.trendmicro import VisionOnePlugin
from app.checklist.plugins.fortiedr import FortiEDRPlugin
from app.checklist.plugins.carbonblack import CarbonBlackPlugin

AVAILABLE_PLUGINS = {
    'demo_plugin': DemoPlugin,
    'crowsdstrike': CrowdStrikePlugin,
    'cisco_umbrella': UmbrellaPlugin,
    'trend_micro_v1': VisionOnePlugin,
    'fortiedr': FortiEDRPlugin,
    'carbon_black': CarbonBlackPlugin
}

def get_plugin_class(slug):
    """Retorna la CLASE del plugin según su slug"""
    return AVAILABLE_PLUGINS.get(slug)