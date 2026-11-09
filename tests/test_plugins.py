import os
import glob
import importlib.util
import pytest

PLUGIN_PATHS = [p for p in glob.glob("plugins/*.py") if not os.path.basename(p).startswith("__") and os.path.basename(p) != "base_plugin.py"]

@pytest.fixture
def sample_alert():
    return {
        "id": "TEST-1001",
        "rule_name": "Test Port Scan Detected",
        "severity": "HIGH",             # "LOW", "MEDIUM", "HIGH", or "CRITICAL"
        "source_ip": "185.220.101.5",   # External or internal IPv4 / IPv6
        "timestamp": "2026-11-07 12:45:00",
        "destination_ip": "10.100.2.8",
        "target_user": "root",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # Optional (SHA256/MD5)
        "domain": "malicious-c2-node.com", # Optional
        "raw_kibana_doc": {}            # Optional raw document from Kibana
    }

def test_plugins_exist():
    """Ensure at least one plugin is registered."""
    assert len(PLUGIN_PATHS) > 0, "No plugins found in plugins/ directory"

@pytest.mark.parametrize("plugin_path", PLUGIN_PATHS)
def test_plugin_conforms_to_interface(plugin_path, sample_alert):
    """Dynamically test every plugin in the plugins/ folder."""
    module_name = os.path.basename(plugin_path)[:-3]

    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # 1. Check for instance
    assert hasattr(mod, "plugin_instance"), f"Plugin '{module_name}' must export 'plugin_instance'."

    # 2. Check run() method execution
    output = mod.plugin_instance.run(sample_alert)
    assert isinstance(output, dict), f"Plugin '{module_name}' run() must return a dictionary."
    assert "module" in output, f"Plugin '{module_name}' return dictionary missing required key 'module'."