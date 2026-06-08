import os
import json
from pathlib import Path

class Config:
    def __init__(self):
        self.config_file = "hids_config.json"
        self.settings = self.load_or_create()

    def load_or_create(self):
        default = {
            "monitor_directories": ["/etc", "/home", "/var/log"],
            "file_extensions": [".py", ".sh", ".conf", ".exe", ".dll", ".so"],
            "exclude_dirs": ["__pycache__", ".git", "node_modules", "venv"],
            "scan_interval_seconds": 300,
            "hash_algorithm": "sha256",
            "virustotal_api_key": "",
            "virustotal_enable": True,
            "virustotal_max_per_scan": 4
        }
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    return json.load(f)
            except:
                pass
        with open(self.config_file, "w") as f:
            json.dump(default, f, indent=4)
        return default