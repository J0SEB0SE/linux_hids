import os
import hashlib
import json
from datetime import datetime
import time
import psutil
from config import Config
from virustotal import VirusTotal

class Scanner:
    def __init__(self, config):
        self.config = config.settings
        self.baseline_path = "file_baseline.json"
        self.baseline = {}
        self.vt = VirusTotal(
            self.config.get("virustotal_api_key"),
            self.config.get("virustotal_enable")
        )

    def hash_file(self, path):
        try:
            h = getattr(hashlib, self.config["hash_algorithm"])()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None

    def build_baseline(self):
        print("Building baseline... Please wait.")
        self.baseline = {}
        for directory in self.config["monitor_directories"]:
            if not os.path.exists(directory):
                continue
            for root, dirs, files in os.walk(directory):
                dirs[:] = [d for d in dirs if d not in self.config["exclude_dirs"]]
                for file in files:
                    if any(file.endswith(ext) for ext in self.config["file_extensions"]):
                        full = os.path.join(root, file)
                        h = self.hash_file(full)
                        if h:
                            self.baseline[full] = h
        with open(self.baseline_path, "w") as f:
            json.dump(self.baseline, f, indent=4)
        print(f"Baseline built with {len(self.baseline)} files.")

    def load_baseline(self):
        if os.path.exists(self.baseline_path):
            try:
                with open(self.baseline_path) as f:
                    self.baseline = json.load(f)
                print(f"Loaded baseline with {len(self.baseline)} files.")
                return True
            except:
                return False
        return False

    def scan_files(self):
        print("Scanning files...")
        changes = []
        current = {}
        vt_count = 0
        max_vt = self.config.get("virustotal_max_per_scan", 4)

        for directory in self.config["monitor_directories"]:
            if not os.path.exists(directory):
                continue
            for root, dirs, files in os.walk(directory):
                dirs[:] = [d for d in dirs if d not in self.config["exclude_dirs"]]
                for file in files:
                    if not any(file.endswith(ext) for ext in self.config["file_extensions"]):
                        continue
                    full = os.path.join(root, file)
                    h = self.hash_file(full)
                    if not h:
                        continue
                    current[full] = h
                    if full in self.baseline:
                        if self.baseline[full] != h:
                            changes.append({"type": "MODIFIED", "path": full, "hash": h})
                    else:
                        changes.append({"type": "CREATED", "path": full, "hash": h})

        for path in list(self.baseline.keys()):
            if path not in current:
                changes.append({"type": "DELETED", "path": path})

        if changes and self.config.get("virustotal_enable"):
            for c in changes:
                if c["type"] in ("CREATED", "MODIFIED") and vt_count < max_vt:
                    self.vt.check(c["hash"], c["path"])
                    vt_count += 1
                    time.sleep(15)

        if changes:
            with open("hids_alerts.log", "a") as f:
                f.write(f"\n--- {datetime.now()} ---\n")
                for c in changes:
                    line = f"{c['type']} | {c['path']}\n"
                    print(line.strip())
                    f.write(line)
        else:
            print("No changes detected.")

        return changes

    def scan_processes(self):
        print("Scanning processes...")
        suspicious = ["miner", "crypt", "backdoor"]
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                p = proc.info
                name = p["name"].lower()
                if any(s in name for s in suspicious):
                    print(f"[PROCESS ALERT] {p['name']} (PID: {p['pid']})")
            except:
                continue