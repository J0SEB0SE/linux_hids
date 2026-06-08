import requests

class VirusTotal:
    def __init__(self, api_key, enabled):
        self.api_key = api_key
        self.enabled = enabled

    def check(self, file_hash, file_path):
        if not self.enabled or not self.api_key:
            return {"status": "disabled"}
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.api_key}
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    print(f"[ALERT] MALICIOUS FILE: {file_path} ({malicious} detections)")
                return {"malicious": malicious}
            return {"status": "not_found"}
        except:
            return {"status": "error"}