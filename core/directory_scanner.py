import requests

class DirectoryScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.common_dirs = [
            "/uploads",
            "/upload",
            "/files",
            "/static",
            "/assets",
            "/images",
            "/backup",
            "/backups",
            "/config",
            "/configs",
            "/logs",
            "/tmp",
            "/temp",
            "/api",
            "/api/v1",
            "/api/v2",
            "/.env",
            "/.git"
        ]

    def scan(self):
        findings = []

        for path in self.common_dirs:
            url = self.base_url + path
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)

                if response.status_code in [200, 301, 302, 401, 403]:
                    findings.append({
                        "path": path,
                        "status": response.status_code
                    })

            except requests.RequestException:
                continue

        return findings
