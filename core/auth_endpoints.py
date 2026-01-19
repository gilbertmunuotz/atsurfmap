import requests

class AuthEndpointScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.common_paths = [
            "/login",
            "/signin",
            "/admin",
            "/administrator",
            "/admin/login",
            "/dashboard",
            "/user/login",
            "/account/login"
        ]

    def scan(self):
        discovered = []

        for path in self.common_paths:
            url = self.base_url + path
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)

                if response.status_code in [200, 401, 403]:
                    discovered.append({
                        "endpoint": path,
                        "status": response.status_code
                    })

            except requests.RequestException:
                continue

        return discovered
