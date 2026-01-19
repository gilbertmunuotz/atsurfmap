import requests

class HttpClient:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.headers = {
            "User-Agent": "AttackSurfaceMapper/1.0"
        }

    def get(self, url):
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                return response
            except requests.RequestException:
                return None
        
    def head(self, url):
            try: 
                response = requests.head(
                    url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                return response
            except requests.RequestException:
                return None