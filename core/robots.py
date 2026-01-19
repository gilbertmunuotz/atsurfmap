from urllib.parse import urljoin
from utils.http_client import HttpClient

class RobotsAnalyzer:
    def __init__(self, base_url):
        self.base_url = base_url
        self.client = HttpClient()

    def fetch(self):
        robots_url = urljoin(self.base_url, "/robots.txt")
        response = self.client.get(robots_url)

        if not response or response.status_code != 200:
            return None

        return response.text
    
    def parse(self, content):
        disallowed = []

        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1).strip()
                if path:
                    disallowed.append(path)

        return disallowed
