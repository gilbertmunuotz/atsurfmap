class HeaderAnalyzer:
    def __init__(self, response):
        self.headers = response.headers
        self.cookies = response.cookies

    def analyze_headers(self):
        findings = {}

        findings["Server"] = self.headers.get("Server", "Not disclosed")
        findings["X-Powered-By"] = self.headers.get("X-Powered-By", "Not disclosed")

        security_headers = {
            "Content-Security-Policy": self.headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": self.headers.get("Strict-Transport-Security"),
            "X-Frame-Options": self.headers.get("X-Frame-Options"),
            "X-Content-Type-Options": self.headers.get("X-Content-Type-Options"),
            "Referrer-Policy": self.headers.get("Referrer-Policy"),
        }

        findings["Security Headers"] = {
            k: ("Present" if v else "Missing")
            for k, v in security_headers.items()
        }

        return findings

    def analyze_cookies(self):
        cookie_results = []

        for cookie in self.cookies:
            cookie_results.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly")
            })

        return cookie_results