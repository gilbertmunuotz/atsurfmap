class RiskAnalyzer:
    def __init__(self):
        pass

    def analyze(self, findings):
        risks = []

        # Security headers
        missing_headers = findings.get("missing_headers", [])
        if missing_headers:
            risks.append({
                "issue": "Missing security headers",
                "risk": "MEDIUM",
                "impact": "Increased risk of XSS, clickjacking, and data injection"
            })

        # Authentication endpoints
        if findings.get("auth_endpoints"):
            risks.append({
                "issue": "Exposed authentication endpoints",
                "risk": "MEDIUM",
                "impact": "Potential brute-force or credential stuffing attacks"
            })

        # Directories
        if findings.get("directories"):
            risks.append({
                "issue": "Exposed directories or sensitive paths",
                "risk": "HIGH",
                "impact": "Possible data leakage or unauthorized access"
            })

        # Open ports
        open_ports = findings.get("open_ports", [])
        for port in open_ports:
            if port["port"] == 22:
                risks.append({
                    "issue": "SSH service exposed",
                    "risk": "HIGH",
                    "impact": "Remote administrative access may be targeted"
                })

            if port["port"] in [8080, 8443]:
                risks.append({
                    "issue": "Alternative web service ports exposed",
                    "risk": "MEDIUM",
                    "impact": "May expose admin panels or test services"
                })

        return risks
