import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, target):
        self.target = target
        self.report_dir = "reporting"
        os.makedirs(self.report_dir, exist_ok=True)

    def generate(self, findings, risks):
        return {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "findings": findings,
            "risk_analysis": risks
        }

    def save(self, report, filename="attack_surface_report.json"):
        path = os.path.join(self.report_dir, filename)
        with open(path, "w") as f:
            json.dump(report, f, indent=4)
