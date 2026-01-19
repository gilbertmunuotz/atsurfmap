import socket
from urllib.parse import urlparse

class PortScanner:
    def __init__(self, target_url):
        parsed = urlparse(target_url)
        self.host = parsed.hostname

        self.common_ports = {
            21: "FTP",
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }

    def scan(self):
        open_ports = []

        for port, service in self.common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)

            try:
                result = sock.connect_ex((self.host, port))
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "service": service
                    })
            except socket.error:
                pass
            finally:
                sock.close()

        return open_ports
