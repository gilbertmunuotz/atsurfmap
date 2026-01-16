from utils.http_client import HttpClient

def main():
    print("Web Application Attack Surface Mapping Tool")
    
    target = input("Enter the target URL (e.g. https://example.com): ").strip()

    client = HttpClient()
    response = client.get(target)

    if response:
        print(f"[+] Target reachable: {target}")
        print(f"[+] HTTP status: {response.status_code}")
    else:
        print(f"[-] Failed to reach target")

if __name__ == "__main__":
    main()