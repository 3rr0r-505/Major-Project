import subprocess

def execute_http_request(ip, port, method, endpoint):
        """Executes HTTP request using curl and returns response."""
        url = f"http://{ip}:{port}{endpoint}"
        print(f"[*] Testing HTTP request: {method} {url}")

        try:
            cmd = ["curl", "-s", f"http://{ip}:{port}{endpoint}", "|", "sed", "'/<head>/,/<\/head>/d'"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()
            return output
        except Exception as e:
            print(f"[!] Curl Error: {e}")
            return None

if __name__ == "__main__":
    result = execute_http_request("54.160.218.15", "8080", "GET", "/" )
    print(result)