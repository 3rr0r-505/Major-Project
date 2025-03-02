import os
import re
import sys
import time
import json
import yaml
import paramiko
import requests
import subprocess
import difflib
from pathlib import Path

class codeInjection:
    def __init__(self):
        self.config = self.load_config()
        self.signatures = self.load_commands()

    def load_config(self):
        """Loads honeypot configuration from config.json."""
        config_path = Path(__file__).parent.parent / "configs" / "config.json"
        with open(config_path, "r") as file:
            return json.load(file)

    def load_commands(self):
        """Loads honeypot detection signatures from signatures.yaml."""
        commands_path = Path(__file__).parent.parent / "configs" / "injection-cmd.yaml"
        with open(commands_path, "r") as file:
            return yaml.safe_load(file)

    def execute_ssh_command(self, ip, port, username, password, command):
        """Executes SSH command and returns output."""
        try:
            print(f"[*] Testing SSH command: {command}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port, username, password, timeout=50)
            
            channel = client.invoke_shell()
            time.sleep(1)
            channel.recv(1024)
            channel.send(command + "\n")
            time.sleep(1)
            output = channel.recv(4096).decode().strip()
            # print(f"[*] Received Output: {output}")
            return output
        except Exception as e:
            print(f"[!] SSH Error: {e}")
            return None
        finally:
            client.close()

    def chk_cowrie(self, ip, port, username, password):
        """Detects code injection on Cowrie SSH honeypot."""
        print("[*] Checking code injection on Cowrie")
        print("[DEBUG] self.signatures keys:", self.signatures.keys())
        
        if "cowrie" not in self.signatures.get("codeInjection", {}):
            print("[ERROR] 'cowrie' key not found inside 'codeInjection'!")
        
        for entry in self.signatures.get("codeInjection", {}).get("cowrie", []):
            command = entry["command"]
            expected_output = entry["output"].strip()  # Remove extra spaces/newlines

            print(f"[*] Executing Cowrie test command: {command}")
            print(f"[*] Expected output pattern:\n{expected_output}")

            actual_output = self.execute_ssh_command(ip, port, username, password, command).strip()

            if actual_output:
                print(f"[*] Received Output:\n{actual_output}")

                # Remove the first line if it's the executed command
                actual_lines = actual_output.split("\n")
                if actual_lines[0].strip() == command:
                    actual_output = "\n".join(actual_lines[1:]).strip()

                # Compare line by line
                if all(line in actual_output for line in expected_output.split("\n")):
                    print(f"[*] Expected output found in received output. No code injection.")
                else:
                    print(f"[!] Possible code injection detected! Expected output not found in received output.")
                    return True  # Possible code injection detected
        
        return False

    def execute_http_request(self, ip, port, method, endpoint):
        """Executes HTTP request using curl and returns response."""
        url = f"http://{ip}:{port}{endpoint}"
        print(f"[*] Testing HTTP request: {method} {url}")

        try:
            cmd = ["curl", "-s", f"http://{ip}:{port}{endpoint}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()
            return output
        except Exception as e:
            print(f"[!] Curl Error: {e}")
            return None

    def execute_wpot_httprequest(self, ip, port, method, endpoint):
        """Executes HTTP request using curl and filters response with sed."""
        url = f"http://{ip}:{port}{endpoint}"
        print(f"[*] Testing HTTP request: {method} {url}")

        try:
            # First command: curl
            curl_cmd = ["curl", "-s", url]

            # Second command: sed
            sed_cmd = ["sed", "/<head>/,/<\\/head>/d"]

            # Execute curl and pipe output to sed
            curl_proc = subprocess.Popen(curl_cmd, stdout=subprocess.PIPE)
            sed_proc = subprocess.Popen(sed_cmd, stdin=curl_proc.stdout, stdout=subprocess.PIPE, text=True)

            # Close unused pipe end
            curl_proc.stdout.close()

            # Capture output
            output, _ = sed_proc.communicate()

            return output.strip()
        except Exception as e:
            print(f"[!] Curl Error: {e}")
            return None

    def normalize_http_response(self, response):
        response = response.strip()
        
        # Replace dynamic fields
        response = re.sub(r"(?i)Date:\s+.*GMT", "Date: ANY_DATE GMT", response)
        response = re.sub(r"(?i)Content-Length:\s*\d+", "Content-Length: ANY_LENGTH", response)
        response = re.sub(r"(?i)Set-Cookie: .*?(?=\n|$)", "Set-Cookie: ANY_COOKIE", response, flags=re.MULTILINE)
        response = re.sub(r"(?i)Version:\s*\d+\.\d+\.\d+", "Version: ANY_VERSION", response)
        
        # Normalize whitespace and indentation without affecting header formatting
        response = re.sub(r"[ \t]+", " ", response).strip()

        return response

    def chk_conpot(self, ip, port):
        """Detects code injection on Conpot HTTP honeypot."""
        print("[*] Checking code inejction on Conpot")
        print("[DEBUG] Available signatures keys:", self.signatures.keys())

        conpot_signatures = self.signatures.get("codeInjection", {}).get("conpot", [])
        if not conpot_signatures:
            print("[ERROR] 'conpot' key not found inside 'codeInjection' or it is empty!")
            return False

        for entry in conpot_signatures:
            command = entry.get("command", "")
            expected_output = entry.get("output", "").strip()

            if not command or not expected_output:
                print("[ERROR] Invalid signature entry! Skipping...")
                continue

            # Extract method and endpoint
            try:
                method, endpoint = command.split(" ", 1)
            except ValueError:
                print(f"[ERROR] Invalid command format: {command}")
                continue

            print(f"[*] Executing Conpot test request: {method} {endpoint}")
            print(f"[*] Expected output pattern:\n{expected_output}")

            # Perform HTTP request
            actual_output = self.execute_http_request(ip, port, method, endpoint).strip()

            if not actual_output:
                print("[!] No response received from HTTP request.")
                continue

            print(f"[*] Received Output:\n{actual_output}")

            # Replace dynamic fields in expected output with placeholders
            expected_pattern = expected_output
            expected_pattern = re.sub(r"Date: .+? GMT", "Date: ANY_DATE GMT", expected_pattern)
            expected_pattern = re.sub(r"Content-Length: \d+", "Content-Length: ANY_LENGTH", expected_pattern)
            expected_pattern = re.sub(r"<td>.*?</td>", "<td>ANY_VALUE</td>", expected_pattern)

            # Replace dynamic fields in actual output to match the processed expected pattern
            actual_output_cleaned = actual_output
            actual_output_cleaned = re.sub(r"Date: .+? GMT", "Date: ANY_DATE GMT", actual_output_cleaned)
            actual_output_cleaned = re.sub(r"Content-Length: \d+", "Content-Length: ANY_LENGTH", actual_output_cleaned)
            actual_output_cleaned = re.sub(r"<td>.*?</td>", "<td>ANY_VALUE</td>", actual_output_cleaned)

            # Perform regex search to allow minor variations
            if expected_pattern in actual_output_cleaned:
                print("[*] Expected output found in received output. No code injection.")
            else:
                print("[!] Possible code injection detected! Expected output not found in received output.")
                return True  

        return False

    def chk_wordpot(self, ip, port):
        """Detects code injection on Wordpot honeypot."""
        print("[*] Checking code injection on Wordpot")
        print("[DEBUG] Available signatures keys:", self.signatures.keys())

        wordpot_signatures = self.signatures.get("codeInjection", {}).get("wordpot", [])
        if not wordpot_signatures:
            print("[ERROR] 'wordpot' key not found inside 'codeInjection' or it is empty!")
            return False

        for entry in wordpot_signatures:
            command = entry.get("command", "")
            expected_output = entry.get("output", "").strip()

            if not command or not expected_output:
                print("[ERROR] Invalid signature entry! Skipping...")
                continue

            # Extract method and endpoint
            try:
                method, endpoint = command.split(" ", 1)
            except ValueError:
                print(f"[ERROR] Invalid command format: {command}")
                continue

            print(f"[*] Executing Wordpot test request: {method} {endpoint}")
            print(f"[*] Expected output pattern:\n{expected_output}")

            # Perform HTTP request
            actual_output = self.execute_wpot_httprequest(ip, port, method, endpoint).strip()

            if not actual_output:
                print("[!] No response received from HTTP request.")
                continue

            print(f"[*] Received Output:\n{actual_output}")

            # Clean outputs before comparison
            expected_pattern = self.normalize_http_response(expected_output)
            actual_output_cleaned = self.normalize_http_response(actual_output)

            # Perform relaxed matching using re.search()
            similarity = difflib.SequenceMatcher(None, expected_pattern, actual_output_cleaned).ratio()

            if similarity > 0.8:  # Threshold (adjust as needed)
                print("[*] Expected output closely matches received output. No code injection.")
            else:
                print("[!] Possible code injection detected! Output differs significantly.")
                diff = "\n".join(difflib.unified_diff(expected_pattern.splitlines(), actual_output_cleaned.splitlines(), lineterm=""))
                print(diff)
                return True

        return False

    def inject(self):
        """Main function to detect Cowrie (SSH) and Conpot/Wordpot (HTTP) honeypots."""
        hp_type = self.config.get("honeypot_type", "").lower()
        creds = self.config.get("honeypot_creds", {})
        ip = creds.get("ip")
        port = creds.get("ports")
        username = creds.get("username")
        password = creds.get("password")

        if hp_type == "ssh":
            result = self.chk_cowrie(ip, port, username, password)
        elif hp_type == "http":
            if port == 8800 or port == "8800":
                result = self.chk_conpot(ip, port)
            elif port == 8080 or port == "8080":
                result = self.chk_wordpot(ip, port)
            else:
                print(f"[!] Unknown HTTP honeypot on port {port}.")
                return False
        else:
            print(f"[!] Not available for {hp_type} honeypot.")
            return False

        return "[*] Code Injection detected!" if result else "[*] No Code Injection detected."


