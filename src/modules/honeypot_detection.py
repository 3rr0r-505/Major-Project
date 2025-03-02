import os
import re
import json
import yaml
import subprocess
from pathlib import Path

class detectHoneypot:
    def __init__(self):
        self.config = self.load_config()
        self.signatures = self.load_signatures()

    def load_config(self):
        """Loads honeypot configuration from config.json."""
        config_path = Path(__file__).parent.parent / "configs" / "config.json"
        with open(config_path, "r") as file:
            return json.load(file)

    def load_signatures(self):
        """Loads honeypot detection signatures from signatures.yaml."""
        signature_path = Path(__file__).parent.parent / "configs" / "signatures.yaml"
        with open(signature_path, "r") as file:
            signatures = yaml.safe_load(file)

        # Convert integer keys to strings
        signatures = {str(k): v for k, v in signatures.items()}
        
        print(f"[*] Loaded Signatures: {signatures}")  # Debugging print
        return signatures

    def run_nc(self, command):
        """Executes a Netcat (nc) command and returns the output."""
        try:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
            output = result.stdout.strip()
            print(f"[*] Netcat Output: {output}")  # Debugging print
            return output if output else "[!] No response received."
        except subprocess.TimeoutExpired:
            return "[!] Netcat command timed out."
        except Exception as e:
            return f"[!] Error running Netcat: {e}"

    def detect_cowrie(self, ip, port):
        """Detects Cowrie SSH honeypot by checking SSH banners via Netcat."""
        command = f'echo -e "\\n" | nc -w 5 -v {ip} {port}'
        response = self.run_nc(command)
        print(f"[*] Full Cowrie Response:\n{response}")  # Debugging print

        # Extract only the second line (SSH banner)
        response_lines = response.split("\n")
        if len(response_lines) > 1:
            ssh_banner = response_lines[1].strip().replace("\r", "").replace("\n", "")
        else:
            print("[!] No valid SSH banner received.")
            return False  

        # Debugging print to show exact byte representation
        print(f"[*] Extracted SSH Banner (Raw Bytes): {repr(ssh_banner)}")

        # Ensure signatures are loaded properly
        cowrie_signatures = self.signatures.get("2222", [])
        print(f"[*] Loaded Signatures for 2222: {cowrie_signatures}")

        # Compare with expected signature
        for entry in cowrie_signatures:
            for step in entry.get("steps", []):
                expected_banner = step.get("output", "").strip().replace("\r", "").replace("\n", "")
                print(f"[*] Checking Signature: {repr(expected_banner)}")  # Debugging print
                if ssh_banner == expected_banner:
                    print("[+] Cowrie Honeypot Detected!")
                    return True  # Cowrie detected
        return False

    def detect_conpot(self, ip, port):
        """Detects Conpot HTTP honeypot by extracting the title tag from the response."""
        command = f'printf "GET /index.html HTTP/1.1\\r\\nHost: {ip}\\r\\nConnection: close\\r\\n\\r\\n" | nc -w 10 -v {ip} {port}'
        response = self.run_nc(command)
        print(f"[*] Conpot Response:\n{response}")  # Debugging print

        # Extract <TITLE> content using regex
        title_match = re.search(r"<TITLE>(.*?)</TITLE>", response, re.IGNORECASE | re.DOTALL)
        extracted_title = title_match.group(1).strip() if title_match else ""

        print(f"[*] Extracted HTML Title: '{extracted_title}'")  # Debugging print

        # Ensure signatures are loaded properly
        conpot_signatures = self.signatures.get("8800", [])
        print(f"[*] Loaded Signatures for 8800: {conpot_signatures}")

        # Compare extracted title with expected title
        for entry in conpot_signatures:
            for step in entry.get("steps", []):
                expected_title = step.get("output", "").strip()
                print(f"[*] Checking Signature: '{expected_title}'")  # Debugging print
                if extracted_title == expected_title:
                    print("[+] Conpot Honeypot Detected!")
                    return True  # Conpot detected
        return False

    def detect_wordpot(self, ip, port):
        """Detects Wordpot honeypot by extracting the title and meta generator tag."""
        
        # Run netcat command to extract both title and meta generator
        command = f'printf "GET / HTTP/1.1\\r\\nHost: {ip}\\r\\nConnection: close\\r\\n\\r\\n" | nc -w 10 -v {ip} {port} | grep -i -E "<title>|<meta name=\\"generator\\""'
        response = self.run_nc(command)

        print(f"[*] Wordpot Response:\n{response}")  # Debugging print

        # Extract title
        title_match = re.search(r"<title>(.*?)</title>", response, re.IGNORECASE | re.DOTALL)
        extracted_title = title_match.group(1).strip() if title_match else ""

        # Extract meta generator
        meta_match = re.search(r'<meta name="generator" content="(.*?)"\s*/?>', response, re.IGNORECASE | re.DOTALL)
        extracted_meta = meta_match.group(1).strip() if meta_match else ""

        print(f"[*] Extracted HTML Title: '{extracted_title}'")  # Debugging print
        print(f"[*] Extracted Meta Generator: '{extracted_meta}'")  # Debugging print

        # Ensure signatures are loaded properly
        wordpot_signatures = self.signatures.get("8080", [])
        print(f"[*] Loaded Signatures for 8080: {wordpot_signatures}")

        # Compare extracted title/meta with expected signatures
        for entry in wordpot_signatures:
            for step in entry.get("steps", []):
                expected_output = step.get("output", "").strip()

                print(f"[*] Checking Signature: '{expected_output}'")  # Debugging print

                if extracted_title == expected_output or extracted_meta == expected_output:
                    print("[+] Wordpot Honeypot Detected!")
                    return True  # Wordpot detected

        return False  # No match found

    def detect(self):
        """Main function to detect Cowrie (SSH) and Conpot (HTTP) honeypots using Netcat."""
        hp_type = self.config["honeypot_type"].lower()
        creds = self.config["honeypot_creds"]
        ip = creds["ip"]
        port = creds["ports"]

        if hp_type == "ssh":
            result = self.detect_cowrie(ip, port)
        elif hp_type == "http" and port == "8800":
            result = self.detect_conpot(ip, port)
        elif hp_type == "http" and port == "8080":
            result = self.detect_wordpot(ip, port)
        else:
            print(f"[!] Not avilable for {hp_type} honeypot.")
            return False

        return "[*] Honeypot detected!" if result else "[*] No honeypot detected."