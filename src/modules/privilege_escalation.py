import os
import re
import json
import yaml
import subprocess
from pathlib import Path
from tabulate import tabulate

class privEsc:
    def __init__(self):
        self.config = self.load_config()

    def load_config(self):
        """Loads honeypot configuration from config.json."""
        config_path = Path(__file__).parent.parent / "configs" / "config.json"
        with open(config_path, "r") as file:
            return json.load(file)

    def chk_trivy(self):
        """Check if Trivy is installed."""
        try:
            subprocess.run(["sudo", "trivy", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            print("[!] Trivy is not installed.")
            return False

    def run_trivy(self, image_name):
        """Find CVEs for the honeypots using Trivy and format the output."""
        if not self.chk_trivy():
            return {}
        try:
            result = subprocess.run([
                "sudo", "trivy", "image", image_name, "--format", "json"
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            data = json.loads(result.stdout)
            cve_dict = {}
            cve_list = []
            unique_cves = set()
            
            print(f"\n[*] Finding CVE for {image_name}: \n")
            for target in data.get("Results", []):
                for vuln in target.get("Vulnerabilities", []):
                    if vuln.get("Status") == "affected":
                        cve_id = vuln.get("VulnerabilityID", "N/A")
                        severity = vuln.get("Severity", "N/A")
                        
                        if cve_id not in unique_cves:
                            unique_cves.add(cve_id)
                            cve_dict[cve_id] = severity
                            cve_list.append([
                                vuln.get("PkgName", "N/A"),
                                cve_id,
                                severity,
                                vuln.get("Status", "N/A"),
                                vuln.get("InstalledVersion", "N/A"),
                                vuln.get("FixedVersion", "N/A"),
                                vuln.get("Title", "N/A")
                            ])
            total_cves = len(unique_cves)
            if cve_list:
                print(tabulate(cve_list, headers=["Library", "Vulnerability", "Severity", "Status", "Installed Version", "Fixed Version", "Title"], tablefmt="grid"))
                print(f"[+] Total CVEs found: {total_cves}")
            else:
                print("[+] No vulnerabilities found.")
            return cve_dict
        except Exception as e:
            print(f"[!] Error running Trivy: {e}")
            return {}

    def chk_dockerImage(self, image_name):
        """Check if the Docker image is present. If not, pull the image."""
        try:
            result = subprocess.run(["sudo", "docker", "images", "--format", "{{.Repository}}"], stdout=subprocess.PIPE, text=True)
            available_images = result.stdout.splitlines()
            if image_name not in available_images:
                print(f"[+] Pulling Docker image {image_name}...")
                subprocess.run(["sudo", "docker", "pull", image_name], check=True)
            return True
        except Exception as e:
            print(f"[!] Error checking/pulling Docker image: {e}")
            return False

    def scanImage(self):
        """Main function to check for CVEs in Cowrie (SSH), Conpot (HTTP), and Wordpot (HTTP-WordPress) honeypots."""
        hp_type = self.config["honeypot_type"].lower()
        creds = self.config["honeypot_creds"]
        ip = creds["ip"]
        port = str(creds["ports"])

        image_mapping = {
            "ssh-2222": "cowrie/cowrie",
            "http-8800": "honeynet/conpot",
            "http-8080": "wordpot"
        }

        image_name = image_mapping.get(f"{hp_type}-{port}", None)
        if not image_name:
            print(f"[!] No known honeypot type detected for {hp_type} on port {port}.")
            return {}

        if self.chk_dockerImage(image_name):
            return self.run_trivy(image_name)
        else:
            print("[!] Failed to check Docker image.")
            return {}
