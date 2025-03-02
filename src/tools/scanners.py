import os
import sys
import json
import subprocess
from pathlib import Path

class Scanners:
    def __init__(self, nikto_timeout, wpscan_timeout):
        self.config = self.load_config()
        self.hp_type = self.config["honeypot_type"].lower()
        self.creds = self.config["honeypot_creds"]
        self.ip = self.creds["ip"]
        self.port = int(self.creds["ports"])
        self.http_link = self.creds["http-link"]
        self.nikto_timeout = nikto_timeout * 60
        self.wpscan_timeout = wpscan_timeout * 60

    def load_config(self):
        config_path = Path(__file__).parent.parent / "configs" / "config.json"
        if not config_path.exists():
            raise FileNotFoundError("[!] Config file not found!")
        with open(config_path, "r") as file:
            return json.load(file)

    def require_sudo(self):
        """Check if script is running as root."""
        if os.geteuid() != 0:
            print("[!] This script requires sudo/root privileges. Restarting with sudo...")
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

    def find_NSEscripts(self, hp_type):
        """Find honeypot-related NSE scripts.
            # currently not used.
        """
        try:
            script_path = "/usr/share/nmap/scripts/"
            honeypot_scripts = subprocess.run(
                ["find", script_path, "-name", "*honeypot*.nse"],
                capture_output=True, text=True
            ).stdout.split("\n")

            type_specific_scripts = subprocess.run(
                ["find", script_path, "-name", f"*{hp_type}*.nse"],
                capture_output=True, text=True
            ).stdout.split("\n")

            # Extract just filenames (without full paths)
            scripts_list = list(filter(None, {os.path.basename(script) for script in honeypot_scripts + type_specific_scripts}))
            print(f"[+] Found NSE scripts: {scripts_list}")
            return scripts_list
        except Exception as e:
            print(f"[!] Error finding NSE scripts: {e}")
            return []

    def run_scan(self, command):
        """Run a scanner and print output live while capturing it."""
        print(f"[+] Running <{' '.join(command)}>")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = []
        
        for line in iter(process.stdout.readline, ''):
            print(line, end='')  # Print live output
            output.append(line.strip())  # Store output without extra newlines

        process.stdout.close()
        process.wait()
        print("[*] Scan Complete.")

        return "\n".join(output)  # Join stored output with proper formatting

    def nmapScanner(self):
        """Run Nmap scan."""
        scripts = self.find_NSEscripts(self.hp_type)
        scripts_str = ",".join(scripts)
        print("\n===============Nmap Scan Report===============\n")
        return self.run_scan(["nmap", "-A", "-Pn", "-T4", "-vv", self.ip])

    def niktoScanner(self):
        """Run Nikto scan."""
        print("\n===============Nikto Scan Report===============\n")
        return self.run_scan(["nikto", "-h", self.http_link, "-Tuning", "123bde", "-Display", "V", "-maxtime", str(self.nikto_timeout)])

    def wpScanner(self):
        """Run WPScan."""
        print("\n===============WPscan Scan Report===============\n")
        return self.run_scan(["timeout", str(self.wpscan_timeout), "wpscan", "--url", self.http_link, "--enumerate", "vp,vt,cb,dbe,u", "--max-threads", "10", "--random-user-agent", "--verbose"])

    def scan(self):
        """Perform scans based on honeypot type."""
        scan_functions = {
            "ssh": [self.nmapScanner],
            "http_8800": [self.nmapScanner, self.niktoScanner],
            "http_8080": [self.nmapScanner, self.niktoScanner, self.wpScanner]
        }

        scan_key = f"{self.hp_type}_{self.port}" if self.hp_type == "http" else self.hp_type
        scans = scan_functions.get(scan_key)

        if not scans:
            print(f"[!] Scanning not available for {self.hp_type} honeypot.")
            return False

        return tuple(scan() for scan in scans) if len(scans) > 1 else scans[0]()
