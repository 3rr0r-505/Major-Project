import os
import re
import json
import signal
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

class msfScan:
    def __init__(self, config_path=None):
        """
        Initialize the reverse exploit class, loading honeypot configuration.

        Args:
            config_path (str, optional): Custom config file path. Defaults to None.
        """
        self.config_path = config_path or Path(__file__).parent.parent / "configs" / "config.json"
        self.config = self.load_config()
        self.found_msf_modules = {}  # Store CVE to MSF module mapping

    def load_config(self):
        """Loads honeypot configuration from config.json."""
        try:
            with open(self.config_path, "r") as file:
                return json.load(file)
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            return {}

    def run_msf_search(self, cve):
        """Run Metasploit search for a given CVE and return found modules."""
        command = f'msfconsole -q -x "search {cve}; exit"'
        output = subprocess.getoutput(command)

        # Remove ANSI escape codes (colors, formatting)
        output = re.sub(r'\x1b\[[0-9;]*m', '', output)

        # Extract module names (Metasploit uses 'exploit/', 'auxiliary/', etc.)
        found_modules = [
            line.split()[0] for line in output.split("\n")
            if "exploit/" in line or "auxiliary/" in line
        ]

        if found_modules:
            print(f"[+] Metasploit module present for {cve}: {', '.join(found_modules)}")
        else:
            print(f"[!] Metasploit module not present for {cve}")
        
        return cve, found_modules if found_modules else None

    def msfScan(self, cve_dict):
        """
        Scan a list of CVEs against Metasploit modules using threading.

        Args:
            cve_dict (dict): A dictionary of CVEs with severity levels.

        Returns:
            dict: Mapping of CVEs to available MSF modules, or a message if none are found.
        """
        with ThreadPoolExecutor(max_workers=15) as executor:
            try:
                future_to_cve = {executor.submit(self.run_msf_search, cve): cve for cve in cve_dict.keys()}
                
                for future in as_completed(future_to_cve):
                    cve, modules = future.result()
                    if modules:
                        self.found_msf_modules[cve] = modules

            except KeyboardInterrupt:
                print("\n[!] Ctrl+C detected! Shutting down threads...")
                executor.shutdown(wait=False, cancel_futures=True)
                raise SystemExit("\n[!] Scan aborted by user.")

        if not self.found_msf_modules:
            print("\n[!] No Metasploit modules found for the given CVEs.")
            return {"[!] No Metasploit modules found for the given CVEs."}
        
        return self.found_msf_modules

