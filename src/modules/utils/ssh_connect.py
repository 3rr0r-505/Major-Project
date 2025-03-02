##################################################
# from utils.ssh_connector import ConnectSSH  
# [Create an instance of the SSH connector]
# ssh_client = ConnectSSH()
# [Connect to the SSH honeypot]
# ssh_client.connect()
##################################################


import os
import json
import logging
import paramiko
from config_loader import configJSON

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConnectSSH:
    def __init__(self):
        self.config_path = configJSON()  # configJSON() returns the config.json location
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from the given JSON file."""
        try:
            with open(self.config_path, 'r') as file:
                return json.load(file)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return None
    
    def connect(self):
        """Connect to an SSH honeypot using credentials from the config file."""
        if not self.config:
            return
        
        if self.config.get("honeypot_type", "").lower() != "ssh":
            logging.warning("Honeypot type is not SSH. Exiting...")
            return
        
        creds = self.config.get("honeypot_creds", {})
        ip, port, username, password = creds.get("ip"), creds.get("ports"), creds.get("username"), creds.get("password")
        
        if not all([ip, port, username, password]):
            logging.warning("Incomplete SSH credentials. Exiting...")
            return
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=int(port), username=username, password=password, timeout=10)
            logging.info("Connected to SSH honeypot!")
            
            stdin, stdout, stderr = client.exec_command("whoami")
            logging.info(f"Output: {stdout.read().decode().strip()}")
            
            client.close()
        except paramiko.AuthenticationException:
            logging.error("SSH authentication failed.")
        except paramiko.SSHException as e:
            logging.error(f"SSH connection error: {e}")
        except Exception as e:
            logging.error(f"SSH connection failed: {e}")
