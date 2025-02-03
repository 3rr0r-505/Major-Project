##################################################
# Note: main.py is not completed!
# Note: implement after completing modules! 
##################################################

# importing libraries
import os
import time
import json
import datetime
from tools import nmap_scan, nikto_scan, metasploit_exploit, openvas_scan
from modules import (
    honeypot_detection, privilege_escalation, code_injection, 
    data_leakage, reverse_exploit, service_crash, dos_attack, evading_logs
)

# ASCII Banner
BANNER = r"""
#####################################################################################################
##     __  __                                      ____              __     __     _____           ##
##    / / / /  ____     ____     ___     __  __   / __ \   ____     / /_   / /_   |__  /   _____   ##
##   / /_/ /  / __ \   / __ \   / _ \   / / / /  / /_/ /  / __ \   / __/  / __/    /_ <   / ___/   ##
##  / __  /  / /_/ /  / / / /  /  __/  / /_/ /  / ____/  / /_/ /  / /_   / /_    ___/ /  / /       ## 
## /_/ /_/   \____/  /_/ /_/   \___/   \__, /  /_/       \____/   \__/   \__/   /____/  /_/        ##
##                                    /____/                                                       ## 
#####################################################################################################                                
"""

# Menu 
MENU = r"""
[#] Welcome to HoneyPott3r! developed by 5pyd3r!!
[#] Here's the list of operations.

[!] Scans:
[1] Nmap scan
[2] Nikto scan
[3] OpenVAS scan
[4] Metasploit scan

[!] Attacks:
[1] Honeypot Detection
[2] Code Injection
[3] Data Leakage
[4] Denial of Service
[5] Evading Logs
[6] Service Crash
[7] Reverse Exploitation
[8] Privilege Escalation

[!] Commands:
[1] To Start the Scan use 'start'
[2] To run the Scan use 'scan'
[3] To reset the credentials use 'reset'
[4] To Exit use 'exit'
"""

LOGS_DIR = "logs"  # Store all logs inside this directory
os.makedirs(LOGS_DIR, exist_ok=True)  # Ensure logs directory exists

def get_timestamp():
    """Returns a timestamp string for folder naming."""
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

def user_input(prompt):
    """Handles user input with proper formatting"""
    return input(f"HoneyPott3r > {prompt}: ").strip().lower()

def run_scan(scan_module, result_dir):
    """Runs a scan and logs results"""
    scan_module.run(result_dir)

def run_attack(attack_module, result_dir):
    """Runs an attack and logs results"""
    attack_module.run(result_dir)

def main():
    print(BANNER)  # Show banner initially
    print(MENU)  # Show menu initially
    
    while True:
        command = user_input("Enter your command")

        # Start the test
        if command == "start":
            print(MENU)  # Always show menu after each scan
            
            # Take user inputs for test parameters
            test_name = user_input("Set the test name")
            honeypot_type = user_input("Set the honeypot type")
            honeypot_creds = user_input("Set the honeypot credentials")

            config_data = {
                "test_name": test_name,
                "honeypot_type": honeypot_type,
                "honeypot_creds": honeypot_creds
            }
            os.makedirs("temp", exist_ok=True)
            config_path = os.path.join("temp", "config.json")
            with open(config_path, "w") as config_file:
                json.dump(config_data, config_file, indent=4)

            # Create results directory using test_name and timestamp
            results_folder = f"results/{test_name}-{get_timestamp()}"
            os.makedirs(results_folder, exist_ok=True)

            print("\n[*] Testing initiated.....\n")
            time.sleep(2)

        # Initiating Scans
        elif command == "scan":
            print("\n[*] Running Scans and Attacks...\n")

            # Run scanning tools
            run_scan(nmap_scan,results_folder)
            run_scan(nikto_scan,results_folder)
            run_scan(metasploit_exploit,results_folder)
            run_scan(openvas_scan,results_folder)

            # Run attack modules
            attack_modules = [
                honeypot_detection, privilege_escalation, code_injection, 
                data_leakage, reverse_exploit, service_crash, dos_attack, evading_logs
            ]
            for attack in attack_modules:
                run_attack(attack, results_folder)

            print("\n[+] Testing complete!\n")
            os.rmdir("temp")

        # Reset the Credentials
        elif command == "reset":
            print("[!] Resetting credentials...")
            test_name = None
            honeypot_type = None
            honeypot_creds = None
            print("[+] Credentials have been reset.\n")

        # Exit the loop and terminate the script
        elif command == "exit":
            print("[!] Exiting HoneyPott3r...")
            break  

        else:
            print("[!] Invalid command. Please try again.")

if __name__ == "__main__":
    main()
