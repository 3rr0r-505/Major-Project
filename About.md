# HoneyPott3r - Python Honeypot Vulnerability Scanner Project
**HoneyPott3r** is a tool designed to identify and analyze vulnerabilities in popular honeypot frameworks. It leverages integrated Kali Linux tools and custom attack vectors to simulate real-world threats, enabling researchers and security teams to test the resilience of their honeypots effectively.

---

## Project File Structure
Here's an overview of the main project directory and its structure:
```
HoneyPott3r/src/  
│  
├── main.py                     # Main entry point for the tool   
│  
├── tools/                      # External tools & scripts  
│   ├── scanners.py             # Script for Nmap, Nikto, and WPScan vulnerability scanning  
│   └── msf_scan.py             # Script to find Metasploit modules related to vulnerabilities  
│  
├── modules/                    # Core attack modules  
│   ├── honeypot_detection.py   # Honeypot fingerprinting techniques  
│   ├── code_injection.py       # Code injection attack methods  
│   ├── data_leakage.py         # Exploitation techniques for data leakage  
│   ├── privilege_escalation.py # Techniques for privilege escalation  
│   ├── reverse_exploitation.py # Methods to exploit honeypots in reverse  
│   ├── dos_attack.py           # DoS attack simulation methods  
│   └── evading_logs.py         # Techniques for log evasion  
│  
├── config/                     # Configuration files for tools and modules  
│   ├── honeypots.yaml          # Repository links for known honeypots  
│   ├── injection-cmd.yaml      # Code injection commands & expected responses  
│   ├── leakage-cmd.yaml        # Data leakage commands & expected responses  
│   └── signatures.yaml         # Signatures to detect honeypots  
│  
├── dashboard/                  # Web-based dashboard for viewing scan reports  
│   ├── dashboard.py            # Flask script to run the dashboard server  
│   └── templates/              # HTML templates for rendering dashboard pages  
│       ├── index.html          # Template for listing all scan reports  
│       ├── dashboard.html      # Template for displaying a summary view of a report  
│       └── report.html         # Template for viewing the complete details of a report  
│  
└── utils/                      # Helper functions & utilities  
    ├── logger.py               # Logging functionality  
    ├── mongo_loader.py         # Script to load reports into MongoDB  
    └── config_loader.py        # Script to load configuration files  

```
---

## Project Workflow
Here’s the workflow of your tool:
```
Start Tool  
   ↓  
Initialize MongoDB and Dashboard  
   ↓  
Get User Input (Target IP/Range)  
   ↓  
Simulate Attacks  
   ├── Honeypot Detection → Identify and analyze honeypot behavior  
   ├── Code Injection → Execute payloads and analyze responses/logs  
   ├── Data Leakage → Detect unintended data exposure  
   ├── Log Evasion → Check if logs are manipulated or bypassed  
   ├── Privilege Escalation → Test system response to privilege exploits  
   ├── Reverse Exploitation → Exploit weaknesses in honeypots  
   └── DoS/Service Crash → Observe honeypot resilience to denial-of-service attacks  
   ↓  
Simulate Scanning  
   ├── Nmap Scan → Scan the network for honeypots  
   ├── Nikto Scan → Check HTTP endpoints for web-based honeypots  
   ├── WPScan → Identify vulnerabilities in WordPress honeypots  
   └── MSF Scan → Find Metasploit modules for discovered CVEs  
   ↓  
Generate Report & Real-time Logs  
   ↓  
Store Report and Logs in MongoDB (localhost)  
   ↓  
View Report in Dashboard  
   ↓  
Exit Tool  
```
---

## Supported Honeypots and Protocols
Here’s the list of honeypots for testing this project:

| **Honeypot**  | **Supported Protocols**            | **Purpose**                                                                | **Repository**                                            |
|---------------|------------------------------------|----------------------------------------------------------------------------|-----------------------------------------------------------|
| **Cowrie**    | SSH                                | Emulates SSH/Telnet to capture brute force attacks.                        | [GitHub Link](https://github.com/cowrie/cowrie)           |
| **Conpot**    | HTTP                               | Emulates SCADA/ICS systems for industrial protocols.                       | [GitHub Link](https://github.com/mushorg/conpot)          |
| **Wordpot**   | HTTP (WordPress)                   | Emulates WordPress installations for CMS-specific attacks.                 | [GitHub Link](https://github.com/gbrindisi/wordpot)       |


<!-- | **Kippo**     | SSH                                | Simulates a medium-interaction SSH server for attack logging and analysis. | [GitHub Link](https://github.com/desaster/kippo)          |
| **Glastopf**  | HTTP                               | Emulates vulnerable web servers to capture attack patterns.                | [GitHub Link](https://github.com/mushorg/glastopf)        |
| **Dionaea**   | SMB, HTTP, FTP, TFTP, MSSQL, MySQL | Catches malware and collects samples for analysis.                         | [GitHub Link](https://github.com/DinoTools/dionaea)       |
| **Conpot**    | Modbus, SNMP, BACnet, HTTP, FTP    | Emulates SCADA/ICS systems for industrial protocols.                       | [GitHub Link](https://github.com/mushorg/conpot)          |
| **Wordpot**   | HTTP (WordPress)                   | Emulates WordPress installations for CMS-specific attacks.                 | [GitHub Link](https://github.com/gbrindisi/wordpot)       |
| **T-Pot**     | Multi (Cowrie, Dionaea, etc.)      | Multi-honeypot platform for various protocols.                             | [GitHub Link](https://github.com/telekom-security/tpotce) |
| **Honeyd**    | TCP, UDP, ICMP                     | Simulates multiple hosts and services on a network.                        | [GitHub Link](https://github.com/DataSoft/Honeyd)         |-->
---

## Project Features
Here’s the list of features for this project:

| **Category**              | **Feature**                     | **Description**                                                                                     |
|---------------------------|---------------------------------|-----------------------------------------------------------------------------------------------------|
| **Detection**             | Honeypot Detection              | Identifies and fingerprints honeypots deployed in the network.                                      |
| **Scanning**              | Vulnerability Scanning          | Integrates tools like Nmap, Nikto, WPscan, and Metasploit to find vulnerabilities.                  |
| **Exploitation**          |                                 |                                                                                                     |
|   1                       | Code Injection Attacks          | Simulates injection attacks (e.g., SQL, Command) to evaluate honeypot defenses.                     |
|   2                       | Data Leakage Exploitation       | Attempts to extract sensitive information stored in the honeypot.                                   |
|   3                       | Reverse Exploitation            | Uses the honeypot’s own vulnerabilities to launch counterattacks.                                   |
|   4                       | Privilege Escalation            | Tests for vulnerabilities that allow unauthorized access to higher privilege levels.                |
| **Stealth**               | Log Evasion Techniques          | Implements methods to bypass or manipulate honeypot logging mechanisms.                             |
| **Simulation**            | DoS Attack Simulation           | Simulates denial-of-service attacks to test the resilience of the honeypot.                         |
| **Configuration**         | Customizable Configurations     | Allows easy configuration of scan settings and attack parameters using YAML files.                  |
| **Reporting**             | Integrated Reporting            | Logs results of scans, exploits, and generates a detailed final report for analysis.                |
| **Storage**               | MongoDB Localhost Storage	      | Stores scan reports and logs in a MongoDB database for future reference.                            |
| **Visualization**	        | Web UI Dashboard	              | Provides a Flask-based web dashboard to view scan reports and analysis in real time.                |
| **Tool Integration**      | Multi-Tool Integration          | Seamlessly integrates external tools like Nmap, Metasploit, Nikto, and WPscan for enhanced testing. |
| **Usability**             |                                 |                                                                                                     |
|   1                       | User-Friendly Interface         | Centralized `main.py` script to manage all operations with a simple CLI or menu interface.          |
|   2                       | Modular Design                  | Organized file structure for easy scalability and maintenance.                                      |

---
