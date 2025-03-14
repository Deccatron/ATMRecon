**_ATMRecon_**

_01000001 01010100 01001101 01010010 01000101 01000011 01001111 01001110_

---------------------------------------------------------------------------

ATMRecon is a network scanning tool designed to help cybersecurity professionals and enthusiasts identify and assess ATM-related devices on a given subnet. By scanning for open ports and identifying services that are commonly associated with ATMs, such as HTTPS (443), ATM protocols (1025), and ATM management services (3000-3010), ATMRecon provides valuable insights into potentially vulnerable ATM machines and other related devices.

The tool performs deep scans using Nmap, targeting ATM-specific ports to find devices that may be exposed to exploitation. It checks the devices for active services, gathers banners, and even looks for known exploits related to these services via the Exploit Database.

ATMRecon is built to be fast, customizable, and user-friendly, offering features such as:

Subnet scanning: Scans a subnet to find active ATM-related devices.
Port scanning: Identifies open ports associated with ATM devices.
Service identification: Detects ATM-related services through port and banner analysis.
Exploit search: Integrates with the Exploit Database to check for known vulnerabilities related to identified services.
Customizable scan types: Choose between SYN, TCP, or UDP scanning methods.
Multithreading support: Run scans with multiple threads for faster performance.
Developed by Deccatron, ATMRecon is a powerful tool for anyone looking to identify and analyze ATM ports and services for pentest exploitational usage.

---------------------------------------------------------------------------

_**Commands**_

usage: atmrecon.py [-h] [--subnet SUBNET] [--ports PORTS] [--threads THREADS]
                   [--timeout TIMEOUT] [--verbose] [--scan_type {SYN,TCP,UDP}]

ATM Network Scanner Tool - AKA ATMRecon

optional arguments:
  -h, --help            show this help message and exit
  --subnet SUBNET       Subnet to scan (default: 192.168.1.0/24)
  --ports PORTS         Port range to scan (default: 443,1025,3000-3099)
  --threads THREADS     Number of threads (default: 20)
  --timeout TIMEOUT     Connection timeout in seconds (default: 3)
  --verbose             Enable verbose output (because who doesn’t love detailed logs?)
  --scan_type {SYN,TCP,UDP}
                        Scan type to perform (choices: SYN, TCP, UDP, default: SYN)

---------------------------------------------------------------------------

_**ATMRecon was developed solely for educational and security research purposes. DO NOT use this software for any malicious activities.**_
