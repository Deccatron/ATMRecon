import nmap
import socket
import threading
import logging
import argparse
import time
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import requests

def parse_arguments():
    """Parse those fancy command line arguments."""
    parser = argparse.ArgumentParser(description='ATM Network Scanner Tool - AKA ATMRecon')
    parser.add_argument('--subnet', type=str, default='192.168.1.0/24',
                        help='Subnet to scan (default: 192.168.1.0/24)')
    parser.add_argument('--ports', type=str, default='443,1025,3000-3099',
                        help='Port range to scan (default: 443,1025,3000-3099)')
    parser.add_argument('--threads', type=int, default=20,
                        help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=3,
                        help='Connection timeout in seconds (default: 3)')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output (because who doesn’t love detailed logs?)')
    parser.add_argument('--scan_type', type=str, choices=['SYN', 'TCP', 'UDP'], default='SYN',
                        help='Scan type to perform (choices: SYN, TCP, UDP, default: SYN)')
    return parser.parse_args()

def configure_logging(verbose):
    """Set up logging, so you know what's going on... ykwim lol."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def parse_port_range(port_range):
    """Convert port range string into actual ports. Magic, right?"""
    ports = []
    for part in port_range.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

class ATMNetworkScanner:
    def __init__(self, subnet, ports, threads, timeout, scan_type):
        self.subnet = subnet
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.scan_type = scan_type
        self.nm = nmap.PortScanner()
        self.results = {}
        self.ip_queue = Queue()
        self.scan_start_time = None

    def scan_subnet(self):
        """Scan the subnet for active ATM devices. They're out there, trust me."""
        logging.info(f"Scanning subnet: {self.subnet} for any ATM devices... Stay tuned!")
        try:
            # Decide on the scan type - we’re classy like that
            scan_type_flag = self.get_scan_type_flag()
            
            # Run the nmap scan and hope for the best
            self.nm.scan(hosts=self.subnet, arguments=scan_type_flag + ' -T4 --min-rate=1000')
            
            # Put all potential ATM hosts into the queue
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    for port in self.ports:
                        if port in self.nm[host].all_tcp():
                            self.ip_queue.put(host)
                            logging.debug(f"Potential ATM device spotted: {host} on port {port}")
            
            logging.info(f"Found {self.ip_queue.qsize()} possible ATM devices!")
            return True
        except Exception as e:
            logging.error(f"Oops, something went wrong while scanning the subnet: {str(e)}")
            return False

    def get_scan_type_flag(self):
        """Choose the right scan type, so you can be stealthy and shit"""
        if self.scan_type == 'SYN':
            return '-sS'  # SYN scan (because stealth is cool)
        elif self.scan_type == 'TCP':
            return '-sT'  # TCP connect scan (for the brave hearts)
        elif self.scan_type == 'UDP':
            return '-sU'  # UDP scan (for when you're feeling wild)
        return '-sS'  # Default to SYN scan, because why not?

    def check_service(self, ip, port):
        """Check if an ATM-related service is running. Time to say hello!"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port is open, let's see if we can chat with it
                try:
                    sock.send(b'GET / HTTP/1.1\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except (socket.timeout, ConnectionRefusedError):
                    banner = "No banner available, but it’s still alive!"
                
                # Log results
                if ip not in self.results:
                    self.results[ip] = {}
                
                service_name = self.identify_service(port, banner)
                self.results[ip][port] = {
                    'banner': banner,
                    'service': service_name
                }
                logging.info(f"ATM service found on {ip}:{port} - Service: {service_name}")
                
                # Look for known exploits, because we’re not just scanning, we’re hunting!
                exploits = self.search_exploit_db(service_name, port)
                if exploits:
                    self.results[ip][port]['exploits'] = exploits
                    for exploit in exploits:
                        logging.info(f"Found exploit: {exploit}")
            
            sock.close()
        except socket.error as e:
            logging.debug(f"Error checking {ip}:{port} - {str(e)}")
        except Exception as e:
            logging.error(f"Unexpected error checking {ip}:{port} - {str(e)}")

    def identify_service(self, port, banner):
        """Identify the ATM-related service. If you’re lucky, it’ll say ‘ATM’ in big letters."""
        atm_ports = {
            443: 'HTTPS',
            1025: 'ATM Protocol',
            3000: 'ATM Management Service',
            3010: 'Card Reader',
            4000: 'ATM Network Protocol',
        }
        
        if port in atm_ports:
            return atm_ports[port]
        
        banner_lower = banner.lower()
        if 'atm' in banner_lower:
            return 'ATM Service'
        elif 'card reader' in banner_lower:
            return 'Card Reader'
        elif 'payment' in banner_lower:
            return 'Payment Service'
        
        return 'Unknown ATM Service'

    def search_exploit_db(self, service_name, port):
        """Look for exploits in the Exploit DB | AND NOT EXPLOIT THEM BECAUSE THAT IS ILLEGAL ;)"""
        base_url = 'https://www.exploit-db.com/'
        search_url = f'{base_url}search?q={service_name}+{port}'
        
        try:
            response = requests.get(search_url)
            if response.status_code == 200:
                found_exploits = []
                if 'No results found' not in response.text:
                    found_exploits.append(f"Exploit(s) found for {service_name} on port {port}.")
                return found_exploits
            else:
                logging.error(f"Failed to fetch exploits. HTTP status: {response.status_code}")
                return []
        except requests.RequestException as e:
            logging.error(f"Error searching Exploit DB: {e}")
            return []

    def scan_host(self, ip):
        """Scan one host for open ATM ports. One host at a time... one ATM at a time."""
        logging.debug(f"Scanning ATM host: {ip}")
        for port in self.ports:
            self.check_service(ip, port)

    def scan_all_hosts(self):
        """Scan all hosts like a boss. Multithreading for the win."""
        host_list = []
        while not self.ip_queue.empty():
            host_list.append(self.ip_queue.get())
        
        logging.info(f"Scanning {len(host_list)} ATM devices across {len(self.ports)} ports with {self.threads} threads...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_host, host_list)

    def display_results(self):
        """Show the results. Time to flaunt our findings!"""
        logging.info("\n" + "="*50)
        logging.info("ATM SCAN RESULTS (AKA WHAT WE FOUND)")
        logging.info("="*50)
        
        if not self.results:
            logging.info("No ATM-related open ports found. Oops!")
            return
        
        for ip, services in self.results.items():
            logging.info(f"\nATM Host: {ip}")
            logging.info("-"*40)
            
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                logging.info(f"Hostname: {hostname}")
            except socket.herror:
                logging.info("Hostname: Unknown")
            
            if services:
                logging.info("Open ATM-related ports:")
                for port, details in sorted(services.items()):
                    logging.info(f"  {port}/tcp - {details['service']}")
                    if details['banner'] and details['banner'] != "No banner available":
                        banner_preview = details['banner'].split('\n')[0][:50]
                        logging.info(f"    Banner: {banner_preview}...")
                    if 'exploits' in details:
                        for exploit in details['exploits']:
                            logging.info(f"    Exploit: {exploit}")
            else:
                logging.info("No ATM-related open ports found.")
        
        if self.scan_start_time:
            duration = time.time() - self.scan_start_time
            logging.info(f"\nScan completed in {duration:.2f} seconds")

    def run(self):
        """Run the entire scanning process. It’s showtime!"""
        self.scan_start_time = time.time()
        
        if self.scan_subnet():
            self.scan_all_hosts()
            self.display_results()
        else:
            logging.error("Failed to scan the subnet. Please check your network connection and try again.")

def main():
    """Main function to run the ATMRecon tool."""
    args = parse_arguments()
    configure_logging(args.verbose)
    
    ports = parse_port_range(args.ports)
    
    scanner = ATMNetworkScanner(
        subnet=args.subnet,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        scan_type=args.scan_type
    )
    
    try:
        scanner.run()
    except KeyboardInterrupt:
        logging.info("\nScan interrupted by user. Exiting...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    logging.info("\n\nDeveloped by Deccatron | For Strictly Educational Use")
    main()
