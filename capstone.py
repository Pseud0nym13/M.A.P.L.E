import platform
import subprocess
import re
import requests
import json
import logging
from typing import List, Dict, Any

class VulnerabilityScanner:
    def __init__(self, nvd_api_key: str = None):
        #Initialize the vulnerability scanner with logging and API configuration
        # Configure logging
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # NVD API base URL
        self.NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Store API key
        self.nvd_api_key = nvd_api_key

    def get_os_details(self) -> Dict[str, str]:
        #Retrieve operating system details
        #:return: Dictionary with OS name and version
        try:
            os_name = platform.system()
            os_version = platform.release()
            
            # Additional details for different platforms
            if os_name == "Linux":
                try:
                    # Try to get more specific Linux distribution info
                    with open("/etc/os-release", "r") as f:
                        os_info = f.read()
                        match = re.search(r'PRETTY_NAME="([^"]+)"', os_info)
                        if match:
                            os_name = match.group(1)
                except FileNotFoundError:
                    pass
            elif os_name == "Windows":
                # Get more detailed Windows version
                os_version = platform.platform()
            
            return {
                "name": os_name,
                "version": os_version
            }
        except Exception as e:
            self.logger.error(f"Error retrieving OS details: {e}")
            return {"name": "Unknown", "version": "Unknown"}

    def get_installed_software_windows(self) -> List[Dict[str, str]]:
        #Retrieve installed software on Windows using PowerShell
        #return: List of dictionaries with software name and version
        software_list = []
        try:
            # Use different methods to get software
            methods = [
                # Method 1: WMI Product List
                ["powershell", "Get-WmiObject Win32_Product | Select-Object Name, Version | ConvertTo-Json"],
                # Method 2: Registry uninstall list
                ["powershell", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | ConvertTo-Json"]
            ]
            
            for cmd in methods:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)
                    
                    if result.returncode == 0:
                        try:
                            software_data = json.loads(result.stdout)
                            
                            # Handle different output formats
                            for item in software_data:
                                name = item.get('Name') or item.get('DisplayName')
                                version = item.get('Version') or item.get('DisplayVersion')
                                
                                if name and version:
                                    software_list.append({
                                        "name": name.strip(),
                                        "version": version.strip()
                                    })
                        except json.JSONDecodeError:
                            self.logger.warning(f"Could not parse JSON for method: {cmd}")
                    
                    # If we found software, break the loop
                    if software_list:
                        break
                
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Timeout occurred for command: {cmd}")
                except Exception as e:
                    self.logger.warning(f"Error with software detection method: {e}")
        
        except Exception as e:
            self.logger.error(f"Error retrieving Windows software: {e}")
        
        return software_list

    def get_installed_software_linux(self) -> List[Dict[str, str]]:
        #Retrieve installed software on Linux using package managers
        #return: List of dictionaries with software name and version
        software_list = []
        
        # Try different package managers
        package_managers = [
            # Debian/Ubuntu
            ["dpkg", "-l"],
            # Red Hat/CentOS
            ["rpm", "-qa"],
            # Arch Linux
            ["pacman", "-Q"]
        ]
        
        for manager in package_managers:
            try:
                result = subprocess.run(manager, capture_output=True, text=True, shell=False)
                if result.returncode == 0:
                    # Parse output based on package manager
                    if manager[0] == "dpkg":
                        # Debian/Ubuntu style parsing
                        for line in result.stdout.split('\n')[5:]:  # Skip header
                            parts = line.split()
                            if len(parts) >= 3:
                                software_list.append({
                                    "name": parts[1],
                                    "version": parts[2]
                                })
                    elif manager[0] == "rpm":
                        # RPM style parsing
                        for line in result.stdout.split('\n'):
                            parts = line.rsplit('-', 2)
                            if len(parts) >= 2:
                                software_list.append({
                                    "name": parts[0],
                                    "version": f"{parts[1]}-{parts[2]}"
                                })
                    elif manager[0] == "pacman":
                        # Arch Linux style parsing
                        for line in result.stdout.split('\n'):
                            parts = line.split()
                            if len(parts) == 2:
                                software_list.append({
                                    "name": parts[0],
                                    "version": parts[1]
                                })
                    break  # Stop after first successful package manager
            except Exception as e:
                self.logger.warning(f"Error with {manager[0]}: {e}")
        
        return software_list

    def get_installed_software(self) -> List[Dict[str, str]]:
        #Retrieve installed software based on operating system
        #:return: List of dictionaries with software name and version
        os_name = platform.system().lower()
        
        if os_name == "windows":
            return self.get_installed_software_windows()
        elif os_name == "linux":
            return self.get_installed_software_linux()
        else:
            self.logger.warning(f"Software detection not supported for {os_name}")
            return []

    def query_nvd_api(self, software_name: str, version: str) -> List[Dict[str, Any]]:
        #Query NVD API for vulnerabilities
        #:param software_name: Name of the software
        #:param version: Software version
        #:return: List of vulnerabilities
        if not software_name or not version:
            self.logger.warning(f"Skipping API query for invalid software: {software_name} {version}")
            return []

        try:
            # Prepare request parameters and headers
            params = {
                "keywordSearch": f"{software_name} {version}",
                "resultsPerPage": 30  # Limit results
            }
            
            # Prepare headers
            headers = {
                "User-Agent": "VulnerabilityScanner/1.0",
                "Accept": "application/json"
            }
            
            # Add API key if provided
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key
            
            # Make the API request
            response = requests.get(
                self.NVD_API_BASE_URL, 
                params=params, 
                headers=headers
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = []
            
            # Extract relevant vulnerability information
            for cve in data.get('vulnerabilities', []):
                vuln_details = {
                    "cve_id": cve.get('cve', {}).get('id', 'N/A'),
                    "description": next((desc.get('value', 'No description') 
                                         for desc in cve.get('cve', {}).get('descriptions', []) 
                                         if desc.get('lang') == 'en'), 'No description'),
                    "severity": cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'Unknown'),
                    "published_date": cve.get('publishedDate', 'N/A')
                }
                vulnerabilities.append(vuln_details)
            
            return vulnerabilities
        
        except requests.RequestException as e:
            self.logger.error(f"API request failed for {software_name} {version}: {e}")
            return []


    def scan_system_vulnerabilities(self):
        #Scan the entire system for vulnerabilities

        # Get OS details
        os_info = self.get_os_details()
        self.logger.info(f"OS Detected: {os_info['name']} {os_info['version']}")
        
        # Check OS vulnerabilities
        os_vulnerabilities = self.query_nvd_api(os_info['name'], os_info['version'])
        
        # Get installed software
        software_list = self.get_installed_software()
        self.logger.info(f"Detected {len(software_list)} software packages")
        
        # Comprehensive vulnerability report
        vulnerability_report = {
            "os": {
                "name": os_info['name'],
                "version": os_info['version'],
                "vulnerabilities": os_vulnerabilities
            },
            "software_vulnerabilities": []
        }
        
        # Check vulnerabilities for each software
        for software in software_list:
            # Ensure software dict has 'name' and 'version' keys
            if 'name' in software and 'version' in software:
                vulns = self.query_nvd_api(software['name'], software['version'])
                if vulns:
                    vulnerability_report['software_vulnerabilities'].append({
                        "name": software['name'],
                        "version": software['version'],
                        "vulnerabilities": vulns
                    })
            else:
                self.logger.warning(f"Skipping incomplete software entry: {software}")
        
        # Generate report
        self.generate_vulnerability_report(vulnerability_report)
        
        return vulnerability_report

    def generate_vulnerability_report(self, report: Dict):
        #Generate a detailed vulnerability report
        #:param report: Vulnerability report dictionary
        print("\n--- VULNERABILITY REPORT ---")
        
        # OS Vulnerabilities
        print("\nOS Vulnerabilities:")
        if report['os']['vulnerabilities']:
            for vuln in report['os']['vulnerabilities']:
                print(f"  - CVE: {vuln['cve_id']}")
                print(f"    Severity: {vuln['severity']}")
                print(f"    Description: {vuln['description']}")
                print(f"    Published: {vuln['published_date']}\n")
        else:
            print("  No known vulnerabilities found for this OS version.")
        # Software Vulnerabilities
        print("\nSoftware Vulnerabilities:")
        if report['software_vulnerabilities']:
            for sw in report['software_vulnerabilities']:
                print(f"{sw['name']} (v{sw['version']}):")
                for vuln in sw['vulnerabilities']:
                    print(f"  - CVE: {vuln['cve_id']}")
                    print(f"    Severity: {vuln['severity']}")
                    print(f"    Description: {vuln['description']}")
                    print(f"    Published: {vuln['published_date']}\n")
        else:
            print("  No vulnerabilities found for installed software.")

def main():
    api_key = "9cf83c22-7978-4c57-b8f0-f35df8e494cd"
    scanner = VulnerabilityScanner(nvd_api_key=api_key)
    scanner.scan_system_vulnerabilities()

if __name__ == "__main__":
    main()