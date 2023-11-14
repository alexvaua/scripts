import sys

import nmap


def scan_ip(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-Pn -sV")

    if ip in nm.all_hosts():
        print(f"IP: {ip} is up")
        for proto in nm[ip].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[ip][proto].keys()
            for port in ports:
                print(
                    f"Port {port}: {nm[ip][proto][port]['product']} {nm[ip][proto][port]['version']}"
                )
    else:
        print(f"IP: {ip} is down or not responding")


def scan_ips_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            ips = [line.strip() for line in file]
            for ip in ips:
                scan_ip(ip)
    except FileNotFoundError as e:
        print(f"Error: {e.filename} not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    scan_ips_from_file(file_path)
