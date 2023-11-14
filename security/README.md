# The python script to determine if a particular IP is up and gather information from it using `nmap` in Python with the `python-nmap` library

To use that script, you need to install the library by running:

```bash
pip install python-nmap
```

This script reads the IP addresses from the specified file as a parameter:

```bash
python nmap_ips.py ips.txt
```

That command initate checks if each IP is up and prints information about open ports if the IP is reachable.
You can adjust the scan arguments in the nm.scan line according to your needs.

---

Note that scanning hosts without proper authorization may violate terms of service, so use this script responsibly and only on hosts you are authorized to scan.
