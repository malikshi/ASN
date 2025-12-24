#!/opt/venv-python/bin/python
import requests
import ipaddress
import json
import subprocess
import os
import gzip
from collections import defaultdict

# --- Configuration ---
input_file_asn = "https://raw.githubusercontent.com/IPTUNNELS/IPTUNNELS/main/firewall/ASN.txt"
input_file_geoid = "https://raw.githubusercontent.com/malikshi/geoid/main/table.list"
ip_list_file = "ip_list.txt"

# --- IPInfo Configuration ---
IPINFO_URL = "https://ipinfo.io/data/ipinfo_lite.json.gz?token=11d8ba16d9d324"
IPINFO_FILE = "ipinfo_lite.json.gz"

def update_ipinfo_database():
    """
    Downloads the latest ipinfo database.
    Falls back to local file if download fails.
    Returns True if a usable file exists, False otherwise.
    """
    print(f"Attempting to download latest DB from ipinfo...")
    try:
        # Stream download to avoid high memory usage during download
        # Uses verify=True for security, can be set to False if env has cert issues
        response = requests.get(IPINFO_URL, stream=True, timeout=60)
        
        if response.status_code == 200:
            with open(IPINFO_FILE, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("Download successful. Updated local database.")
            return True
        else:
            print(f"Download failed with status code: {response.status_code}")
    except Exception as e:
        print(f"Download failed due to error: {e}")

    # Fallback check
    if os.path.exists(IPINFO_FILE):
        print("Using existing local database.")
        return True
    else:
        print("Critical Error: No local database found and download failed.")
        return False

def load_ipinfo_database():
    """
    Parses the compressed newline-delimited JSON file.
    Returns a dictionary mapping ASN (string, no 'AS' prefix) to {'ipv4': set(), 'ipv6': set()}
    """
    print("Loading and parsing ipinfo database into memory...")
    data_map = defaultdict(lambda: {'ipv4': set(), 'ipv6': set()})
    
    if not os.path.exists(IPINFO_FILE):
        return None

    try:
        with gzip.open(IPINFO_FILE, 'rt', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    # Sample format: {"network": "1.0.0.0/24", "asn": "AS13335", ...}
                    asn_raw = entry.get('asn', '')
                    network_str = entry.get('network', '')
                    
                    if asn_raw and network_str:
                        # Strip 'AS' prefix to match ASN.txt format (usually numbers like '13335')
                        asn = asn_raw.upper().replace('AS', '')
                        
                        try:
                            network = ipaddress.ip_network(network_str, strict=False)
                            if network.version == 4:
                                data_map[asn]['ipv4'].add(network)
                            else:
                                data_map[asn]['ipv6'].add(network)
                        except ValueError:
                            # Invalid network string, skip
                            continue
                            
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error reading database file: {e}")
        return None
        
    print(f"Database loaded. Found entries for {len(data_map)} ASNs.")
    return data_map

def fetch_and_process_prefixes_geoid(asn):
    try:
        # Download table.list if it doesn't exist
        if not os.path.exists('table.list'):
            response = requests.get(input_file_geoid)
            response.raise_for_status()
            with open('table.list', 'w') as f:
                f.write(response.text)

        result = subprocess.run(
            ['grep', '-w', asn, 'table.list'],
            capture_output=True,
            text=True,
            check=True
        )
        prefixes = [line.split()[0].strip() for line in result.stdout.splitlines()]
    except (requests.exceptions.RequestException, subprocess.CalledProcessError) as e:
        print(f"Error fetching prefixes for ASN {asn} from geoid: {e}")
        return set(), set()

    ipv4_prefixes = set()
    ipv6_prefixes = set()
    for prefix in prefixes:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            if network.version == 4:
                ipv4_prefixes.add(network)
            elif network.version == 6:
                ipv6_prefixes.add(network)
        except ValueError:
            print(f"Error: Invalid network: {prefix}")

    return ipv4_prefixes, ipv6_prefixes

def filter_unique_prefixes(prefixes, existing_prefixes):
    unique = set()
    for prefix in prefixes:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            if network.num_addresses > 1:
                unique.add(network)  # Add the ip_network object
                existing_prefixes.add(network)
            else:
                print(f"Warning: Skipping invalid or single-address prefix: {prefix}")

        except ValueError:
            print(f"Error: Invalid network: {prefix}")
            continue

    return unique

def merge_and_filter_duplicates(all_prefixes, new_prefixes):
    for new_prefix in new_prefixes:
        overlaps_existing = any(new_prefix.overlaps(existing) for existing in all_prefixes)
        if not overlaps_existing:
            all_prefixes.add(new_prefix)
        elif overlaps_existing:
            for existing_prefix in all_prefixes.copy():  # Iterate over a copy to avoid modifying the set while iterating
                if new_prefix.overlaps(existing_prefix):
                    if new_prefix.prefixlen < existing_prefix.prefixlen:  # new_prefix is more general
                        all_prefixes.remove(existing_prefix)
                        all_prefixes.add(new_prefix)

# --- Fetch and Process ASNs from the File ---
all_ipv4_prefixes = set()
all_ipv6_prefixes = set()

# 1. Prepare IPInfo Database
if update_ipinfo_database():
    ipinfo_db = load_ipinfo_database()
else:
    print("Skipping IPInfo processing due to missing database.")
    ipinfo_db = None

print("Fetching ASN list...")
response = requests.get(input_file_asn)

if response.status_code == 200:
    for line in response.text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
            
        asn = line.split('|')[0].strip()

        # --- From geoid ---
        ipv4_prefixes_geoid, ipv6_prefixes_geoid = fetch_and_process_prefixes_geoid(asn)

        # --- From ipinfo (Local DB) ---
        ipv4_prefixes_ipinfo = set()
        ipv6_prefixes_ipinfo = set()
        
        if ipinfo_db and asn in ipinfo_db:
            ipv4_prefixes_ipinfo = ipinfo_db[asn]['ipv4']
            ipv6_prefixes_ipinfo = ipinfo_db[asn]['ipv6']

        # --- Merge and deduplicate for this ASN ---
        asn_ipv4_prefixes = set()
        asn_ipv6_prefixes = set()
        
        # Merge Geoid
        merge_and_filter_duplicates(asn_ipv4_prefixes, ipv4_prefixes_geoid)
        merge_and_filter_duplicates(asn_ipv6_prefixes, ipv6_prefixes_geoid)
        
        # Merge IPInfo
        merge_and_filter_duplicates(asn_ipv4_prefixes, ipv4_prefixes_ipinfo)
        merge_and_filter_duplicates(asn_ipv6_prefixes, ipv6_prefixes_ipinfo)

        # --- Write to individual ASN files ---
        with open(f"asn{asn}.txt", 'w') as f_out:
            f_out.write(f"# IPv4 prefixes for ASN {asn}\n")
            f_out.writelines(f"{prefix}\n" for prefix in sorted(asn_ipv4_prefixes, key=lambda x: x.network_address))
            f_out.write("\n")
            f_out.write(f"# IPv6 prefixes for ASN {asn}\n")
            f_out.writelines(f"{prefix}\n" for prefix in sorted(asn_ipv6_prefixes, key=lambda x: x.network_address))

        # --- Merge into the overall sets ---
        merge_and_filter_duplicates(all_ipv4_prefixes, asn_ipv4_prefixes)
        merge_and_filter_duplicates(all_ipv6_prefixes, asn_ipv6_prefixes)
else:
    print("Error fetching the ASN list file.")

# --- Create ip_list.txt ---
with open(ip_list_file, "w") as f_out:
    f_out.writelines(f"{network}\n" for network in sorted(all_ipv4_prefixes, key=lambda x: x.network_address))
    f_out.writelines(f"{network}\n" for network in sorted(all_ipv6_prefixes, key=lambda x: x.network_address))

print(f"Prefixes written to {ip_list_file}")