#!/opt/venv-python/bin/python
import requests
import ipaddress
import json
import subprocess
import os
import gzip
from collections import defaultdict
import shutil

# --- Configuration ---
SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/IPTUNNELS/IPTUNNELS/main/firewall/ASN.txt",
        "name": "default",
        "need_aggregate": True
    },
    {
        "url": "https://raw.githubusercontent.com/IPTUNNELS/IPTUNNELS/main/firewall/ASN-CDN-ACCESS.txt",
        "name": "addons",
        "need_aggregate": False
    }
]

input_file_geoid = "https://raw.githubusercontent.com/malikshi/geoid/refs/heads/data/table.txt"
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")
IPINFO_URL = f"https://ipinfo.io/data/ipinfo_lite.json.gz?token={IPINFO_TOKEN}"
IPINFO_FILE = "ipinfo_lite.json.gz"
BUILD_DIR = "build"

def update_ipinfo_database():
    print(f"Attempting to download latest DB from ipinfo...")
    try:
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

    if os.path.exists(IPINFO_FILE):
        print("Using existing local database.")
        return True
    else:
        print("Critical Error: No local database found and download failed.")
        return False

def load_ipinfo_database():
    print("Loading and parsing ipinfo database into memory...")
    data_map = defaultdict(lambda: {'ipv4': set(), 'ipv6': set()})
    
    if not os.path.exists(IPINFO_FILE):
        return None

    try:
        with gzip.open(IPINFO_FILE, 'rt', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    asn_raw = entry.get('asn', '')
                    network_str = entry.get('network', '')
                    
                    if asn_raw and network_str:
                        asn = asn_raw.upper().replace('AS', '')
                        try:
                            network = ipaddress.ip_network(network_str, strict=False)
                            if network.version == 4:
                                data_map[asn]['ipv4'].add(network)
                            else:
                                data_map[asn]['ipv6'].add(network)
                        except ValueError:
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
        if not os.path.exists('table.txt'):
            response = requests.get(input_file_geoid)
            response.raise_for_status()
            with open('table.txt', 'w') as f:
                f.write(response.text)

        result = subprocess.run(
            ['grep', '-w', asn, 'table.txt'],
            capture_output=True,
            text=True,
            check=False  # Ignore errors if grep finds nothing
        )
        if result.returncode == 0:
            prefixes = [line.split()[0].strip() for line in result.stdout.splitlines()]
        else:
            prefixes = []
    except (requests.exceptions.RequestException, subprocess.SubprocessError) as e:
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

def fetch_cloudflare_ips():
    print("Fetching direct Cloudflare IPs...")
    cf_ipv4 = set()
    cf_ipv6 = set()
    try:
        r4 = requests.get("https://www.cloudflare.com/ips-v4", timeout=10)
        if r4.status_code == 200:
            for line in r4.text.splitlines():
                if line.strip():
                    cf_ipv4.add(ipaddress.ip_network(line.strip(), strict=False))
        
        r6 = requests.get("https://www.cloudflare.com/ips-v6", timeout=10)
        if r6.status_code == 200:
            for line in r6.text.splitlines():
                if line.strip():
                    cf_ipv6.add(ipaddress.ip_network(line.strip(), strict=False))
    except Exception as e:
        print(f"Failed to fetch Cloudflare IPs: {e}")
    return cf_ipv4, cf_ipv6

def merge_and_filter_duplicates(all_prefixes, new_prefixes):
    for new_prefix in new_prefixes:
        overlaps_existing = False
        for existing in all_prefixes:
            if new_prefix.overlaps(existing):
                overlaps_existing = True
                break
                
        if not overlaps_existing:
            all_prefixes.add(new_prefix)
        else:
            for existing_prefix in all_prefixes.copy():
                if new_prefix.overlaps(existing_prefix):
                    if new_prefix.prefixlen < existing_prefix.prefixlen:
                        all_prefixes.remove(existing_prefix)
                        all_prefixes.add(new_prefix)

def write_formats(base_dir, name, ipv4_prefixes, ipv6_prefixes):
    all_prefixes = sorted(ipv4_prefixes, key=lambda x: x.network_address) + sorted(ipv6_prefixes, key=lambda x: x.network_address)
    all_strs = [str(p) for p in all_prefixes]
    
    if not all_strs:
        print(f"No prefixes to write for {name} in {base_dir}")
        return

    # Ensure directories exist
    os.makedirs(f"{base_dir}/text", exist_ok=True)
    os.makedirs(f"{base_dir}/nginx/allow", exist_ok=True)
    os.makedirs(f"{base_dir}/nginx/deny", exist_ok=True)
    os.makedirs(f"{base_dir}/srs", exist_ok=True)
    
    # Write text format
    with open(f"{base_dir}/text/{name}.txt", "w") as f:
        f.write("\n".join(all_strs) + "\n")
        
    # Write nginx formats
    with open(f"{base_dir}/nginx/allow/{name}.txt", "w") as f:
        f.write("\n".join([f"allow {p};" for p in all_strs]) + "\n")
        
    with open(f"{base_dir}/nginx/deny/{name}.txt", "w") as f:
        f.write("\n".join([f"deny {p};" for p in all_strs]) + "\n")
        
    # Write srs formats
    srs_json = {
        "version": 3,
        "rules": [
            {
                "ip_cidr": all_strs
            }
        ]
    }
    json_path = f"{base_dir}/srs/{name}.json"
    srs_path = f"{base_dir}/srs/{name}.srs"
    
    with open(json_path, "w") as f:
        json.dump(srs_json, f, indent=2)
        
    # Compile static srs
    try:
        subprocess.run(["sing-box", "rule-set", "compile", "--output", srs_path, json_path], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to compile SRS for {name}: {e}\nOutput: {e.stderr.decode('utf-8') if e.stderr else ''}")
    except FileNotFoundError:
        print("sing-box binary not found. Skipping SRS compilation.")

# --- Main Execution ---
if os.path.exists(BUILD_DIR):
    shutil.rmtree(BUILD_DIR)

if update_ipinfo_database():
    ipinfo_db = load_ipinfo_database()
else:
    print("Skipping IPInfo processing due to missing database.")
    ipinfo_db = None

# Pre-fetch Cloudflare IPs
cf_ipv4, cf_ipv6 = fetch_cloudflare_ips()

for source in SOURCES:
    print(f"\nProcessing source: {source['name']} ({source['url']})")
    response = requests.get(source["url"])
    if response.status_code != 200:
        print(f"Failed to fetch {source['url']}")
        continue

    base_dir = os.path.join(BUILD_DIR, source["name"])
    
    all_source_ipv4 = set()
    all_source_ipv6 = set()

    for line in response.text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
            
        asn = line.split('|')[0].strip()
        print(f"Processing ASN {asn} ...")

        # geoid
        ipv4_geoid, ipv6_geoid = fetch_and_process_prefixes_geoid(asn)

        # ipinfo
        ipv4_ipinfo = set()
        ipv6_ipinfo = set()
        if ipinfo_db and asn in ipinfo_db:
            ipv4_ipinfo = ipinfo_db[asn]['ipv4']
            ipv6_ipinfo = ipinfo_db[asn]['ipv6']

        # Merge for this ASN
        asn_ipv4 = set()
        asn_ipv6 = set()
        
        merge_and_filter_duplicates(asn_ipv4, ipv4_geoid)
        merge_and_filter_duplicates(asn_ipv6, ipv6_geoid)
        merge_and_filter_duplicates(asn_ipv4, ipv4_ipinfo)
        merge_and_filter_duplicates(asn_ipv6, ipv6_ipinfo)
        
        # Write ASN specific files
        file_basename = f"asn{asn}"
        write_formats(base_dir, file_basename, asn_ipv4, asn_ipv6)

        # Aggregate for this source if needed
        if source["need_aggregate"]:
            merge_and_filter_duplicates(all_source_ipv4, asn_ipv4)
            merge_and_filter_duplicates(all_source_ipv6, asn_ipv6)

    # Process explicit external IPs for default source
    if source["name"] == "default":
        print("Processing explicit Cloudflare IPs (ASN 13335)...")
        write_formats(base_dir, "asn13335", cf_ipv4, cf_ipv6)
        if source["need_aggregate"]:
            merge_and_filter_duplicates(all_source_ipv4, cf_ipv4)
            merge_and_filter_duplicates(all_source_ipv6, cf_ipv6)

    # Write aggregated file for this source
    if source["need_aggregate"]:
        print(f"Writing aggregated ip_list for {source['name']}...")
        write_formats(base_dir, "ip_list", all_source_ipv4, all_source_ipv6)

print("\nAll tasks completed successfully. Output located in 'build/'.")