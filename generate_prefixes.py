#!/opt/venv-python/bin/python
import requests
import ipaddress
import json
import subprocess

input_file_bgpview = "https://raw.githubusercontent.com/IPTUNNELS/IPTUNNELS/main/firewall/ASN.txt"
input_file_geoid = "https://raw.githubusercontent.com/malikshi/geoid/main/table.list"
ip_list_file = "ip_list.txt"

def fetch_and_process_prefixes_bgpview(asn):
    url = f'https://api.bgpview.io/asn/{asn}/prefixes'
    response = requests.get(url)

    try:
        data = response.json()['data']
    except (KeyError, json.JSONDecodeError):
        print(f"Error: Issue fetching or parsing data for ASN {asn}")
        return set(), set()

    parent_prefixes = {
        'ipv4': set(),
        'ipv6': set()
    }

    for ip_version in parent_prefixes:
        for prefix in data.get(f'{ip_version}_prefixes', []):
            parent = prefix.get('parent', {}).get('prefix')
            if parent:
                try:
                    network = ipaddress.ip_network(parent, strict=False)
                    parent_prefixes[ip_version].add(network)  # Add the ip_network object
                except ValueError:
                    print(f"Error: Invalid network from bgpview.io: {parent}")

    return parent_prefixes['ipv4'], parent_prefixes['ipv6']

def fetch_and_process_prefixes_geoid(asn):
    try:
        result = subprocess.run(
            ['cat', 'table.list', '|', 'grep', '-w', asn],
            capture_output=True,
            text=True,
            check=True
        )
        prefixes = [line.split()[0].strip() for line in result.stdout.splitlines()]  # Extract the first field (prefix)
    except subprocess.CalledProcessError as e:
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
            network = ipaddress.ip_network(prefix, strict=False)  # Allow host bits
            if network.num_addresses > 1:  # Check if it's a valid network (more than one address)
                unique.add(prefix)  # Add only valid networks
                existing_prefixes.add(network)  # Add to the master list
            else:
                print(f"Warning: Skipping invalid or single-address prefix: {prefix}")  # Warning message for invalid prefixes

        except ValueError:
            print(f"Error: Invalid network: {prefix}")
            continue

    return unique

def merge_and_filter_duplicates(all_prefixes, new_prefixes):
    for prefix in new_prefixes:
        if not any(prefix.overlaps(existing) for existing in all_prefixes):
            all_prefixes.add(prefix)

# --- Fetch and Process ASNs from the File ---
all_ipv4_prefixes = set()
all_ipv6_prefixes = set()

# --- From bgpview.io ---
response = requests.get(input_file_bgpview)
if response.status_code == 200:
    for line in response.text.splitlines():
        asn = line.split('|')[0].strip()
        ipv4_prefixes, ipv6_prefixes = fetch_and_process_prefixes_bgpview(asn)
        merge_and_filter_duplicates(all_ipv4_prefixes, ipv4_prefixes)
        merge_and_filter_duplicates(all_ipv6_prefixes, ipv6_prefixes)
else:
    print("Error fetching the ASN list file from bgpview.io")

# --- From geoid ---
response = requests.get(input_file_geoid)
if response.status_code == 200:
    for line in response.text.splitlines():  # Process the downloaded content
        asn = line.split('|')[0].strip()
        ipv4_prefixes, ipv6_prefixes = fetch_and_process_prefixes_geoid(asn)
        merge_and_filter_duplicates(all_ipv4_prefixes, ipv4_prefixes)
        merge_and_filter_duplicates(all_ipv6_prefixes, ipv6_prefixes)
else:
    print("Error fetching the ASN list file from geoid")

# --- Create ip_list.txt ---
with open(ip_list_file, "w") as f_out:
    f_out.writelines(f"{network}\n" for network in sorted(all_ipv4_prefixes, key=lambda x: x.network_address))
    f_out.writelines(f"{network}\n" for network in sorted(all_ipv6_prefixes, key=lambda x: x.network_address))

print(f"Prefixes written to {ip_list_file}")