#!/usr/bin/env python3
import requests
import ipaddress
import json

input_file = "https://raw.githubusercontent.com/IPTUNNELS/IPTUNNELS/main/firewall/ASN.txt"  
ip_list_file = "ip_list.txt"

def fetch_and_process_prefixes(asn):
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
        for prefix in data.get(f'{ip_version}_prefixes', []):  # Handle missing prefixes
            parent = prefix.get('parent', {}).get('prefix')
            if parent:
                parent_prefixes[ip_version].add(parent)

    return parent_prefixes['ipv4'], parent_prefixes['ipv6']


def filter_unique_prefixes(prefixes, existing_prefixes):
    unique = set()
    for prefix in prefixes:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            print(f"Error: Invalid network: {prefix}")
            continue

        if not any(network.subnet_of(existing) for existing in existing_prefixes if existing.version == network.version):
            unique.add(prefix)
            existing_prefixes.add(network)  

    return unique

# --- Fetch and Process ASNs from the File ---
all_ipv4_prefixes = set()
all_ipv6_prefixes = set()

response = requests.get(input_file)
if response.status_code == 200:
    for line in response.text.splitlines():
        asn = line.split('|')[0].strip()  # Extract ASN from line
        ipv4_prefixes, ipv6_prefixes = fetch_and_process_prefixes(asn)

        # Write to individual ASN files
        with open(f"asn{asn}.txt", 'w') as f:
            f.write(f"# IPv4 prefixes for ASN {asn}\n")
            f.writelines(prefix + '\n' for prefix in ipv4_prefixes)
            f.write("\n")
            f.write(f"# IPv6 prefixes for ASN {asn}\n")
            f.writelines(prefix + '\n' for prefix in ipv6_prefixes)

        all_ipv4_prefixes.update(filter_unique_prefixes(ipv4_prefixes, all_ipv4_prefixes))
        all_ipv6_prefixes.update(filter_unique_prefixes(ipv6_prefixes, all_ipv6_prefixes))

    # --- Create ip_list.txt ---
    with open(ip_list_file, "w") as f_out:
        f_out.writelines(f"{network}\n" for network in sorted(all_ipv4_prefixes, key=lambda x: x.network_address))
        f_out.writelines(f"{network}\n" for network in sorted(all_ipv6_prefixes, key=lambda x: x.network_address))

    print(f"Prefixes written to {ip_list_file}")
else:
    print("Error fetching the ASN list file.")
