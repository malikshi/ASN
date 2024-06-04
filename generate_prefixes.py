#!/usr/bin/env python3
import requests
import ipaddress
import json

input_files = ["asn55674.txt","asn37020.txt", "asn37447.txt", "asn37453.txt", "asn327738.txt", "asn328442.txt", "asn17670.txt", "asn18004.txt", "asn132280.txt", "asn9341.txt", "asn215918.txt", "asn133798.txt", "asn23693.txt", "asn24203.txt", "asn45727.txt", "asn4761.txt", "asn7713.txt", "asn398962.txt", "asn2516.txt", "asn17676.txt", "asn4713.txt", "asn9605.txt", "asn2527.txt", "asn4788.txt", "asn9534.txt", "asn4818.txt", "asn9930.txt", "asn38466.txt", "asn9299.txt", "asn17639.txt", "asn132199.txt", "asn4775.txt", "asn10139.txt", "asn7303.txt", "asn27747.txt", "asn22927.txt", "asn11664.txt", "asn11315.txt", "asn131445.txt", "asn133481.txt", "asn45629.txt", "asn23969.txt", "asn24378.txt", "asn7552.txt", "asn45899.txt", "asn18403.txt", "asn131429.txt", "asn45543.txt", "asn9873.txt", "asn131267.txt", "asn10226.txt", "asn24337.txt", "asn132513.txt", "asn136255.txt", "asn58952.txt", "asn133385.txt", "asn9988.txt", "asn132167.txt", "asn38623.txt", "asn45498.txt", "asn131178.txt", "asn17976.txt", "asn38901.txt", "asn20940.txt"]
ip_list_file = "ip_list.txt"  # Output file for combined prefixes

def fetch_and_process_prefixes(asn):
    url = f'https://api.bgpview.io/asn/{asn}/prefixes'
    response = requests.get(url)

    try:
        data = response.json()['data']
    except (KeyError, json.JSONDecodeError):  # Handle missing data or invalid JSON
        print(f"Error: Issue fetching or parsing data for ASN {asn}")
        return set(), set()  # Return empty sets

    parent_prefixes = {
        'ipv4': set(),
        'ipv6': set()
    }

    for ip_version in parent_prefixes:
        for prefix in data[f'{ip_version}_prefixes']:
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
            existing_prefixes.add(network)  # Add to the master list

    return unique

# --- Prefix Generation ---
unique_ipv4_prefixes_all = []
unique_ipv6_prefixes_all = []

for input_file in input_files:
    asn = input_file[3:-4]
    ipv4_prefixes, ipv6_prefixes = fetch_and_process_prefixes(asn)
    unique_ipv4_prefixes = filter_unique_prefixes(ipv4_prefixes, set())
    unique_ipv6_prefixes = filter_unique_prefixes(ipv6_prefixes, set())

    # Write to individual ASN files
    with open(input_file, 'w') as f:
        f.write(f"# IPv4 prefixes for ASN {asn}\n")
        f.writelines(prefix + '\n' for prefix in unique_ipv4_prefixes)
        f.write("\n")
        f.write(f"# IPv6 prefixes for ASN {asn}\n")
        f.writelines(prefix + '\n' for prefix in unique_ipv6_prefixes)

    print(f"Prefixes written to {input_file}")

    # Append to combined lists
    unique_ipv4_prefixes_all.extend(unique_ipv4_prefixes)
    unique_ipv6_prefixes_all.extend(unique_ipv6_prefixes)

# --- Create Combined ip_list.txt ---

# Filter out overlapping IPv4 networks
filtered_ipv4 = []
for prefix in unique_ipv4_prefixes_all:
    network = ipaddress.ip_network(prefix, strict=False)
    if not any(network.subnet_of(other) for other in filtered_ipv4):
        filtered_ipv4.append(network)

# Filter out overlapping IPv6 networks
filtered_ipv6 = []
for prefix in unique_ipv6_prefixes_all:
    network = ipaddress.ip_network(prefix, strict=False)
    if not any(network.subnet_of(other) for other in filtered_ipv6):
        filtered_ipv6.append(network)

with open(ip_list_file, "w") as f_out:
    f_out.writelines(f"{network}\n" for network in sorted(filtered_ipv4, key=lambda x: x.network_address))
    f_out.writelines(f"{network}\n" for network in sorted(filtered_ipv6, key=lambda x: x.network_address))
