#!/opt/venv-python/bin/python
import requests
import ipaddress
import json
import subprocess
import os

input_file_asn = "https://raw.githubusercontent.com/IPTUNNELS/IPTUNNELS/main/firewall/ASN.txt"
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

    prefixes = {
        'ipv4': set(),
        'ipv6': set()
    }

    for ip_version in prefixes:
        for prefix_data in data.get(f'{ip_version}_prefixes', []):
            # prefix_str = prefix_data.get('parent', {}).get('prefix') # this for get parent prefix
            prefix_str = prefix_data.get('prefix') # this for prefix instead of parent prefix
            if prefix_str:
                try:
                    network = ipaddress.ip_network(prefix_str, strict=False)
                    prefixes[ip_version].add(network)  # Add the ip_network object
                except ValueError:
                    print(f"Error: Invalid network from bgpview.io: {prefix_str}")

    return prefixes['ipv4'], prefixes['ipv6']

    # for ip_version in parent_prefixes:
    #     for prefix in data.get(f'{ip_version}_prefixes', []):
    #         # parent = prefix.get('parent', {}).get('prefix')
    #         parent = prefix.get('prefix')
    #         if parent:
    #             try:
    #                 network = ipaddress.ip_network(parent, strict=False)
    #                 parent_prefixes[ip_version].add(network)  # Add the ip_network object
    #             except ValueError:
    #                 print(f"Error: Invalid network from bgpview.io: {parent}")

    # return parent_prefixes['ipv4'], parent_prefixes['ipv6']

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

response = requests.get(input_file_asn)
if response.status_code == 200:
    for line in response.text.splitlines():
        asn = line.split('|')[0].strip()

        # --- From geoid ---
        ipv4_prefixes_geoid, ipv6_prefixes_geoid = fetch_and_process_prefixes_geoid(asn)

        # --- From bgpview.io ---
        ipv4_prefixes_bgpview, ipv6_prefixes_bgpview = fetch_and_process_prefixes_bgpview(asn)

        # --- Merge and deduplicate for this ASN ---
        asn_ipv4_prefixes = set()
        asn_ipv6_prefixes = set()
        merge_and_filter_duplicates(asn_ipv4_prefixes, ipv4_prefixes_geoid)
        merge_and_filter_duplicates(asn_ipv4_prefixes, ipv4_prefixes_bgpview)
        merge_and_filter_duplicates(asn_ipv6_prefixes, ipv6_prefixes_geoid)
        merge_and_filter_duplicates(asn_ipv6_prefixes, ipv6_prefixes_bgpview)

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