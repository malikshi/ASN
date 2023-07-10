import requests
import ipaddress
import json

asns = ['23693', '24203', '4761', '45727', '13335', '133798', '7713']
all_ipv4_prefixes = set()
all_ipv6_prefixes = set()

for asn in asns:
    url = f'https://api.bgpview.io/asn/{asn}/prefixes'
    response = requests.get(url)
    try:
        data = response.json()['data']
    except json.decoder.JSONDecodeError:
        print("Error: Invalid JSON format in API response")
        continue
    parent_ipv4_prefixes = set()
    parent_ipv6_prefixes = set()

    for prefix in data['ipv4_prefixes']:
        parent = prefix.get('parent', {}).get('prefix')
        if parent:
            parent_ipv4_prefixes.add(parent)

    for prefix in data['ipv6_prefixes']:
        parent = prefix.get('parent', {}).get('prefix')
        if parent:
            parent_ipv6_prefixes.add(parent)

    unique_ipv4_prefixes = set()

    for prefix in parent_ipv4_prefixes:
        network = ipaddress.ip_network(prefix)
        overlap = False
        for existing_prefix in all_ipv4_prefixes:
            if existing_prefix.version != network.version:
                continue
            if network.subnet_of(existing_prefix):
                overlap = True
                break
        if not overlap:
            unique_ipv4_prefixes.add(prefix)
            all_ipv4_prefixes.add(network)

    unique_ipv6_prefixes = set()

    for prefix in parent_ipv6_prefixes:
        network = ipaddress.ip_network(prefix)
        overlap = False
        for existing_prefix in all_ipv6_prefixes:
            if existing_prefix.version != network.version:
                continue
            if network.subnet_of(existing_prefix):
                overlap = True
                break
        if not overlap:
            unique_ipv6_prefixes.add(prefix)
            all_ipv6_prefixes.add(network)

    with open(f'asn{asn}.txt', 'w') as f:
        f.write("# IPv4 prefixes for ASN " + asn + "\n")
        for prefix in unique_ipv4_prefixes:
            f.write(prefix + '\n')
        f.write("\n")
        f.write("# IPv6 prefixes for ASN " + asn + "\n")
        for prefix in unique_ipv6_prefixes:
            f.write(prefix + '\n')
        f.write("\n")

    print(f"Prefixes written to asn{asn}.txt file")
