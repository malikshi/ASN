#!/usr/bin/env python3
import requests
import ipaddress
import json
# id, dns, jp, ph, my, ar, th, vn, la, mm, kh
asns = ['23693', '24203', '4761', '45727', '13335', '133798', '7713', '398962', '2516', '17676', '4713', '9605', '2527', '4788', '9534', '4818', '9930', '38466', '9299', '17639', '132199', '4775', '10139', '7303', '27747', '22927', '11664', '11315', '131445', '133481', '45629', '23969', '24378', '7552', '45899', '18403', '131429', '45543', '9873', '131267', '10226', '24337', '132513', '136255', '58952', '133385', '9988', '132167', '38623', '45498', '131178', '17976', '38901']
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
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            print(f"Error: Invalid IPv4 network: {prefix}")
            continue

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
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            print(f"Error: Invalid IPv6 network: {prefix}")
            continue

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
