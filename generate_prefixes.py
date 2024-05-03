#!/usr/bin/env python3
import requests
import ipaddress
import json

input_files = ["asn9341.txt","asn215918.txt", "asn133798.txt", "asn23693.txt", "asn24203.txt", "asn45727.txt", "asn4761.txt", "asn7713.txt", "asn398962.txt", "asn2516.txt", "asn17676.txt", "asn4713.txt", "asn9605.txt", "asn2527.txt", "asn4788.txt", "asn9534.txt", "asn4818.txt", "asn9930.txt", "asn38466.txt", "asn9299.txt", "asn17639.txt", "asn132199.txt", "asn4775.txt", "asn10139.txt", "asn7303.txt", "asn27747.txt", "asn22927.txt", "asn11664.txt", "asn11315.txt", "asn131445.txt", "asn133481.txt", "asn45629.txt", "asn23969.txt", "asn24378.txt", "asn7552.txt", "asn45899.txt", "asn18403.txt", "asn131429.txt", "asn45543.txt", "asn9873.txt", "asn131267.txt", "asn10226.txt", "asn24337.txt", "asn132513.txt", "asn136255.txt", "asn58952.txt", "asn133385.txt", "asn9988.txt", "asn132167.txt", "asn38623.txt", "asn45498.txt", "asn131178.txt", "asn17976.txt", "asn38901.txt", "asn20940.txt"]

all_ipv4_prefixes = set()
all_ipv6_prefixes = set()

for input_file in input_files:
    asn = input_file[3:-4]
    url = f'https://api.bgpview.io/asn/{asn}/prefixes'
    response = requests.get(url)
    try:
        data = response.json()['data']
    except json.decoder.JSONDecodeError:
        print(f"Error: Invalid JSON format in API response for ASN {asn}")
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

    with open(input_file, 'w') as f:
        f.write("# IPv4 prefixes for ASN " + asn + "\n")
        for prefix in unique_ipv4_prefixes:
            f.write(prefix + '\n')
        f.write("\n")
        f.write("# IPv6 prefixes for ASN " + asn + "\n")
        for prefix in unique_ipv6_prefixes:
            f.write(prefix + '\n')
        f.write("\n")

    print(f"Prefixes written to {input_file} file")
