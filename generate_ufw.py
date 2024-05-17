import os
import ipaddress

# Define the input and output file paths
input_files = ["as132280.txt","asn9341.txt","asn215918.txt", "asn13335.txt", "asn133798.txt", "asn23693.txt", "asn24203.txt", "asn45727.txt", "asn4761.txt", "asn7713.txt", "asn398962.txt", "asn2516.txt", "asn17676.txt", "asn4713.txt", "asn9605.txt", "asn2527.txt", "asn4788.txt", "asn9534.txt", "asn4818.txt", "asn9930.txt", "asn38466.txt", "asn9299.txt", "asn17639.txt", "asn132199.txt", "asn4775.txt", "asn10139.txt", "asn7303.txt", "asn27747.txt", "asn22927.txt", "asn11664.txt", "asn11315.txt", "asn131445.txt", "asn133481.txt", "asn45629.txt", "asn23969.txt", "asn24378.txt", "asn7552.txt", "asn45899.txt", "asn18403.txt", "asn131429.txt", "asn45543.txt", "asn9873.txt", "asn131267.txt", "asn10226.txt", "asn24337.txt", "asn132513.txt", "asn136255.txt", "asn58952.txt", "asn133385.txt", "asn9988.txt", "asn132167.txt", "asn38623.txt", "asn45498.txt", "asn131178.txt", "asn17976.txt", "asn38901.txt", "asn20940.txt"]
output_file = "ufw_rules.txt"
ip_list_file = "ip_list.txt"

# Create empty lists to store IPv4 and IPv6 networks
ipv4_networks = []
ipv6_networks = []

# Loop through the input files
for input_file in input_files:
    # Open the input file for reading
    with open(input_file, "r") as f_in:
        # Loop through the lines in the input file
        for line in f_in:
            # Trim any leading or trailing spaces
            line = line.strip()
            # Skip any comment lines
            if line.startswith("#"):
                continue
            # Parse the IP address and prefix length
            parts = line.split("/")
            if len(parts) != 2:
                continue
            ip, prefix = parts
            # Create an IPv4 or IPv6 object
            try:
                if ":" in ip:
                    network = ipaddress.IPv6Network(line, strict=False)
                    ipv6_networks.append(network)
                else:
                    network = ipaddress.IPv4Network(line, strict=False)
                    ipv4_networks.append(network)
            except ValueError:
                pass

# Combine the IPv4 and IPv6 networks
networks = ipv4_networks + ipv6_networks

# Sort the networks in ascending order by the IP address
networks.sort(key=lambda x: (x.version, x.network_address))

# Create an empty list to store the allowed networks
allowed_networks = []

# Loop through the networks
for network in networks:
    # Check if the network overlaps with any of the previously allowed networks
    overlap = False
    for allowed_network in allowed_networks:
        if network.overlaps(allowed_network):
            overlap = True
            break
    # If the network does not overlap, add it to the allowed networks
    if not overlap:
        allowed_networks.append(network)

# Open the output file for writing
with open(output_file, "w") as f_out:
    # Loop through the allowed networks
    for network in allowed_networks:
        # Check if it's an IPv4 or IPv6 address
        if network.version == 4:
            # Write the IPv4 UFW rule
            f_out.write(f"ufw allow proto tcp from {network} to any port 22,80,8080,8880,2052,2082,2086,2095,443,2053,2083,2087,2096,8443\n")
        else:
            # Write the IPv6 UFW rule
            f_out.write(f"ufw allow proto tcp from {network} to any port 22,80,8080,8880,2052,2082,2086,2095,443,2053,2083,2087,2096,8443\n")

# Open the ip list for writing
with open(ip_list_file, "w") as f_out:
    # Loop through the allowed networks
    for network in allowed_networks:
        # Check if it's an IPv4 or IPv6 address
        if network.version == 4:
            # Write the IPv4 addresses
            f_out.write(f"{network}\n")
        else:
            # Write the IPv6 addresses
            f_out.write(f"{network}\n")

# Print a message indicating the output file path
print(f"UFW rules written to {os.path.abspath(output_file)}")
print(f"Allowed Networks written to {os.path.abspath(ip_list_file)}")
