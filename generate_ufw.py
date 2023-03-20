import os
import ipaddress

# Define the input and output file paths
input_files = ["asn13335.txt", "asn133798.txt", "asn23693.txt", "asn24203.txt", "asn45727.txt", "asn4761.txt"]
output_file = "ufw_rules.txt"

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
            ip, prefix = line.split("/")
            # Create an IPv4 or IPv6 object
            if ":" in ip:
                network = ipaddress.IPv6Network(line, strict=False)
                ipv6_networks.append(network)
            else:
                network = ipaddress.IPv4Network(line, strict=False)
                ipv4_networks.append(network)

# Combine the IPv4 and IPv6 networks
networks = ipv4_networks + ipv6_networks

# Sort the networks in ascending order by the IP address
networks.sort(key=lambda x: x.network_address)

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
            f_out.write(f"ufw allow from {network} to any\n")
        else:
            # Write the IPv6 UFW rule
            f_out.write(f"ufw allow from {network} to any\n")

# Print a message indicating the output file path
print(f"UFW rules written to {os.path.abspath(output_file)}")
