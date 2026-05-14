import os
import sys
import paramiko
from netmiko import ConnectHandler
import argparse
import time
from time import sleep
import re
import openpyxl
import csv 
from sys import exit
from utils_gfiber import *

def extract_interf_descriptions(output):
    # Sample list of output lines.
    # output = [
    #     "ae2             up    up   [R=TWITCH][S=ACTIVE][U=PEER][T=PF46489]",
    #     "ae3             up    up   [R=TWITCH][S=ACTIVE][U=PEER][T=PF46489]",
    #     "ae12            up    up   [R=EDGIO/EDGECAST][S=ACTIVE][U=PEER][T=PF15133]",
    #     "ae14            up    up   [R=EDGIO/EDGECAST][S=ACTIVE][U=PEER][T=PF15133]",
    #     "ae22            up    up   [R=RIOTGAMES][S=ACTIVE][U=PEER][T=PF6507]",
    #     "ae23            up    up   [R=GOOGLE][S=ACTIVE][U=PEER][T=PF15169]"
    # ]

    # Regular expression to capture the interface name at the beginning of the line.
    #interface_pattern = re.compile(r'^(ae\d+)', re.IGNORECASE)
    interface_pattern = re.compile(r'^(ae\d+(?:\.\d+)?)', re.IGNORECASE)

    # Regular expression to capture the content inside square brackets.
    bracket_pattern = re.compile(r'\[([^\]]+)\]')

    # Dictionary to store the results.
    interfaces_info = {}

    # Loop through each line in the output.
    for line in output:
        # Extract the interface name.
        interface_match = interface_pattern.match(line)
        if interface_match:
            interface_name = interface_match.group(1)
        else:
            continue  # Skip the line if no interface name is found.
        
        # Extract all content inside square brackets.
        bracket_contents = bracket_pattern.findall(line)
        
        # Parse each bracket content into key-value pairs.
        info_dict = {}
        for content in bracket_contents:
            # Expecting content in the form "Key=Value"
            if '=' in content:
                key, value = content.split('=', 1)
                info_dict[key] = value
        # Save the parsed information into the result dictionary.
        interfaces_info[interface_name] = info_dict

    # Print the resulting dictionary.
    # print("Extracted interface information:")
    # for iface, info in interfaces_info.items():
    #     print(f"{iface}: {info}")
    return interfaces_info


def parse_isis_adj(output):
    adjacency_list = []
    for line in output[1:]:
        # Split line into fields using default whitespace splitting
        if "Warning: License key missing" in line:
            continue
        elif line == "":
            continue
        fields = line.split()
        #print(fields)

        # Assign fields to variables for clarity
        interface = fields[0]
        system = fields[1]
        l = fields[2]
        state = fields[3]
        hold_secs = fields[4]

        # Create a dictionary for each adjacency entry
        adjacency_entry = {
            "Interface": interface,
            "System": system,
            "L": l,
            "State": state,
            "Hold (secs)": hold_secs,
        }

        # Append the dictionary to the list
        adjacency_list.append(adjacency_entry)

        # Output the parsed data structure
    #print(adjacency_list)
    return adjacency_list