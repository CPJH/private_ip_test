#!/usr/bin/env python3

import yaml
import ipaddress
import os
import sys

def is_valid_yaml(line):
    try:
        yaml.safe_load(line)
        return True
    except yaml.YAMLError:
        return False

def remove_invalid_yaml_lines(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            if is_valid_yaml(line):
                outfile.write(line)

def is_private_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    return ip_obj.is_private

def analyze_yaml(yaml_data):
    private_ips = {}
    privateip_count = 0
    def analyze_data(data, path=''):
        nonlocal private_ips
        nonlocal privateip_count
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}/{key}" if path else key
                analyze_data(value, new_path)
        
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                new_path = f"{path}[{idx}]"
                analyze_data(item, new_path)

        elif isinstance(data, str):
            if is_private_ip(data):
                    private_ips[path] = data
                    privateip_count += 1
    analyze_data(yaml_data)
    return (private_ips, privateip_count)

changed_file = sys.argv[1]
orig_file = changed_file + ".master"
print(f"\nChecking for private IP Addresses in file {changed_file}\n")
updated_file = orig_file + "-updated"
remove_invalid_yaml_lines(orig_file, updated_file)
with open(updated_file, 'r') as f:
    yaml_data = yaml.safe_load(f)
private_ips, count = analyze_yaml(yaml_data)
os.remove(updated_file)
if count > 0:
    print(f"The following private IP addresses already exist in file \"{changed_file}\" in the master branch")
    for k, v in private_ips.items():
        print(f"{v} at the key path: {k}")
    print(f"\nTotal number of Private IP addresses found for this file in the master branch: {count}")
else:
    print(f"No private IP addresses exist  on the {changed_file} in the master branch")
