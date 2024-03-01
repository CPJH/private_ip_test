#!/usr/bin/env python3

import ipaddress
import re
import sys

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def clean_ip_string(ip_addr):
    clean_ip_str = ip_addr.replace("'", "").replace('"', '')
    return clean_ip_str

def parse_diff_data(diff_data):
    diff_pattern = r'^@@.*\n([\s\S]*?)(?=(^@@|\Z))'
    diff_matches = re.finditer(diff_pattern, diff_data, re.MULTILINE)
    result = []
    for match in diff_matches:
        diff_lines = match.group(1).split('\n')
        diff_dict = {'-': [], '+': []}
        for line in diff_lines:
            if line.startswith('-'):
                diff_dict['-'].append(line)
            elif line.startswith('+'):
                diff_dict['+'].append(line)
        result.append(diff_dict)
    return result


diff_dict = {}
changed_file = sys.argv[1]

with open(changed_file + ".gitdiff", 'r') as file:
     gitdiff_file_contents = file.read()

diff_structures = parse_diff_data(gitdiff_file_contents)
#print(diff_structures)
for i, diff in enumerate(diff_structures, start=1):
    diffindex = "Diff" + str(i)
    diff_dict[diffindex] = {}
    diff_dict[diffindex]["-"] = diff['-']
    diff_dict[diffindex]["+"] = diff['+']


private_ip_list = []
for change_data in diff_dict.values():
    deleted = []
    added = []
    for deleted_line in change_data["-"]:
        del_ip = re.split(r'[-:]', deleted_line)[-1].strip()
        if del_ip:
            deleted.append(clean_ip_string(del_ip))
    for added_line in change_data["+"]:
        add_ip = re.split(r'[-:]', added_line)[-1].strip()
        if add_ip:
            added.append(clean_ip_string(add_ip))
    for j in added:
        if j not in deleted:
            if is_private_ip(j):
                print(f"private ip {j} detected")
                private_ip_list.append(j)

if private_ip_list:
    print(f"Following private ip addresses have been detected in file {changed_file}")
    for i in private_ip_list:
        print(i)
    print("This Pull Request is adding/updating  Private IP addresses, which could be noop !!! Please check your changes ")
    sys.exit(1)
else:
    print(f"All good with changes for file {changed_file}")
