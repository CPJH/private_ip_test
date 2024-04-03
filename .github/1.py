#!/usr/bin/env python3

'''
The logic uses an output of a git diff to extract IP addresses referenced in the yaml for each file changed in PullRequest(PR)
and also entire versions of changed files corresponding to the  master/pr branches which are expected as files with the 
appropriate suffix  of either ".gitdiff", ".pr" or ".master", i.e for changed file at path "folder/file" the code exects  
files to be present as:
"folder/changedfile.gitdiff"
"folder/changedfile.pr"
"folder/changedfile.master"
IMPORTANT: Please ensure these files  exist at the specified location before execution
whenever the script is invoked with arguments(Files Changed in PR)
Example of git diff output:
`git diff <sha-of-basebranchofpr> <sha-of-changebranchofpr> --unified=0 -- folder/changedfile`
diff --git a/folder/changedfile b/folder/changedfile --unified=0 folder/changedfile
index 5701646e8..3dfd88edd 100644
--- a/folder/changedfile.sls
+++ b/folder/changedfile.sls
@@ -34 +34 @@ abc:
-  - 'x.xx.x.xx'
+  - 'x.xxx.x.x'
@@ -2363,0 +2364 @@ xyz:
+    - xx.xx.xx.x
@@
The master version of file is/can be generated with:
git show <sha-of-basebranchofpr>:folder/changedfile > folder/changedfile.master
The pr version of the file is/can be generated with:
git show <sha-of-changebranchofpr>:folder/changedfile > folder/changedfile.pr
'''

import yaml
import ipaddress
import os
import sys
import re

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
   if "/" in ip:
       ip = ip.split("/")[0]    
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
            if line.startswith('-') and not line == '-':
                diff_dict['-'].append(line)
            elif line.startswith('+') and not line == '+':
                diff_dict['+'].append(line)
        result.append(diff_dict)
    return result

def detect_privateip_pr(filepath):
    changed_file = filepath
    diff_dict = {}
    existing_privips = scan_for_priv_ip_master(filepath)
    with open(changed_file + ".gitdiff", 'r') as file:
        gitdiff_file_contents = file.read()
    diff_structures = parse_diff_data(gitdiff_file_contents)
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
            if "#" in deleted_line:
                deleted_line = deleted_line.split("#")[0] 
            del_ip = re.split(r'[-:]', deleted_line)[-1].strip()
            if del_ip:
                deleted.append(clean_ip_string(del_ip))
        for added_line in change_data["+"]:
            if "#" in added_line:
                added_line = added_line.split("#")[0]
            add_ip = re.split(r'[-:]', added_line)[-1].strip()
            if add_ip:
                added.append(clean_ip_string(add_ip))
        for j in added:
            if j not in deleted:
                if j not in existing_privips:
                    if is_private_ip(j):
                        if j not in private_ip_list:
                            private_ip_list.append(j)
    if private_ip_list:
        privip_dict = {}
        for i in private_ip_list:
            if not check_allipsprivate_pr(i, filepath)[0]:
                 privip_dict[i] = check_allipsprivate_pr(i, filepath)[1]
    if privip_dict:
        privip_dict_section = {}
        for k, v in privip_dict.items():
            for path in v:
               if '][' in path:
                   section = path.split('][')[0].lstrip('[')
               else:
                   section = path.lstrip('[').rstrip(']')
               if section not in privip_dict_section:
                   privip_dict_section[section]= [k]
               else:
                   privip_dict_section[section].append(k)
        print(f"Following Private Addresses have been detected in file {changed_file} in these respective sections")
        for k, v in privip_dict_section.items():
            print(f"{k}:")
            for i in v:
                print(f"    {i}")
        print("This Pull Request is adding/updating  Private IP addresses, which could be noop! Please check your changes\n")
        sys.exit(1)
    else:
        print(f"No Private IP addresses detected in changes for file {changed_file} related to this pull request\n")

def analyze_yaml(yaml_data):
    private_ips = {}
    privateip_count = 0
    def analyze_data(data, path=''):
        nonlocal private_ips
        nonlocal privateip_count
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(key, int):
                    new_path = f"{path}[{key}]" if path else f"[{key}]"
                else:
                    new_path = f"{path}['{key}']" if path else f"['{key}']"  
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

def check_allipsprivate_pr(ip, filepath):
    changed_file = filepath
    orig_file = changed_file + ".pr"
    updated_file = orig_file + "-updated"
    remove_invalid_yaml_lines(orig_file, updated_file)
    with open(updated_file, 'r') as f:
        yaml_data = yaml.safe_load(f)
    private_ips  = analyze_yaml(yaml_data)[0]
    privip_paths = []
    for k, v in private_ips.items():
        if v == ip:
            privip_paths.append(k)
    for path in privip_paths:
        if '][' in path:
            parts = path.split('][') 
            check_path =  ']['.join(parts[:-1]) + ']'
        else:
            check_path = path
        if check_key_contains_priv_terms(check_path):
            return True, None
        check_path_val = eval("yaml_data" + check_path)
        if isinstance(check_path_val, list):
            if check_all_ips_priv_list(check_path_val):
                return True, None
        elif isinstance(check_path_val, dict):
            if check_all_ips_priv_dict(check_path_val):
                return True, None 
    return False, privip_paths
                    
def check_key_contains_priv_terms(input_string):
    # Check if the input string contains "private" or "priv"
    if "priv" in input_string.lower():
        return True
    return False
     
def check_all_ips_priv_list(ip_list):
    for ip in ip_list:
        if is_private_ip(ip):
            continue
        else:
             return False
    return True    

def check_all_ips_priv_dict(ip_dict):
    for k,v in ip_dict.items():
        if isinstance(v, dict):
            if check_all_ips_priv_dict(v):
                continue
            else:
                return False
        elif isinstance(v, list):
            if check_all_ips_priv_list(v):
                continue
            else:
                return False 
        elif isinstance(v, str):
            if is_private_ip(v):
                continue
            else:
                return False
    return True
            
def scan_for_priv_ip_master(filepath):
    changed_file = filepath
    orig_file = changed_file + ".master"
    print(f"\nChecking for private IP Addresses in file {changed_file}\n")
    updated_file = orig_file + "-updated"
    remove_invalid_yaml_lines(orig_file, updated_file)
    with open(updated_file, 'r') as f:
        yaml_data = yaml.safe_load(f)
    private_ips, count = analyze_yaml(yaml_data)
    os.remove(updated_file)
    privips = private_ips.values()
    return privips

def scan_for_priv_ip(dir):
    for filename in os.listdir(dir):
        file_path = os.path.join(dir, filename)
        if filename.endswith('.sls'):
            print(f"\nChecking for private IP Addresses in {file_path}...\n")
            updatedfile = file_path + "-updated"
            remove_invalid_yaml_lines(file_path, updatedfile)
            with open(updatedfile, 'r') as f:
                yaml_data = yaml.safe_load(f)
            private_ips = analyze_yaml(yaml_data)[0]
            if private_ips:
                privips_count_dict = {}
                for path, ip in private_ips.items():
                    if '][' in path:
                        section = path.split('][')[0].lstrip('[')
                    else:
                        section = path.lstrip('[').rstrip(']')
                    if section not in privips_count_dict:
                        privips_count_dict[section] = {}
                        privips_count_dict[section]['count'] = 1
                        privips_count_dict[section]['ips'] = [ip]
                    else:
                        privips_count_dict[section]['count'] += 1
                        privips_count_dict[section]['ips'].append(ip)
                for k, v in privips_count_dict.items():
                    print(f"Private IPs in {k}:")
                    if v['count'] == 1:
                        print(f"{v['ips'][0]}\n")
                    else:
                        for ip in v['ips']:
                            print(f"    {ip}")
                        print(f"{v['count']} IPs are private in this section\n")
            else:
                print(f"No private IP addresses found in {file_path}\n")
            print(f"Done checking for private IP Addresses in {file_path}\n\n{'*'*60}")
            os.remove(updatedfile)

if sys.argv[1:]:                  # if script is called with arguments(files changed) then check the code for only files changed in pr,
    for path in sys.argv[1:]:     # else if script is called without arguments corresponding to "workflow_dispatch" of Github Actions
        detect_privateip_pr(path) # then check all the files in the master branch
else:
    scan_for_priv_ip("network")
