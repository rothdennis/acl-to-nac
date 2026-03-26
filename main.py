import yaml
import re

FILE_NAME = 'example.txt'

output = {'vxlan':{'overlay_extensions': {'route_control': {
    'ipv4_access_lists': [],
    'ipv6_access_lists': []
}}}}

def parse_acl_line(line):
    # REMARK
    if remark := re.match(r'\s*(?P<seq_number>\d+) remark (?P<remark>.+)', line):
        return {'seq_number': int(remark.group('seq_number')), 'remark': remark.group('remark')}
    # PERMIT/DENY
    elif permit := re.match(r'\s*(?P<seq_number>\d+) (?P<operation>permit|deny) (?P<protocol>\S+) ((?P<src_ip>\S+) (?P<src_wildcard>\S+)|any) ((?P<dst_ip>\S+) (?P<dst_wildcard>\S+)|any)', line):
        return {
            'seq_number': int(permit.group('seq_number')),
            'operation': permit.group('operation'),
            'protocol': permit.group('protocol'),
            'source': {'ip': permit.group('src_ip'), 'wildcard': permit.group('src_wildcard')},
            'destination': {'ip': permit.group('dst_ip'), 'wildcard': permit.group('dst_wildcard')}
        }
    else:
        return False

def main():
    # print(f'Reading ACL configuration from {FILE_NAME}...')
    with open(FILE_NAME, 'r') as f:
        acl_config = f.read()
    
    acl_version = None    
        
    print('Parsing ACL configuration...')
    for line in acl_config.splitlines():
        if acl_v4 := re.match(r'\s*ip access-list (?P<acl_name>.+)', line):
            print(f'Found ACL (IPv4): {acl_v4.group("acl_name")}')  
            acl_version = 'ipv4_access_lists'
            output['vxlan']['overlay_extensions']['route_control']['ipv4_access_lists'].append({'name': acl_v4.group("acl_name"), 'entries': []})
        elif acl_v6 := re.match(r'\s*ipv6 access-list (?P<acl_name>.+)', line):
            print(f'Found ACL (IPv6): {acl_v6.group("acl_name")}')
            acl_version = 'ipv6_access_lists'
            output['vxlan']['overlay_extensions']['route_control']['ipv6_access_lists'].append({'name': acl_v6.group("acl_name"), 'entries': []})
        elif acl_entry := parse_acl_line(line):
            if acl_version:
                output['vxlan']['overlay_extensions']['route_control'][acl_version][-1]['entries'].append(acl_entry)
        
    with open('output.yaml', 'w') as f:
        yaml.dump(output, f, sort_keys=False)

if __name__ == '__main__':
    main()