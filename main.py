import yaml
import re
import sys

PORT_NAMES = {
    'bgp': 179,
    'dns': 53,
    'ftp': 21,
    'ftp-data': 20,
    'http': 80,
    'https': 443,
    'imap': 143,
    'pop3': 110,
    'smtp': 25,
    'snmp': 161,
    'ssh': 22,
    'telnet': 23,
    'www': 80,
}

PORT_OPERATORS = ('eq', 'gt', 'lt', 'neq', 'range')


def port_to_number(port):
    """Convert a named port to its number, or return the integer value."""
    if isinstance(port, int):
        return port
    if port.isdigit():
        return int(port)
    return PORT_NAMES.get(port.lower(), port)


def wildcard_to_prefix(wildcard):
    """Convert a wildcard mask to a CIDR prefix length."""
    parts = [int(x) for x in wildcard.split('.')]
    mask_parts = [255 - x for x in parts]
    return sum(bin(x).count('1') for x in mask_parts)


def _is_ipv6(token):
    """Return True if a token looks like an IPv6 address or prefix."""
    return ':' in token


def parse_address(tokens):
    """
    Parse one address (any / host / ip+wildcard / CIDR) from the token list.

    Returns (address_dict, remaining_tokens).
    """
    if not tokens:
        return None, tokens

    token = tokens[0]

    if token == 'any':
        addr = {'any': True}
        tokens = tokens[1:]

    elif token == 'host':
        addr = {'host': tokens[1]}
        tokens = tokens[2:]

    elif '/' in token:
        # Inline CIDR notation (IPv4 like 192.168.1.0/24 or IPv6 like 2001:db8::/32)
        if _is_ipv6(token):
            addr = {'ip': token}
        else:
            addr = {'host': token}
        tokens = tokens[1:]

    else:
        # ip + wildcard mask pair
        ip, wildcard = tokens[0], tokens[1]
        tokens = tokens[2:]
        prefix = wildcard_to_prefix(wildcard)
        addr = {'ip': f'{ip}/{prefix}'}

    # Optional port operator immediately following the address
    if tokens and tokens[0] in PORT_OPERATORS:
        operator = tokens[0]
        if operator == 'range':
            port_start = port_to_number(tokens[1])
            port_end = port_to_number(tokens[2])
            tokens = tokens[3:]
            addr['port_number'] = {
                'operator': 'range',
                'port_start': port_start,
                'port_end': port_end,
            }
        else:
            port = port_to_number(tokens[1])
            tokens = tokens[2:]
            addr['port_number'] = {'operator': operator, 'port': port}

    return addr, tokens


def parse_options(tokens):
    """
    Parse trailing options (established, log, http-method, tcp-option-length)
    that follow the source and destination addresses.

    Returns a dict of extra fields to merge into the ACL entry.
    """
    extras = {}
    filtering = {}

    while tokens:
        token = tokens.pop(0)
        if token == 'established':
            filtering.setdefault('flags', []).append({'establish': True})
        elif token == 'log':
            extras['log'] = True
        elif token == 'http-method':
            filtering['http_method'] = tokens.pop(0)
        elif token == 'tcp-option-length':
            filtering['tcp_option_length'] = int(tokens.pop(0))

    if filtering:
        extras['filtering_options'] = [filtering]

    return extras


def parse_acl_entry(line):
    """
    Parse a single numbered ACL entry line.

    Returns a dict representing the entry, or None if the line is not an entry.
    """
    tokens = line.split()
    if not tokens or not tokens[0].isdigit():
        return None

    seq = int(tokens.pop(0))
    if not tokens:
        return None

    keyword = tokens.pop(0)

    if keyword == 'remark':
        return {'seq_number': seq, 'remark': ' '.join(tokens)}

    if keyword not in ('permit', 'deny'):
        return None

    if not tokens:
        return None

    protocol = tokens.pop(0)

    source, tokens = parse_address(tokens)
    if source is None:
        return None

    destination, tokens = parse_address(tokens)
    if destination is None:
        return None

    entry = {
        'seq_number': seq,
        'operation': keyword,
        'protocol': protocol,
        'source': source,
        'destination': destination,
    }
    entry.update(parse_options(tokens))
    return entry


def parse_acl_text(text):
    """
    Parse Cisco ACL text content and return the NetAsCode YAML data structure.
    """
    route_control = {
        'ipv4_access_lists': [],
        'ipv6_access_lists': [],
    }

    acl_version = None

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith('#'):
            continue

        if m := re.match(r'ip access-list\s+(\S+)', stripped):
            acl_version = 'ipv4_access_lists'
            route_control['ipv4_access_lists'].append(
                {'name': m.group(1), 'entries': []}
            )

        elif m := re.match(r'ipv6 access-list\s+(\S+)', stripped):
            acl_version = 'ipv6_access_lists'
            route_control['ipv6_access_lists'].append(
                {'name': m.group(1), 'entries': []}
            )

        elif stripped == 'statistics per-entry' and acl_version:
            acl = route_control[acl_version][-1]
            # Insert statistics_per_entry before 'entries' to preserve key order
            entries = acl.pop('entries')
            acl['statistics_per_entry'] = True
            acl['entries'] = entries

        elif acl_version:
            entry = parse_acl_entry(stripped)
            if entry:
                route_control[acl_version][-1]['entries'].append(entry)

    # Remove empty ACL-type lists so the output is clean
    if not route_control['ipv4_access_lists']:
        del route_control['ipv4_access_lists']
    if not route_control['ipv6_access_lists']:
        del route_control['ipv6_access_lists']

    return {'vxlan': {'overlay_extensions': {'route_control': route_control}}}


def parse_acl_file(filename):
    """Parse a Cisco ACL text file and return the NetAsCode data structure."""
    with open(filename, 'r') as f:
        return parse_acl_text(f.read())


def convert_file(input_filename, output_filename='output.yaml'):
    """Convert a Cisco ACL file to NetAsCode YAML and write to output_filename."""
    data = parse_acl_file(input_filename)
    with open(output_filename, 'w') as f:
        yaml.dump(data, f, sort_keys=False)


if __name__ == '__main__':
    input_file = sys.argv[1] if len(sys.argv) > 1 else 'example.txt'
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'output.yaml'
    convert_file(input_file, output_file)