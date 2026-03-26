# acl-to-nac

[![Tests](https://github.com/rothdennis/acl-to-nac/actions/workflows/tests.yml/badge.svg)](https://github.com/rothdennis/acl-to-nac/actions/workflows/tests.yml)

Convert Cisco IP access-lists (ACLs) to [Network as Code (NaC)](https://netascode.cisco.com/) YAML format.

The converter reads a plain-text file containing one or more Cisco `ip access-list` / `ipv6 access-list` blocks and produces a YAML file that matches the [NaC VXLAN IP ACL data model](https://netascode.cisco.com/docs/data_models/vxlan/overlay_extensions/route_control/ip_acl/). Both IPv4 and IPv6 ACLs are supported.

## Features

- Converts IPv4 and IPv6 Cisco ACLs to NaC YAML
- Supports `permit` / `deny` entries, remarks, and sequence numbers
- Handles `any`, `host`, CIDR, and wildcard-mask address formats
- Resolves named ports (e.g. `www`, `https`, `ftp-data`) to port numbers
- Supports port operators: `eq`, `gt`, `lt`, `neq`, `range`
- Supports trailing options: `established`, `log`, `http-method`, `tcp-option-length`
- Preserves non-contiguous wildcard masks that cannot be expressed as CIDR prefixes
- Handles the `statistics per-entry` directive

## Requirements

- Python 3.9 or newer
- [`pyyaml`](https://pypi.org/project/PyYAML/)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

```bash
python main.py <input_file> [output_file]
```

| Argument | Default | Description |
|---|---|---|
| `input_file` | `example.txt` | Path to the Cisco ACL text file |
| `output_file` | `output.yaml` | Path to write the NaC YAML output |

### Example

Given the following `my_acl.txt`:

```
ip access-list ALLOW-WEB
  10 permit tcp any any eq https
  20 deny   ip  any any
```

Run the converter:

```bash
python main.py my_acl.txt result.yaml
```

The generated `result.yaml` will look like:

```yaml
vxlan:
  overlay_extensions:
    route_control:
      ipv4_access_lists:
      - name: ALLOW-WEB
        entries:
        - seq_number: 10
          operation: permit
          protocol: tcp
          source:
            any: true
          destination:
            any: true
            port_number:
              operator: eq
              port: 443
        - seq_number: 20
          operation: deny
          protocol: ip
          source:
            any: true
          destination:
            any: true
```

## Running the Tests

```bash
python -m pytest tests/ -v
```

## Links

- [NaC VXLAN IP ACLs data model](https://netascode.cisco.com/docs/data_models/vxlan/overlay_extensions/route_control/ip_acl/)
- [Network as Code documentation](https://netascode.cisco.com/)
