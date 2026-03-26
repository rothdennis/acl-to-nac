"""
Test suite for the Cisco ACL → NetAsCode YAML converter.

Each test loads one of the five provided input/output pairs from the tests/
directory, runs the converter, and asserts that the Python data structure
matches the expected YAML file exactly.
"""

import os
import sys
import pytest
import yaml

# Allow importing main.py from the repo root regardless of how pytest is invoked
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(TESTS_DIR)
sys.path.insert(0, REPO_DIR)

from main import (  # noqa: E402
    parse_acl_entry,
    parse_acl_file,
    parse_acl_text,
    parse_address,
    port_to_number,
    wildcard_to_prefix,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def _find_input(test_num):
    """Return the path to test_N_input.txt (tolerating the .txtt typo)."""
    for ext in ('txt', 'txtt'):
        candidate = os.path.join(TESTS_DIR, f'test_{test_num}_input.{ext}')
        if os.path.exists(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Parametrised end-to-end tests (input file → expected output YAML)
# ---------------------------------------------------------------------------

TEST_CASES = [
    pytest.param(i, id=f'test_{i}')
    for i in range(1, 6)
    if _find_input(i) is not None
]


@pytest.mark.parametrize('test_num', TEST_CASES)
def test_end_to_end(test_num):
    """Converting a test input must produce the expected YAML data structure."""
    input_path = _find_input(test_num)
    output_path = os.path.join(TESTS_DIR, f'test_{test_num}_output.yaml')

    actual = parse_acl_file(input_path)
    expected = _load_yaml(output_path)

    assert actual == expected


# ---------------------------------------------------------------------------
# Unit tests for individual converter helpers
# ---------------------------------------------------------------------------

class TestPortToNumber:
    def test_numeric_string(self):
        assert port_to_number('443') == 443

    def test_named_port_www(self):
        assert port_to_number('www') == 80

    def test_named_port_ftp_data(self):
        assert port_to_number('ftp-data') == 20

    def test_named_port_telnet(self):
        assert port_to_number('telnet') == 23

    def test_integer_passthrough(self):
        assert port_to_number(8080) == 8080


class TestWildcardToPrefix:
    def test_slash24(self):
        assert wildcard_to_prefix('0.0.0.255') == 24

    def test_slash16(self):
        assert wildcard_to_prefix('0.0.255.255') == 16

    def test_slash8(self):
        assert wildcard_to_prefix('0.255.255.255') == 8

    def test_slash32(self):
        assert wildcard_to_prefix('0.0.0.0') == 32


class TestParseAddress:
    def test_any(self):
        addr, rest = parse_address(['any'])
        assert addr == {'any': True}
        assert rest == []

    def test_any_with_port(self):
        addr, rest = parse_address(['any', 'gt', '1023', 'other'])
        assert addr == {'any': True, 'port_number': {'operator': 'gt', 'port': 1023}}
        assert rest == ['other']

    def test_ip_wildcard(self):
        addr, rest = parse_address(['10.0.0.0', '0.255.255.255'])
        assert addr == {'ip': '10.0.0.0/8'}
        assert rest == []

    def test_cidr_ipv4_host(self):
        addr, rest = parse_address(['192.168.1.1/32'])
        assert addr == {'host': '192.168.1.1/32'}
        assert rest == []

    def test_cidr_ipv6(self):
        addr, rest = parse_address(['2001:db8::/32'])
        assert addr == {'ip': '2001:db8::/32'}
        assert rest == []

    def test_host_keyword(self):
        addr, rest = parse_address(['host', '10.0.0.1'])
        assert addr == {'host': '10.0.0.1'}
        assert rest == []


class TestParseAclEntry:
    def test_remark(self):
        entry = parse_acl_entry('5 remark Allow all traffic')
        assert entry == {'seq_number': 5, 'remark': 'Allow all traffic'}

    def test_permit_ip(self):
        entry = parse_acl_entry('10 permit ip 192.168.1.0 0.0.0.255 10.0.0.0 0.255.255.255')
        assert entry['seq_number'] == 10
        assert entry['operation'] == 'permit'
        assert entry['protocol'] == 'ip'
        assert entry['source'] == {'ip': '192.168.1.0/24'}
        assert entry['destination'] == {'ip': '10.0.0.0/8'}

    def test_deny_any_any(self):
        entry = parse_acl_entry('20 deny ip any any')
        assert entry['operation'] == 'deny'
        assert entry['source'] == {'any': True}
        assert entry['destination'] == {'any': True}

    def test_established_flag(self):
        entry = parse_acl_entry('10 permit tcp any any established')
        assert entry['filtering_options'] == [{'flags': [{'establish': True}]}]

    def test_log_option(self):
        entry = parse_acl_entry('10 permit ip any any log')
        assert entry['log'] is True

    def test_non_entry_line(self):
        assert parse_acl_entry('ip access-list myacl') is None
        assert parse_acl_entry('') is None
        assert parse_acl_entry('statistics per-entry') is None


class TestParseAclText:
    def test_ipv4_acl_structure(self):
        text = 'ip access-list myacl\n  10 permit ip any any\n'
        result = parse_acl_text(text)
        rc = result['vxlan']['overlay_extensions']['route_control']
        assert 'ipv4_access_lists' in rc
        assert rc['ipv4_access_lists'][0]['name'] == 'myacl'

    def test_ipv6_acl_structure(self):
        text = 'ipv6 access-list myv6acl\n  10 permit ipv6 any any\n'
        result = parse_acl_text(text)
        rc = result['vxlan']['overlay_extensions']['route_control']
        assert 'ipv6_access_lists' in rc
        assert rc['ipv6_access_lists'][0]['name'] == 'myv6acl'

    def test_empty_list_not_included(self):
        text = 'ip access-list myacl\n  10 permit ip any any\n'
        result = parse_acl_text(text)
        rc = result['vxlan']['overlay_extensions']['route_control']
        assert 'ipv6_access_lists' not in rc

    def test_statistics_per_entry(self):
        text = 'ip access-list myacl\n  statistics per-entry\n  10 permit ip any any\n'
        result = parse_acl_text(text)
        acl = result['vxlan']['overlay_extensions']['route_control']['ipv4_access_lists'][0]
        assert acl.get('statistics_per_entry') is True
        # statistics_per_entry must appear before entries in the dict
        keys = list(acl.keys())
        assert keys.index('statistics_per_entry') < keys.index('entries')

    def test_comment_lines_ignored(self):
        text = '# This is a comment\nip access-list myacl\n  10 permit ip any any\n'
        result = parse_acl_text(text)
        rc = result['vxlan']['overlay_extensions']['route_control']
        assert len(rc['ipv4_access_lists']) == 1

    def test_multiple_acls(self):
        text = (
            'ip access-list first\n  10 permit ip any any\n'
            'ip access-list second\n  10 deny ip any any\n'
        )
        result = parse_acl_text(text)
        lists = result['vxlan']['overlay_extensions']['route_control']['ipv4_access_lists']
        assert len(lists) == 2
        assert lists[0]['name'] == 'first'
        assert lists[1]['name'] == 'second'
