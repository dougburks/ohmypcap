#!/usr/bin/env python3
import os
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_URL_SCHEMES = ('http', 'https')
BLOCKED_HOSTS = ('localhost', '127.0.0.1', '0.0.0.0', '::1')
BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fd00::/8'),
]


def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_port(port_str):
    try:
        port = int(port_str)
        return 0 <= port <= 65535
    except (ValueError, TypeError):
        return False


def sanitize_filename(filename):
    return os.path.basename(filename.replace('\\', '/'))


def is_safe_path(base, path):
    real_base = os.path.realpath(base)
    real_path = os.path.realpath(path)
    return real_path.startswith(real_base + os.sep) or real_path == real_base


def validate_url_safety(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError("Only HTTP/HTTPS URLs are allowed")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: no hostname")

    if hostname.lower() in [h.lower() for h in BLOCKED_HOSTS]:
        raise ValueError("Access to localhost is not allowed")

    try:
        addrinfo = socket.getaddrinfo(hostname, None)
        resolved_ips = set()
        for info in addrinfo:
            resolved_ips.add(info[4][0])
        for addr in resolved_ips:
            ip = ipaddress.ip_address(addr)
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    raise ValueError(f"Access to private/internal addresses is not allowed ({addr})")
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")


def validate_zip_extraction(zip_ref, extract_path):
    for member in zip_ref.namelist():
        member_path = os.path.realpath(os.path.join(extract_path, member))
        if not member_path.startswith(os.path.realpath(extract_path) + os.sep):
            raise ValueError(f"Zip slip detected: {member}")


def validate_pcap_content(data):
    if len(data) < 4:
        return False
    magic = data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return True
    if magic == b'\x0a\x0d\x0d\x0a':
        return True
    if magic in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'):
        return True
    return False
