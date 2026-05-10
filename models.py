#!/usr/bin/env python3
"""Event extraction helpers for Suricata eve.json data."""


def get_event_type(event):
    return event.get('event_type', '')


def get_timestamp(event):
    return event.get('timestamp', '')


def get_src_ip(event):
    return event.get('src_ip', event.get('source', {}).get('ip', ''))


def get_src_port(event):
    return event.get('src_port', event.get('source', {}).get('port', 0))


def get_dest_ip(event):
    return event.get('dest_ip', event.get('destination', {}).get('ip', ''))


def get_dest_port(event):
    return event.get('dest_port', event.get('destination', {}).get('port', 0))


def get_protocol(event):
    return event.get('proto', '')


def get_app_proto(event):
    return event.get('app_proto', '')
