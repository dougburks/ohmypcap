#!/usr/bin/env python3
import os
import re
import shutil
import socket
import subprocess
import threading

from db import create_sqlite_db

REQUIRED_EXECUTABLES = ['tcpdump', 'tshark', 'suricata', 'suricata-update']


def check_executables():
    """Check all required executables exist. Returns list of missing tools."""
    missing = []
    for tool in REQUIRED_EXECUTABLES:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def has_internet_access():
    try:
        socket.create_connection(("rules.emergingthreats.net", 80), timeout=5)
        return True
    except OSError:
        return False


def setup_suricata_config(data_dir=None):
    if data_dir is None:
        data_dir = os.path.expanduser('~/ohmypcap-data')
    suricata_dir = os.path.join(data_dir, 'suricata')
    suricata_rules_dir = os.path.join(suricata_dir, 'rules')

    os.makedirs(suricata_dir, exist_ok=True)
    os.makedirs(suricata_rules_dir, exist_ok=True)

    if os.path.isdir('/etc/suricata'):
        needs_copy = False
        if not os.path.exists(os.path.join(suricata_dir, 'suricata.yaml')):
            needs_copy = True

        if needs_copy:
            for item in os.listdir('/etc/suricata'):
                src = os.path.join('/etc/suricata', item)
                dst = os.path.join(suricata_dir, item)
                if os.path.isfile(src):
                    try:
                        shutil.copy2(src, dst)
                    except Exception as e:
                        print(f'Warning: could not copy {src} to {dst}: {e}')
                elif os.path.isdir(src):
                    try:
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    except Exception as e:
                        print(f'Warning: could not copy directory {src} to {dst}: {e}')

    suricata_config = os.path.join(suricata_dir, 'suricata.yaml')
    if os.path.exists(suricata_config):
        with open(suricata_config, 'r') as f:
            config_content = f.read()
        config_content = config_content.replace('/var/lib/suricata/rules', suricata_rules_dir)
        for proto in ('pgsql', 'modbus', 'dnp3', 'enip'):
            config_content = re.sub(
                rf'(\s+{proto}:\s*\n\s+)enabled:\s*no',
                r'\1enabled: yes',
                config_content
            )
        with open(suricata_config, 'w') as f:
            f.write(config_content)

    disable_conf = os.path.join(suricata_dir, 'disable.conf')
    if not os.path.exists(disable_conf):
        with open(disable_conf, 'w') as f:
            f.write('re:classtype:protocol-command-decode\n')

    rules_exist = os.path.exists(os.path.join(suricata_rules_dir, 'suricata.rules'))
    baked_in_rules_dir = '/usr/share/suricata/rules'
    baked_in_rules_exist = os.path.isdir(baked_in_rules_dir) and os.path.exists(os.path.join(baked_in_rules_dir, 'suricata.rules'))

    print("Checking for internet access...")
    if has_internet_access():
        print("Internet access detected — updating Suricata rules...")
        try:
            subprocess.run(
                ['suricata-update', '--no-test', '-c', suricata_config, '--data-dir', suricata_dir, '--disable-conf', disable_conf, '--output', suricata_rules_dir],
                timeout=60
            )
            print("Suricata rules updated successfully")
        except Exception as e:
            print(f'suricata-update warning: {e}')
    elif baked_in_rules_exist:
        print("No internet access detected — using baked-in Suricata rules")
        try:
            shutil.copytree(baked_in_rules_dir, suricata_rules_dir, dirs_exist_ok=True)
            print("Baked-in rules copied successfully")
        except Exception as e:
            print(f'Warning: could not copy baked-in rules: {e}')
    else:
        print("Warning: no baked-in rules found and no internet access — Suricata may not have rules to use")


def spawn_suricata(dir_path, pcap_path, suricata_config_path=None):
    """Spawn Suricata in the background to analyze a PCAP.

    Returns True if a new Suricata process was started.
    Returns False if analysis is already in progress (lock exists).
    """
    if suricata_config_path is None:
        data_dir = os.path.expanduser('~/ohmypcap-data')
        suricata_config_path = os.path.join(data_dir, 'suricata', 'suricata.yaml')

    processing_lock = os.path.join(dir_path, '.processing')
    if os.path.exists(processing_lock):
        return False

    open(processing_lock, 'w').close()

    def on_suricata_done():
        try:
            os.unlink(processing_lock)
        except Exception:
            pass
        eve_file = os.path.join(dir_path, 'eve.json')
        db_file = os.path.join(dir_path, 'events.db')
        if os.path.exists(eve_file) and not os.path.exists(db_file):
            try:
                create_sqlite_db(db_file, eve_file)
            except Exception:
                pass

    try:
        proc = subprocess.Popen(
            ['suricata', '-r', pcap_path, '-c', suricata_config_path,
             '-k', 'none', '--runmode', 'single',
             '--set', 'outputs.1.eve-log.types.0.alert.metadata.rule.raw=true'],
            cwd=dir_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        threading.Thread(target=lambda: (proc.wait(), on_suricata_done()), daemon=True).start()
        return True
    except Exception:
        try:
            os.unlink(processing_lock)
        except Exception:
            pass
        return False
