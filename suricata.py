#!/usr/bin/env python3
import os
import re
import shutil
import subprocess
import threading

import config
from db import create_sqlite_db
from validators import is_host_reachable
from yara_scanner import run_yara_pipeline

REQUIRED_EXECUTABLES = ['tcpdump', 'tshark', 'suricata', 'suricata-update']


def check_executables():
    """Check all required executables exist. Returns list of missing tools."""
    missing = []
    for tool in REQUIRED_EXECUTABLES:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def has_internet_access():
    return is_host_reachable('rules.emergingthreats.net', 80, timeout=5)


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
                    except OSError as e:
                        print(f'Warning: could not copy {src} to {dst}: {e}')
                elif os.path.isdir(src):
                    try:
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    except OSError as e:
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
        # Enable file-store output for extracted file analysis
        config_content = re.sub(
            r'(\s+file-store:\s*\n\s+version:\s*\d+\s*\n\s+)enabled:\s*no',
            r'\1enabled: yes',
            config_content
        )
        config_content = config_content.replace('      #dir: filestore', '      dir: filestore')
        config_content = config_content.replace('      #write-fileinfo: yes', '      write-fileinfo: yes')
        config_content = config_content.replace('      #force-filestore: yes', '      force-filestore: yes')
        config_content = config_content.replace('      #stream-depth: 0', '      stream-depth: 0')
        config_content = config_content.replace('      #force-hash: [sha1, md5]', '      force-hash: [md5, sha1, sha256]')
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
                timeout=config.SURICATA_UPDATE_TIMEOUT
            )
            print("Suricata rules updated successfully")
        except (subprocess.CalledProcessError, OSError) as e:
            print(f'suricata-update warning: {e}')
    elif baked_in_rules_exist:
        print("No internet access detected — using baked-in Suricata rules")
        try:
            shutil.copytree(baked_in_rules_dir, suricata_rules_dir, dirs_exist_ok=True)
            print("Baked-in rules copied successfully")
        except OSError as e:
            print(f'Warning: could not copy baked-in rules: {e}')
    else:
        print("Warning: no baked-in rules found and no internet access — Suricata may not have rules to use")


def spawn_suricata(dir_path, pcap_path, suricata_config_path=None, data_dir=None):
    """Spawn Suricata in the background to analyze a PCAP.

    Returns True if a new Suricata process was started.
    Returns False if analysis is already in progress (lock exists).
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/ohmypcap-data')
    if suricata_config_path is None:
        suricata_config_path = os.path.join(data_dir, 'suricata', 'suricata.yaml')

    phase_file = os.path.join(dir_path, '.phase')
    if os.path.exists(phase_file):
        return False

    _set_phase(dir_path, 'network')

    def on_suricata_done():
        # Phase 2: Run YARA scan on extracted files
        _set_phase(dir_path, 'files')
        try:
            run_yara_pipeline(dir_path, data_dir=data_dir)
        except Exception as e:
            _set_error(dir_path, f'YARA scan failed: {e}')
        # Phase 3: Build SQLite database
        _set_phase(dir_path, 'importing')
        eve_file = os.path.join(dir_path, 'eve.json')
        db_file = os.path.join(dir_path, 'events.db')
        if os.path.exists(eve_file) and not os.path.exists(db_file):
            try:
                create_sqlite_db(db_file, eve_file)
            except Exception as e:
                _set_error(dir_path, f'Database creation failed: {e}')
        # Clear phase only after DB (with YARA matches) is ready
        _clear_phase(dir_path)

    try:
        proc = subprocess.Popen(
            ['suricata', '-r', pcap_path, '-c', suricata_config_path,
             '-l', dir_path,
             '-k', 'none', '--runmode', 'single',
             '--set', 'outputs.1.eve-log.types.0.alert.metadata.rule.raw=true'],
            cwd=dir_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        def _suricata_watchdog():
            """Kill Suricata if it runs longer than the configured timeout."""
            try:
                proc.wait(timeout=config.SURICATA_RUN_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                _set_error(dir_path, f'Suricata timed out after {config.SURICATA_RUN_TIMEOUT}s')
                _clear_phase(dir_path)
                return
            on_suricata_done()

        threading.Thread(target=_suricata_watchdog, daemon=True).start()
        return True
    except (OSError, PermissionError) as e:
        _set_error(dir_path, f'Suricata failed to start: {e}')
        _clear_phase(dir_path)
        return False


def _set_phase(dir_path, phase):
    """Write the current analysis phase to the .phase file."""
    phase_file = os.path.join(dir_path, '.phase')
    try:
        with open(phase_file, 'w') as f:
            f.write(phase)
    except OSError:
        pass


def _clear_phase(dir_path):
    """Remove the .phase file to indicate analysis is complete."""
    phase_file = os.path.join(dir_path, '.phase')
    try:
        if os.path.exists(phase_file):
            os.unlink(phase_file)
    except OSError:
        pass


def _set_error(dir_path, message):
    """Write an error message to the .error file."""
    error_file = os.path.join(dir_path, '.error')
    try:
        with open(error_file, 'w') as f:
            f.write(message)
    except OSError:
        pass


def _clear_error(dir_path):
    """Remove the .error file."""
    error_file = os.path.join(dir_path, '.error')
    try:
        if os.path.exists(error_file):
            os.unlink(error_file)
    except OSError:
        pass
