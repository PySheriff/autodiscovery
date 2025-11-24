#!/usr/bin/env python3
"""
OTel SNMP Autodiscovery - Monolithic Config Generator

This script performs subnet scanning to discover SNMP-enabled devices,
generates a single consolidated OTel Collector configuration file,
and reloads the collector to apply the new configuration.
"""

import ipaddress
import os
import signal
import psutil
import asyncio
from pysnmp.hlapi.asyncio import *
from jinja2 import Environment, FileSystemLoader

# --- Configuration ---
TEMPLATE_DIR = "./"
TEMPLATE_FILE = "config.j2"
OUTPUT_FILE = "./output/otel-config.yaml"
OTEL_PROCESS_NAME = "otelcol-contrib"

# Search these communities
COMMUNITIES = ["public", "network123", "cisco_read"]

# Configuration for Exporters (passed to template)
ES_CONFIG = {
    "es_endpoint": "https://xxxx.es.us-central1.gcp.cloud.es.io",
    "es_user": "USERNAME",
    "es_password": "YOUR_PASSWORD_HERE",
    "es_metrics_index": "metrics-snmp-default"  # Data stream: type-dataset-namespace
}

# Define Subnets to Scan
TARGET_SUBNETS = [
    "192.168.10.0/24",
    "10.255.0.0/24"
]

# Limit concurrent SNMP requests to avoid "too many open files" error
MAX_CONCURRENT_REQUESTS = 10

async def check_snmp(ip, snmp_engine, semaphore):
    """
    Checks if an IP responds to SNMP on port 161.
    Returns (ip, community) if successful, else None.
    Uses a semaphore to limit concurrent connections.
    """
    async with semaphore:
        for community in COMMUNITIES:
            try:
                errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                    snmp_engine,
                    CommunityData(community, mpModel=1), # v2c
                    UdpTransportTarget((str(ip), 161), timeout=1.5, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')) # sysName
                )

                if not errorIndication and not errorStatus:
                    return (str(ip), community)
            except Exception as e:
                # Silently ignore connection errors for unreachable hosts
                pass

        return None

async def scan_and_build_inventory():
    """
    Scans subnets using asyncio and builds a device list.
    """
    ips_to_scan = []
    for subnet in TARGET_SUBNETS:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            # Skip network and broadcast addresses
            ips_to_scan.extend([str(ip) for ip in net.hosts()])
        except ValueError:
            print(f"Skipping invalid subnet: {subnet}")

    print(f"[*] Starting scan of {len(ips_to_scan)} IPs...")

    # Create shared resources
    snmp_engine = SnmpEngine()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    valid_devices = []

    # Scan all IPs concurrently, but semaphore limits actual concurrent requests
    results = await asyncio.gather(
        *[check_snmp(ip, snmp_engine, semaphore) for ip in ips_to_scan],
        return_exceptions=True
    )

    for result in results:
        if result and not isinstance(result, Exception):
            ip, community = result
            print(f"[+] Discovered SNMP Device: {ip}")
            valid_devices.append({
                "ip": ip,
                "community": community
            })

    # Assign IDs to devices (needed for config generation)
    # We sort by IP to ensure config stability between runs
    valid_devices.sort(key=lambda x: ipaddress.ip_address(x['ip']))
    for idx, device in enumerate(valid_devices):
        device['id'] = idx + 1

    return valid_devices

def generate_yaml(devices):
    """
    Renders the Jinja2 template.
    """
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(TEMPLATE_FILE)

    # Merge device list with ES config
    context = {
        "devices": devices,
        **ES_CONFIG
    }

    print(f"[*] Generating config for {len(devices)} devices...")
    rendered_yaml = template.render(context)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        f.write(rendered_yaml)

    print(f"[*] Config written to {OUTPUT_FILE}")

def reload_otel_collector():
    """
    Finds the running otelcol process and sends SIGHUP to reload config.
    If not running, you might want to start it via systemctl.
    """
    reloaded = False
    for proc in psutil.process_iter(['pid', 'name']):
        if OTEL_PROCESS_NAME in proc.info['name']:
            print(f"[*] Sending SIGHUP to OTel Collector (PID: {proc.info['pid']})...")
            os.kill(proc.info['pid'], signal.SIGHUP)
            reloaded = True

    if not reloaded:
        print("[!] OTel Collector process not found. Please start it manually.")
        # Optional: subprocess.run(["systemctl", "restart", "otelcol"])

async def main():
    """Main async entry point."""
    devices = await scan_and_build_inventory()

    if devices:
        generate_yaml(devices)
        reload_otel_collector()
    else:
        print("[-] No devices found. Config not updated.")

if __name__ == "__main__":
    asyncio.run(main())
