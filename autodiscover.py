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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pysnmp.hlapi import *
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
    "es_endpoint": "https://my-deployment.es.us-central1.gcp.cloud.es.io",
    "es_user": "netlab",
    "es_password": "YOUR_PASSWORD_HERE"
}

# Define Subnets to Scan
TARGET_SUBNETS = [
    "192.168.10.0/24",
    "10.255.0.0/24"
]


def ensure_event_loop():
    """Ensure there is an asyncio event loop for the current thread.

    pysnmp's sync HLAPI uses asyncio under the hood and calls
    asyncio.get_event_loop(), which raises RuntimeError in Python 3.12+
    if no loop is set for this thread (for example in ThreadPoolExecutor
    worker threads). This function makes sure a loop exists so that
    getCmd()/nextCmd() can run without crashing.
    """
    try:
        asyncio.get_event_loop()
    except RuntimeError as ex:
        if "There is no current event loop" in str(ex):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        else:
            raise


def check_snmp(ip):
    """
    Checks if an IP responds to SNMP on port 161.
    Returns (ip, community) if successful, else None.
    """
    ensure_event_loop()

    for community in COMMUNITIES:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),  # v2c
            UdpTransportTarget((str(ip), 161), timeout=1.5, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0"))  # sysName
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if not errorIndication and not errorStatus:
            return (str(ip), community)

    return None


def scan_and_build_inventory():
    """
    Scans subnets using threads and builds a device list.
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

    valid_devices = []

    # Scan in parallel (50 threads)
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(check_snmp, ip): ip for ip in ips_to_scan}

        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                ip, community = result
                print(f"[+] Discovered SNMP Device: {ip}")
                valid_devices.append({
                    "ip": ip,
                    "community": community
                })

    # Assign IDs to devices (needed for config generation)
    # We sort by IP to ensure config stability between runs
    valid_devices.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    for idx, device in enumerate(valid_devices):
        device["id"] = idx + 1

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
    for proc in psutil.process_iter(["pid", "name"]):
        if OTEL_PROCESS_NAME in proc.info["name"]:
            print(
                f"[*] Sending SIGHUP to OTel Collector "
                f"(PID: {proc.info['pid']})..."
            )
            os.kill(proc.info["pid"], signal.SIGHUP)
            reloaded = True

    if not reloaded:
        print("[!] OTel Collector process not found. Please start it manually.")
        # Optional: subprocess.run(["systemctl", "restart", "otelcol"])


if __name__ == "__main__":
    devices = scan_and_build_inventory()

    if devices:
        generate_yaml(devices)
        reload_otel_collector()
    else:
        print("[-] No devices found. Config not updated.")
