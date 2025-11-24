# OTel SNMP Autodiscovery - Monolithic Config Generator

This tool automatically discovers SNMP-enabled network devices and generates a single, consolidated OpenTelemetry Collector configuration file. By consolidating everything into a single configuration, you reduce overhead from running N Python/Go runtimes to just one - the standard production pattern for OTel Collectors monitoring hundreds of network devices.

## Architecture Overview

Instead of generating N separate config files, this system generates a single `otel-config.yaml` that utilizes:
- **YAML Anchors** to keep the file size small
- **Jinja2 loops** to generate repetitive sections for receivers and pipelines

## Directory Structure

```
/opt/otel-autodiscovery/
├── autodiscover.py          # Main autodiscovery logic
├── config.j2                # Jinja2 template for OTel config
├── requirements.txt         # Python dependencies
└── output/
    └── otel-config.yaml     # Generated configuration
```

## Requirements

- Python 3.8 or higher (tested with Python 3.12)
- pip or pip3 for package installation
- Network access to target SNMP devices (UDP port 161)
- OpenTelemetry Collector Contrib (otelcol-contrib)

## Installation

### 1. Clone or Copy Files

If deploying to `/opt/otel-autodiscovery/`:

```bash
sudo mkdir -p /opt/otel-autodiscovery
sudo cp * /opt/otel-autodiscovery/
cd /opt/otel-autodiscovery
```

Or work from the current directory for testing.

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Or install packages individually with pip3:

```bash
pip3 install pysnmp-lextudio jinja2 psutil
```

Note: We use `pysnmp-lextudio` (the maintained community fork) for Python 3.8+ compatibility.

### 3. Configure Settings

Edit `autodiscover.py` and update the following variables:

```python
# SNMP Communities to try
COMMUNITIES = ["public", "network123", "cisco_read"]

# Elasticsearch Configuration
ES_CONFIG = {
    "es_endpoint": "",
    "es_user": "",
    "es_password": ""
}

# Subnets to scan
TARGET_SUBNETS = [
    "192.168.10.0/24",
    "10.255.0.0/24"
]
```

## Usage

### Manual Execution

Run the discovery script:

```bash
python3 autodiscover.py
```

Output:
```
[*] Starting scan of 512 IPs...
[+] Discovered SNMP Device: 192.168.10.1
[+] Discovered SNMP Device: 192.168.10.5
[+] Discovered SNMP Device: 10.255.0.50
[*] Generating config for 3 devices...
[*] Config written to ./output/otel-config.yaml
[*] Sending SIGHUP to OTel Collector (PID: 12345)...
```

### Start OTel Collector

Point your collector to the generated config:

```bash
otelcol-contrib --config=/opt/otel-autodiscovery/output/otel-config.yaml
```

Or if using systemd:

```bash
sudo systemctl start otelcol
```

### Automated Discovery (Cron)

Set up a cron job to run discovery periodically:

```bash
# Edit crontab
crontab -e

# Add this line to run every hour
0 * * * * /usr/bin/python3 /opt/otel-autodiscovery/autodiscover.py >> /var/log/otel-discovery.log 2>&1
```

Or every 15 minutes:

```bash
*/15 * * * * /usr/bin/python3 /opt/otel-autodiscovery/autodiscover.py >> /var/log/otel-discovery.log 2>&1
```

The script automatically sends SIGHUP to reload the OTel collector without dropping packets.

## How It Works

### 1. Network Scanning

The script uses async/await with a semaphore (10 concurrent connections by default) to scan the configured subnets:
- Tests each IP address on UDP port 161
- Tries multiple SNMP community strings
- Queries sysName (OID 1.3.6.1.2.1.1.5.0) to verify SNMP response
- Uses a shared SNMP engine to avoid file descriptor exhaustion

### 2. Device Inventory

Discovered devices are:
- Sorted by IP address for config stability
- Assigned sequential IDs (node_1, node_2, etc.)
- Tagged with their working community string

### 3. Config Generation

The Jinja2 template generates:
- **YAML Anchor** (`&snmp_defaults`) defining common SNMP settings
- **Receivers** for each device, inheriting from the anchor
- **Resource Processors** to tag metrics with IP addresses
- **Pipelines** routing each device's metrics through processors to Elasticsearch

### 4. Hot Reload

The script sends SIGHUP to the running OTel Collector process, causing it to reload the configuration without restarting.

## Key Advantages

### Stability
Device IDs remain consistent across scans because we sort by IP address. If 192.168.10.50 is `node_1` in the first scan, it will remain `node_1` in subsequent scans.

### Efficiency
SIGHUP reload is lightweight - it refreshes internal pipelines without killing the process or dropping packets.

### Scalability
This single-file approach works for 300-500 devices per collector instance. Beyond that, consider:
- Sharding across multiple collector instances
- Dividing subnets across different collectors
- Using OTel's load balancing features

## Configuration Template Details

The `config.j2` template uses YAML anchors to reduce duplication:

```yaml
snmp/template: &snmp_defaults
  version: v2c
  community: public
  collection_interval: 60s
  timeout: 10s
  # ... metrics definitions ...

snmp/node_1:
  <<: *snmp_defaults
  endpoint: udp://192.168.10.1:161
  community: public
```

This keeps the file size manageable even with hundreds of devices.

## Troubleshooting

### No devices discovered

1. Verify network connectivity: `ping <target_ip>`
2. Check firewall rules allow UDP 161
3. Verify SNMP is enabled on devices
4. Test community strings manually with snmpwalk:
   ```bash
   snmpwalk -v2c -c public 192.168.10.1 1.3.6.1.2.1.1.5.0
   ```

### OTel Collector not reloading

1. Check if process is running:
   ```bash
   ps aux | grep otelcol
   ```
2. Verify process name matches `OTEL_PROCESS_NAME` in script
3. Manually reload:
   ```bash
   kill -SIGHUP <pid>
   ```

### Permission errors

Run with appropriate permissions:
```bash
sudo python3 autodiscover.py
```

Or adjust file ownership:
```bash
sudo chown -R otel:otel /opt/otel-autodiscovery
```

## Customization

### Adding More Metrics

Edit `config.j2` and add OIDs to the `&snmp_defaults` anchor:

```yaml
metrics:
  system.uptime:
    # ... existing ...

  interface.traffic.in:
    unit: bytes
    sum:
      aggregation: cumulative
      value_type: int
    column_oids:
      - oid: "1.3.6.1.2.1.2.2.1.10"
```

### Custom Exporters

Add additional exporters in `config.j2`:

```yaml
exporters:
  elasticsearch:
    # ... existing ...

  prometheus:
    endpoint: "0.0.0.0:8889"

  logging:
    loglevel: debug
```

Then update pipelines:
```yaml
exporters: [elasticsearch, prometheus, logging]
```

### Adjust Scan Performance

In `autodiscover.py`, modify:

```python
# Reduce timeout for faster scans (less reliable)
UdpTransportTarget((str(ip), 161), timeout=0.5, retries=0)

# Adjust concurrent connections (increase if you have no file descriptor limits)
MAX_CONCURRENT_REQUESTS = 10  # Default is 10, increase to 20-50 for faster scans
```

**Note**: If you get "Too many open files" errors on Linux, you can either:
- Reduce `MAX_CONCURRENT_REQUESTS` to 5
- Increase your system's file descriptor limit: `ulimit -n 4096`

## Production Deployment Checklist

- [ ] Update `COMMUNITIES` with your actual SNMP strings
- [ ] Configure correct `ES_CONFIG` credentials
- [ ] Set appropriate `TARGET_SUBNETS`
- [ ] Test manual run: `python3 autodiscover.py`
- [ ] Verify generated config: `cat output/otel-config.yaml`
- [ ] Start OTel Collector with generated config
- [ ] Set up cron job for automated discovery
- [ ] Configure log rotation for `/var/log/otel-discovery.log`
- [ ] Set up monitoring/alerts for the collector process
- [ ] Document your SNMP community strings securely

## Security Notes

- Store SNMP community strings securely (consider environment variables or secrets manager)
- Restrict file permissions: `chmod 600 autodiscover.py`
- Use SNMP v3 for production (requires template modifications)
- Rotate Elasticsearch credentials regularly
- Monitor collector logs for unauthorized access attempts

## License

This is a reference implementation for OTel SNMP autodiscovery. Adapt as needed for your environment.
