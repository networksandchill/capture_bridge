# USB Ethernet Bridge for Packet Capture

A robust Python script that creates transparent network bridges using USB-to-Ethernet adapters, designed for secure packet capture and network analysis.

## 🎯 Purpose

This tool creates a transparent bridge between two USB Ethernet adapters, allowing you to intercept and analyze network traffic between two devices without disrupting their communication. Think of it as a "network tap" using commodity USB adapters.

```
[Device A] ←→ [USB Adapter 1] ←→ [BRIDGE] ←→ [USB Adapter 2] ←→ [Device B]
                                    ↓
                              [Packet Capture]
```

## ✨ Features

- **🔍 Automatic USB Detection**: Automatically finds and configures USB Ethernet adapters
- **🛡️ SSH Safety**: Detects and avoids interfering with your SSH connection
- **🔄 Self-Healing**: Monitors bridge health and recovers from USB disconnections
- **⚡ Minimal Overhead**: Transparent bridging with minimal packet processing
- **📊 Real-time Status**: Live monitoring with clear status messages
- **🧹 Clean Shutdown**: Proper cleanup on exit or interruption

## 📋 Requirements

### System Requirements
- **Linux** (tested on Ubuntu/Debian, should work on most distributions)
- **Root privileges** (required for network interface manipulation)
- **Python 3.6+**
- **Two USB-to-Ethernet adapters**

### USB Adapter Compatibility
Works with most USB Ethernet adapters that appear as:
- `enx*` interfaces (standard USB ethernet naming)
- `eth*` interfaces (when connected via USB)
- `usb*` interfaces (some adapter types)

**Note**: `usb0` is automatically excluded as it's commonly used for other purposes.

### Required Tools
These are typically pre-installed on most Linux systems:
- `ip` (iproute2 package)
- `bridge` (bridge-utils)
- Standard Python libraries (no additional pip packages needed)

## 🚀 Quick Start

1. **Connect your USB adapters**:
   ```bash
   # Verify adapters are detected
   ip link show | grep -E "(enx|eth|usb)"
   ```

2. **Run the bridge** (as root):
   ```bash
   sudo python3 capture_bridge.py
   ```

3. **Start packet capture**:
   ```bash
   # In another terminal
   sudo tcpdump -i capture0 -w capture.pcap
   # or
   sudo tshark -i capture0
   ```

4. **Connect your devices** to the USB adapters and start monitoring traffic!

## 📖 Usage

### Basic Usage
```bash
# Setup bridge and exit
sudo python3 capture_bridge.py

# Setup bridge with monitoring (recommended)
sudo python3 capture_bridge.py --monitor

# Use custom bridge name
sudo python3 capture_bridge.py --bridge mybr0

# Show current status
sudo python3 capture_bridge.py --status

# Clean up existing bridges
sudo python3 capture_bridge.py --cleanup
```

### Command Line Options

| Flag | Description |
|------|-------------|
| `--bridge NAME` | Custom bridge name (default: `capture0`) |
| `--monitor` | Enable continuous monitoring and auto-recovery |
| `--cleanup` | Clean up existing bridges and exit |
| `--status` | Show detailed bridge and interface status |
| `--debug` | Enable debug-level logging |

### Monitoring Mode (Recommended)

When using `--monitor`, the script will:
- ✅ Continuously monitor bridge health
- ✅ Show clear status when interfaces go up/down
- ✅ Auto-recover from USB disconnections
- ✅ Provide "ready for capture" notifications
- ✅ Only recover from critical issues (not just unplugged cables)

## 🏗️ Design Choices

### Why This Approach?

1. **Safety First**: The script prioritizes system stability over features
   - Avoids dangerous kernel module loading
   - Skips aggressive network stack modifications
   - Includes SSH connection protection

2. **Transparent Operation**: Minimal packet processing overhead
   - Uses Linux bridge for hardware-level forwarding
   - Disables STP (Spanning Tree Protocol) for zero delay
   - No IP addresses assigned to bridge interfaces

3. **USB-Focused**: Designed specifically for USB Ethernet adapters
   - Handles USB hotplug/disconnect events
   - Excludes system network interfaces
   - Validates USB device paths

4. **Operational Reliability**: Built for long-running capture sessions
   - Distinguishes between critical and informational issues
   - Progressive recovery with backoff
   - Clear status reporting

### What It Doesn't Do

- ❌ Modify kernel network settings (sysctl)
- ❌ Load kernel modules (br_netfilter, etc.)
- ❌ Touch your primary network interfaces
- ❌ Require additional Python packages
- ❌ Perform packet modification or filtering

## 📊 Monitoring Output

### Normal Operation
```
2024-01-01 10:00:00 - INFO - Starting enhanced interface monitoring
2024-01-01 10:00:05 - INFO - Status: ['eth1 is down (cable unplugged?)', 'eth2 is down (cable unplugged?)']
2024-01-01 10:00:15 - INFO - ✓ All interfaces UP - Bridge ready for packet capture!
```

### Recovery Scenarios
```
# USB adapter unplugged
2024-01-01 10:05:00 - WARNING - Critical issues (1): ['eth1 missing']
2024-01-01 10:05:15 - INFO - Attempting recovery (backoff: 2s)
2024-01-01 10:05:17 - INFO - Recovery successful

# Cable unplugged (no recovery needed)
2024-01-01 10:10:00 - INFO - Status: ['eth1 is down (cable unplugged?)']
```

## 🔧 Troubleshooting

### Common Issues

**"No USB interfaces detected"**
```bash
# Check if adapters are recognized
lsusb | grep -i ethernet
ip link show

# Verify system recognizes them as network interfaces
ls /sys/class/net/
```

**"Bridge setup failed"**
```bash
# Check permissions
sudo -v

# Clean up any existing bridges
sudo python3 capture_bridge.py --cleanup

# Check for conflicting bridges
bridge link show
```

**"Would interfere with SSH connection"**
```bash
# The script detected your SSH connection uses a USB adapter
# This is a safety feature - use a different network connection for SSH
# or exclude the SSH interface from detection
```

### Debug Mode

Enable detailed logging:
```bash
sudo python3 capture_bridge.py --debug --monitor
```

Check logs:
```bash
tail -f /tmp/simple_capture_bridge.log
```

## 🎯 Capture Examples

### Basic Packet Capture
```bash
# Capture all traffic
sudo tcpdump -i capture0 -w capture.pcap

# View live traffic
sudo tcpdump -i capture0 -n

# Capture specific protocols
sudo tcpdump -i capture0 'port 80 or port 443'
```

### Using Wireshark/tshark
```bash
# Live analysis with tshark
sudo tshark -i capture0

# Save to file with tshark
sudo tshark -i capture0 -w capture.pcapng

# GUI with Wireshark (if running X11)
sudo wireshark -i capture0
```

## 🔒 Security Considerations

- **Run as root**: Required for network interface manipulation
- **SSH safety**: Script detects and avoids SSH interfaces
- **No permanent changes**: All network changes are temporary
- **Clean shutdown**: Proper cleanup on exit prevents network issues
- **Minimal permissions**: Only modifies bridge and USB interfaces

## 🤝 Contributing

### Reporting Issues
Please include:
- Linux distribution and version
- USB adapter models
- Full command output with `--debug`
- Log file contents from `/tmp/simple_capture_bridge.log`

### Feature Requests
This tool intentionally maintains a minimal feature set for stability. New features should:
- Maintain system safety
- Support the core use case (packet capture)
- Not require additional dependencies

## 📄 License

This project is provided as-is for educational and legitimate security testing purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

---

**⚠️ Important**: This tool is designed for defensive security analysis and network troubleshooting. Always ensure you have proper authorization before monitoring network traffic.%
