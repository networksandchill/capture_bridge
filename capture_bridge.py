#!/usr/bin/env python3
"""
Robust USB Ethernet Bridge for Packet Capture
Enhanced with better error handling and fault tolerance
"""

import asyncio
import logging
import subprocess
import time
import glob
import os
import signal
import sys
import re
from typing import List, Optional

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/tmp/simple_capture_bridge.log')
        ]
    )
    return logging.getLogger(__name__)

class SimpleCaptureManager:
    def __init__(self, bridge_name="capture0"):
        self.bridge_name = bridge_name
        self.interfaces = []
        self.logger = setup_logging()
        self.monitoring = False
        self.setup_lock = None
        self.max_retries = 3
        self.retry_delay = 2

        # Setup cleanup on exit
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, cleaning up...")
        self.cleanup()
        sys.exit(0)

    def run_cmd(self, cmd, check=True, timeout=10):
        """Run command with timeout and return success/failure"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=check,
                timeout=timeout
            )
            if result.stdout:
                self.logger.debug(f"Command output: {result.stdout.strip()}")
            return True
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {cmd}")
            return False
        except subprocess.CalledProcessError as e:
            if check:  # Only log error if we expected success
                self.logger.error(f"Command failed: {cmd}")
                self.logger.error(f"Error: {e.stderr.strip() if e.stderr else str(e)}")
            return False

    def get_cmd_output(self, cmd, timeout=5) -> Optional[str]:
        """Get command output safely"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"Failed to get output for: {cmd} - {e}")
            return None

    def detect_usb_interfaces(self) -> List[str]:
        """Detect USB Ethernet interfaces with validation"""
        interfaces = []

        try:
            # Look for enx* interfaces (standard USB ethernet naming)
            enx_paths = glob.glob('/sys/class/net/enx*')
            for path in enx_paths:
                iface = os.path.basename(path)
                if self._validate_interface(iface):
                    interfaces.append(iface)

            # Look for eth* interfaces on USB
            eth_paths = glob.glob('/sys/class/net/eth*')
            for path in eth_paths:
                iface = os.path.basename(path)
                # Check multiple locations for USB device
                if self._is_usb_interface(iface):
                    if self._validate_interface(iface):
                        interfaces.append(iface)

            # Also check for usb* interfaces (some adapters use this) but exclude usb0
            usb_paths = glob.glob('/sys/class/net/usb*')
            for path in usb_paths:
                iface = os.path.basename(path)
                if iface != 'usb0' and self._validate_interface(iface):
                    interfaces.append(iface)

            # Remove duplicates and sort for consistency
            interfaces = sorted(list(set(interfaces)))
            self.logger.info(f"Detected USB interfaces: {interfaces}")

            if len(interfaces) < 2:
                self.logger.warning(f"Expected 2 USB ports, found {len(interfaces)}")
                # Don't return empty list immediately - might be timing issue
                if len(interfaces) == 0 and not hasattr(self, '_recursion_guard'):
                    time.sleep(1)  # Give USB time to enumerate
                    self._recursion_guard = True
                    result = self.detect_usb_interfaces()
                    delattr(self, '_recursion_guard')
                    return result

            return interfaces[:2]  # Take first 2

        except Exception as e:
            self.logger.error(f"Error detecting interfaces: {e}")
            return []

    def _is_usb_interface(self, iface: str) -> bool:
        """Check if interface is USB-based"""
        try:
            # Check uevent file
            uevent_path = f'/sys/class/net/{iface}/device/uevent'
            if os.path.exists(uevent_path):
                with open(uevent_path, 'r') as f:
                    content = f.read().lower()
                    if 'usb' in content:
                        return True

            # Check device path for USB
            device_path = f'/sys/class/net/{iface}/device'
            if os.path.exists(device_path):
                real_path = os.path.realpath(device_path)
                if '/usb' in real_path:
                    return True

            # Check if it starts with known USB prefixes
            if iface.startswith(('enx', 'usb')):
                return True

        except Exception as e:
            self.logger.debug(f"Error checking USB status for {iface}: {e}")

        return False

    def _validate_interface(self, iface: str) -> bool:
        """Validate that interface is real and accessible"""
        try:
            # Check if interface exists
            if not self.interface_exists(iface):
                return False

            # Check if we can read interface state
            state_file = f'/sys/class/net/{iface}/operstate'
            if os.path.exists(state_file):
                with open(state_file, 'r') as f:
                    state = f.read().strip()
                    # Interface should be down, up, or unknown (not 'notpresent')
                    if state == 'notpresent':
                        return False

            # Check if interface has a MAC address (real interface)
            addr_file = f'/sys/class/net/{iface}/address'
            if os.path.exists(addr_file):
                with open(addr_file, 'r') as f:
                    mac = f.read().strip()
                    # Check for valid MAC (not all zeros or all F's)
                    if mac in ['00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff']:
                        return False

            return True

        except Exception as e:
            self.logger.debug(f"Validation failed for {iface}: {e}")
            return False

    def interface_exists(self, interface: str) -> bool:
        """Check if interface exists and is accessible"""
        try:
            return os.path.exists(f'/sys/class/net/{interface}')
        except:
            return False

    def get_interface_state(self, interface: str) -> str:
        """Get interface operational state"""
        try:
            with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
                return f.read().strip()
        except:
            return "unknown"

    def wait_for_interface(self, interface: str, timeout: int = 5) -> bool:
        """Wait for interface to become available"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.interface_exists(interface) and self._validate_interface(interface):
                return True
            time.sleep(0.5)
        return False

    def setup_bridge(self) -> bool:
        """Setup transparent bridge with retry logic"""
        for attempt in range(self.max_retries):
            if attempt > 0:
                self.logger.info(f"Setup attempt {attempt + 1}/{self.max_retries}")
                time.sleep(self.retry_delay)

            if self._setup_bridge_internal():
                return True

            # Clean up failed attempt
            self.cleanup()

        self.logger.error(f"Bridge setup failed after {self.max_retries} attempts")
        return False

    def _setup_bridge_internal(self) -> bool:
        """Internal bridge setup logic"""
        try:
            self.logger.info("Starting bridge setup")

            # Detect USB interfaces with retry
            for _ in range(3):
                self.interfaces = self.detect_usb_interfaces()
                if len(self.interfaces) >= 2:
                    break
                time.sleep(1)

            if len(self.interfaces) < 2:
                self.logger.error(f"Insufficient USB interfaces: {self.interfaces}")
                return False

            self.logger.info(f"Using interfaces: {self.interfaces}")

            # Safety check - don't interfere with SSH
            if not self._check_ssh_safety():
                self.logger.error("Aborting - would interfere with SSH connection")
                return False

            # Validate interfaces before proceeding
            for iface in self.interfaces:
                if not self.wait_for_interface(iface):
                    self.logger.error(f"Interface {iface} not available")
                    return False

            # Clean up any existing bridge first
            self._cleanup_existing_bridges()

            # Create bridge
            self.logger.info(f"Creating bridge {self.bridge_name}")
            if not self.run_cmd(f"ip link add name {self.bridge_name} type bridge"):
                return False

            # Configure bridge for transparent operation
            bridge_config = [
                f"ip link set {self.bridge_name} type bridge stp_state 0",
                f"ip link set {self.bridge_name} type bridge ageing_time 0",
                f"ip link set {self.bridge_name} type bridge forward_delay 0",
                f"ip link set {self.bridge_name} type bridge max_age 0"
            ]

            for cmd in bridge_config:
                self.run_cmd(cmd, check=False)

            # Disable multicast snooping
            self._set_bridge_sysfs('multicast_snooping', '0')
            self._set_bridge_sysfs('multicast_querier', '0')
            self._set_bridge_sysfs('multicast_router', '0')

            # Configure each interface
            for interface in self.interfaces:
                if not self._configure_interface(interface):
                    self.logger.error(f"Failed to configure {interface}")
                    return False

            # Bring bridge up
            if not self.run_cmd(f"ip link set {self.bridge_name} up"):
                return False

            # Skip dangerous netfilter modifications

            # Wait for bridge to stabilize
            time.sleep(1)

            # Verify setup
            if not self._verify_setup():
                return False

            self.logger.info("Bridge setup completed successfully")
            self._show_capture_info()
            return True

        except Exception as e:
            self.logger.error(f"Bridge setup failed: {e}", exc_info=True)
            return False

    def _cleanup_existing_bridges(self):
        """Clean up any existing bridges"""
        # Delete our bridge
        self.run_cmd(f"ip link del {self.bridge_name}", check=False)

        # Clean up any other capture bridges
        for i in range(5):
            self.run_cmd(f"ip link del capture{i}", check=False)

    def _set_bridge_sysfs(self, setting: str, value: str):
        """Set bridge sysfs parameter safely"""
        path = f'/sys/class/net/{self.bridge_name}/bridge/{setting}'
        try:
            if os.path.exists(path):
                with open(path, 'w') as f:
                    f.write(value)
                self.logger.debug(f"Set {setting} = {value}")
        except Exception as e:
            self.logger.debug(f"Could not set {setting}: {e}")

    def _configure_interface(self, interface: str) -> bool:
        """Configure interface with validation"""
        try:
            self.logger.info(f"Configuring {interface}")

            # Verify interface still exists
            if not self.wait_for_interface(interface, timeout=3):
                self.logger.error(f"Interface {interface} disappeared")
                return False

            # Bring interface down first for clean state
            self.run_cmd(f"ip link set {interface} down", check=False)
            time.sleep(0.5)

            # Clear any existing master
            self.run_cmd(f"ip link set {interface} nomaster", check=False)

            # Double-check interface still exists before adding to bridge
            if not self.interface_exists(interface):
                self.logger.error(f"Interface {interface} disappeared during setup")
                return False

            # Add to bridge
            if not self.run_cmd(f"ip link set {interface} master {self.bridge_name}"):
                return False

            # Verify interface was added to bridge
            time.sleep(0.2)
            master = self.get_interface_master(interface)
            if master != self.bridge_name:
                self.logger.error(f"{interface} not properly added to bridge (master: {master})")
                return False

            # Enable promiscuous mode
            if not self.run_cmd(f"ip link set {interface} promisc on"):
                self.logger.warning(f"Failed to enable promiscuous mode on {interface}")

            # Skip aggressive offloading changes to avoid network disruption

            # Bring interface up
            if not self.run_cmd(f"ip link set {interface} up"):
                return False

            self.logger.info(f"Interface {interface} configured successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to configure {interface}: {e}", exc_info=True)
            return False

    def get_interface_master(self, interface: str) -> Optional[str]:
        """Get the master (bridge) of an interface"""
        try:
            master_path = f'/sys/class/net/{interface}/master'
            if os.path.exists(master_path):
                real_path = os.path.realpath(master_path)
                return os.path.basename(real_path)
        except:
            pass
        return None

    def _disable_offloading(self, interface: str):
        """Disable offloading features for packet capture"""
        offload_features = [
            'rx-checksumming off',
            'tx-checksumming off',
            'scatter-gather off',
            'tcp-segmentation-offload off',
            'udp-fragmentation-offload off',
            'generic-segmentation-offload off',
            'generic-receive-offload off',
            'large-receive-offload off',
            'rxvlan off',
            'txvlan off',
            'ntuple off',
            'rxhash off'
        ]

        for feature in offload_features:
            self.run_cmd(f"ethtool -K {interface} {feature}", check=False, timeout=2)

    def _check_ssh_safety(self):
        """Check if we might interfere with SSH connection"""
        try:
            # Get current SSH connection info
            output = self.get_cmd_output("who am i")
            if output and "(" in output:
                match = re.search(r'\(([^)]+)\)', output)
                if match:
                    ssh_ip = match.group(1)
                    self.logger.info(f"SSH connection from: {ssh_ip}")

                    # Find interface serving this IP
                    route_output = self.get_cmd_output(f"ip route get {ssh_ip}")
                    if route_output:
                        match = re.search(r'dev (\S+)', route_output)
                        if match:
                            ssh_iface = match.group(1)
                            if ssh_iface in self.interfaces:
                                self.logger.error(f"DANGER: Interface {ssh_iface} is used for SSH!")
                                return False
            return True
        except Exception as e:
            self.logger.warning(f"SSH safety check failed: {e}")
            return True  # Proceed with caution

    def _verify_setup(self) -> bool:
        """Comprehensive bridge verification"""
        try:
            # Check bridge exists
            if not self.interface_exists(self.bridge_name):
                self.logger.error("Bridge does not exist")
                return False

            # Check bridge is admin up
            output = self.get_cmd_output(f"ip link show {self.bridge_name}")
            if not output:
                self.logger.error("Cannot query bridge status")
                return False

            # Look for UP flag (admin state)
            if not re.search(r'<.*UP.*>', output):
                self.logger.error(f"Bridge is not administratively UP")
                return False

            # Check operational state
            state = self.get_interface_state(self.bridge_name)
            self.logger.info(f"Bridge operational state: {state}")

            # Check interfaces are in bridge
            verified_count = 0
            for interface in self.interfaces:
                master = self.get_interface_master(interface)
                if master == self.bridge_name:
                    verified_count += 1
                    self.logger.debug(f"{interface} verified in bridge")
                else:
                    self.logger.error(f"{interface} not in bridge (master: {master})")

            if verified_count != len(self.interfaces):
                self.logger.error(f"Only {verified_count}/{len(self.interfaces)} interfaces verified")
                return False

            # Additional check using bridge command
            output = self.get_cmd_output("bridge link show")
            if output:
                for interface in self.interfaces:
                    if interface not in output:
                        self.logger.warning(f"{interface} not shown in bridge link output")

            self.logger.info("Bridge verification passed")
            return True

        except Exception as e:
            self.logger.error(f"Verification failed: {e}", exc_info=True)
            return False

    def _show_capture_info(self):
        """Show capture information"""
        print(f"\n{'='*40}")
        print(f"    TRANSPARENT BRIDGE READY")
        print(f"{'='*40}")
        print(f"Bridge Name: {self.bridge_name}")
        print(f"Interfaces:  {self.interfaces[0]} <--> {self.interfaces[1]}")
        print(f"")
        print(f"Capture Commands:")
        print(f"  tcpdump -i {self.bridge_name} -w capture.pcap")
        print(f"  tcpdump -i {self.bridge_name} -n")
        print(f"  tshark -i {self.bridge_name}")
        print(f"")
        print(f"Physical Setup:")
        print(f"  [Device A] <-> [{self.interfaces[0]}] <-> [BRIDGE] <-> [{self.interfaces[1]}] <-> [Device B]")
        print(f"{'='*40}\n")

    async def monitor(self):
        """Enhanced monitoring with better recovery"""
        if not self.setup_lock:
            self.setup_lock = asyncio.Lock()

        self.monitoring = True
        self.logger.info("Starting enhanced interface monitoring")

        consecutive_failures = 0
        recovery_backoff = 2
        had_issues = False

        while self.monitoring:
            try:
                await asyncio.sleep(5)  # Check interval

                # Check interface health
                critical_issues, info_issues = self._check_health()

                # Check if all interfaces are up (no critical issues and no "down" info issues)
                all_up = not critical_issues and not any("is down" in issue for issue in info_issues)

                # Check if we just recovered from any issues (critical or info)
                if had_issues and all_up:
                    self.logger.info("✓ All interfaces UP - Bridge ready for packet capture!")
                    had_issues = False

                # Track if we have any issues at all
                if critical_issues or info_issues:
                    had_issues = True

                # Log informational issues without triggering recovery
                if info_issues:
                    self.logger.info(f"Status: {info_issues}")

                if critical_issues:
                    consecutive_failures += 1
                    self.logger.warning(f"Critical issues ({consecutive_failures}): {critical_issues}")

                    # Progressive recovery attempts
                    if consecutive_failures >= 3:
                        self.logger.info(f"Attempting recovery (backoff: {recovery_backoff}s)")

                        # Check for new USB interfaces
                        current_interfaces = self.detect_usb_interfaces()

                        if len(current_interfaces) >= 2:
                            self.logger.info("Found sufficient interfaces for recovery")

                            # Use lock if available (async context)
                            if self.setup_lock:
                                async with self.setup_lock:
                                    self._perform_recovery()
                            else:
                                self._perform_recovery()

                            consecutive_failures = 0
                            recovery_backoff = 2
                        else:
                            self.logger.info(f"Waiting for USB interfaces ({len(current_interfaces)}/2)")
                            recovery_backoff = min(recovery_backoff * 2, 60)

                        await asyncio.sleep(recovery_backoff)
                else:
                    # System healthy
                    if consecutive_failures > 0:
                        self.logger.info("System recovered - all checks passing")
                    consecutive_failures = 0
                    recovery_backoff = 2

            except Exception as e:
                self.logger.error(f"Monitoring error: {e}", exc_info=True)
                await asyncio.sleep(10)

    def _check_health(self):
        """Check system health and return critical and non-critical issues"""
        critical_issues = []
        info_issues = []

        try:
            # Check bridge exists
            if not self.interface_exists(self.bridge_name):
                critical_issues.append("Bridge missing")
                return critical_issues, info_issues  # Critical - no point checking more

            # Check each interface
            for iface in self.interfaces:
                if not self.interface_exists(iface):
                    critical_issues.append(f"{iface} missing")
                else:
                    # Check if still in bridge
                    master = self.get_interface_master(iface)
                    if master != self.bridge_name:
                        critical_issues.append(f"{iface} not in bridge")

                    # Check if interface is up (this is informational only)
                    state = self.get_interface_state(iface)
                    if state == "down":
                        info_issues.append(f"{iface} is down (cable unplugged?)")

        except Exception as e:
            critical_issues.append(f"Health check error: {e}")

        return critical_issues, info_issues

    def _perform_recovery(self):
        """Perform recovery operation"""
        try:
            self.logger.info("Starting recovery procedure")
            self._cleanup_bridge_only()
            time.sleep(2)

            if self.setup_bridge():
                self.logger.info("Recovery successful")
            else:
                self.logger.error("Recovery failed")
        except Exception as e:
            self.logger.error(f"Recovery error: {e}", exc_info=True)

    def _cleanup_bridge_only(self):
        """Clean up bridge without stopping monitoring"""
        try:
            self.logger.info("Starting bridge cleanup for recovery")

            # Find all interfaces in any bridge
            all_interfaces = set()

            # Method 1: Check configured interfaces
            all_interfaces.update(self.interfaces)

            # Method 2: Find via sysfs
            try:
                bridge_path = f'/sys/class/net/{self.bridge_name}/brif/'
                if os.path.exists(bridge_path):
                    all_interfaces.update(os.listdir(bridge_path))
            except:
                pass

            # Method 3: Parse ip link output
            output = self.get_cmd_output("ip link show")
            if output:
                for line in output.split('\n'):
                    if f'master {self.bridge_name}' in line:
                        match = re.search(r'^\d+:\s+(\S+)[@:]', line)
                        if match:
                            all_interfaces.add(match.group(1))

            # Method 4: Check all USB interfaces
            all_interfaces.update(self.detect_usb_interfaces())

            # Clean up all found interfaces
            for interface in all_interfaces:
                if self.interface_exists(interface):
                    self.run_cmd(f"ip link set {interface} down", check=False)
                    self.run_cmd(f"ip link set {interface} nomaster", check=False)
                    self.run_cmd(f"ip link set {interface} promisc off", check=False)
                    self.logger.debug(f"Cleaned up {interface}")

            # Delete bridges
            self._cleanup_existing_bridges()

            self.logger.info("Bridge cleanup for recovery completed")

        except Exception as e:
            self.logger.error(f"Bridge cleanup error: {e}", exc_info=True)

    def cleanup(self):
        """Comprehensive cleanup"""
        try:
            self.monitoring = False
            self.logger.info("Starting comprehensive cleanup")

            # Find all interfaces in any bridge
            all_interfaces = set()

            # Method 1: Check configured interfaces
            all_interfaces.update(self.interfaces)

            # Method 2: Find via sysfs
            try:
                bridge_path = f'/sys/class/net/{self.bridge_name}/brif/'
                if os.path.exists(bridge_path):
                    all_interfaces.update(os.listdir(bridge_path))
            except:
                pass

            # Method 3: Parse ip link output
            output = self.get_cmd_output("ip link show")
            if output:
                for line in output.split('\n'):
                    if f'master {self.bridge_name}' in line:
                        match = re.search(r'^\d+:\s+(\S+)[@:]', line)
                        if match:
                            all_interfaces.add(match.group(1))

            # Method 4: Check all USB interfaces
            all_interfaces.update(self.detect_usb_interfaces())

            # Clean up all found interfaces
            for interface in all_interfaces:
                if self.interface_exists(interface):
                    self.run_cmd(f"ip link set {interface} down", check=False)
                    self.run_cmd(f"ip link set {interface} nomaster", check=False)
                    self.run_cmd(f"ip link set {interface} promisc off", check=False)
                    self.logger.debug(f"Cleaned up {interface}")

            # Delete bridges
            self._cleanup_existing_bridges()

            self.logger.info("Cleanup completed")

        except Exception as e:
            self.logger.error(f"Cleanup error: {e}", exc_info=True)

    def show_status(self):
        """Show detailed status"""
        print(f"\n{'='*50}")
        print(f"         BRIDGE STATUS REPORT")
        print(f"{'='*50}")

        # USB interfaces
        detected = self.detect_usb_interfaces()
        print(f"\nUSB Interfaces Detected: {len(detected)}")
        for iface in detected:
            state = self.get_interface_state(iface)
            master = self.get_interface_master(iface)
            print(f"  • {iface}: state={state}, master={master or 'none'}")

        # Bridge status
        print(f"\nBridge: {self.bridge_name}")
        if self.interface_exists(self.bridge_name):
            state = self.get_interface_state(self.bridge_name)
            print(f"  Status: EXISTS (operational: {state})")

            # Show bridge members from sysfs
            bridge_path = f'/sys/class/net/{self.bridge_name}/brif/'
            if os.path.exists(bridge_path):
                members = os.listdir(bridge_path)
                print(f"  Members: {', '.join(members) if members else 'none'}")

            # Show admin state
            output = self.get_cmd_output(f"ip link show {self.bridge_name}")
            if output and re.search(r'<.*UP.*>', output):
                print(f"  Admin: UP")
            else:
                print(f"  Admin: DOWN")
        else:
            print(f"  Status: NOT FOUND")

        # Health check
        print(f"\nHealth Check:")
        issues = self._check_health()
        if issues:
            for issue in issues:
                print(f"  ⚠ {issue}")
        else:
            print(f"  ✓ All checks passed")

        print(f"{'='*50}\n")

async def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Robust USB Ethernet Bridge for Packet Capture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Setup bridge and exit
  %(prog)s --monitor          # Setup and monitor for changes
  %(prog)s --status           # Show current status
  %(prog)s --cleanup          # Clean up and exit
  %(prog)s --bridge br0       # Use custom bridge name
        """
    )
    parser.add_argument('--bridge', default='capture0', help='Bridge name (default: capture0)')
    parser.add_argument('--monitor', action='store_true', help='Monitor for changes continuously')
    parser.add_argument('--cleanup', action='store_true', help='Clean up and exit')
    parser.add_argument('--status', action='store_true', help='Show detailed status')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    manager = SimpleCaptureManager(args.bridge)

    try:
        if args.cleanup:
            manager.cleanup()
            return

        if args.status:
            manager.show_status()
            return

        # Setup bridge
        if not manager.setup_bridge():
            print("ERROR: Bridge setup failed - check logs at /tmp/simple_capture_bridge.log")
            sys.exit(1)

        if args.monitor:
            print("Monitoring mode active - Press Ctrl+C to stop")
            await manager.monitor()
        else:
            print("\nBridge is running. Use --monitor flag to enable auto-recovery.")
            print("Press Ctrl+C to stop and cleanup.\n")
            # Keep running until interrupted
            try:
                await asyncio.Event().wait()
            except:
                pass

    except KeyboardInterrupt:
        print("\n\nShutting down gracefully...")
    except Exception as e:
        print(f"\nERROR: {e}")
        manager.logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        manager.cleanup()

if __name__ == '__main__':
    # Ensure we're running as root
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (use sudo)")
        sys.exit(1)

    asyncio.run(main())
