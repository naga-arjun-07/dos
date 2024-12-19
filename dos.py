import os
import sys
import time
import json
import logging
import socket
import threading
import traceback
from typing import Dict, Set
from concurrent.futures import ThreadPoolExecutor

class DoSPreventionSystem:
    def __init__(self, verbose: bool = True):  # Fixed initialization method name
        """Initialize DoS Prevention System with debug capabilities"""
        # Configuration Parameters
        self.MAX_CONNECTIONS = 20  # Lowered for easier testing
        self.TIME_WINDOW = 60
        self.BLOCK_DURATION = 300
        
        # Debug and Logging Setup
        self.verbose = verbose
        self._setup_logging()
        
        # Connection Tracking
        self.connection_log: Dict[str, Dict] = {}
        self.blocked_ips: Set[str] = set()
        
        # Synchronization
        self._lock = threading.Lock()

    def _setup_logging(self):
        """
        Configure logging with console and file output
        """
        # Ensure logs directory exists
        os.makedirs('logs', exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('logs/dos_prevention.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Debug information
        if self.verbose:
            print("\n=== DoS Prevention System Initialized ===")
            print(f"Max Connections: {self.MAX_CONNECTIONS}")
            print(f"Time Window: {self.TIME_WINDOW} seconds")
            print(f"Block Duration: {self.BLOCK_DURATION} seconds")
            print("========================================\n")

    def detect_connection(self, ip_address: str, port: int) -> bool:
        """
        Detect and analyze potential DoS attack with detailed logging
        Returns True if connection is allowed, False if blocked
        """
        current_time = time.time()
        
        try:
            # Validate IP address
            if not self._validate_ip(ip_address):
                self.logger.warning(f"Invalid IP detected: {ip_address}")
                return False
            
            with self._lock:
                # Purge old connection logs
                self._purge_old_logs(current_time)
                
                # Check if IP is already blocked
                if ip_address in self.blocked_ips:
                    self._log_block_attempt(ip_address, port)
                    return False
                
                # Initialize IP tracking if not exists
                if ip_address not in self.connection_log:
                    self.connection_log[ip_address] = {
                        'connections': [],
                        'ports': set()
                    }
                
                # Track connection details
                log_entry = self.connection_log[ip_address]
                log_entry['connections'].append(current_time)
                log_entry['ports'].add(port)
                
                # Debug output
                if self.verbose:
                    self._print_connection_state(ip_address, log_entry)
                
                # Analyze connection frequency
                if len(log_entry['connections']) > self.MAX_CONNECTIONS:
                    self._trigger_mitigation(ip_address)
                    return False
                
            return True
        
        except Exception as e:
            self.logger.error(f"Connection detection error: {str(e)}")
            traceback.print_exc()
            return False

    def _print_connection_state(self, ip_address: str, log_entry: Dict):
        """Helper method to print connection state"""
        print(f"\nConnection State for {ip_address}:")
        print(f"Total Connections: {len(log_entry['connections'])}")
        print(f"Ports Used: {sorted(log_entry['ports'])}")

    def _validate_ip(self, ip_address: str) -> bool:
        """
        Validate IP address format and check for restricted ranges
        """
        try:
            socket.inet_aton(ip_address)
            
            # Reject private/local IP ranges
            if ip_address.startswith(('10.', '172.', '192.168.', '127.')):
                if self.verbose:
                    print(f"Rejected private/local IP: {ip_address}")
                return False
            
            return True
        except (socket.error, TypeError):
            if self.verbose:
                print(f"Invalid IP format: {ip_address}")
            return False

    def _purge_old_logs(self, current_time: float):
        """Remove connection logs older than the time window"""
        for ip, log_entry in list(self.connection_log.items()):
            log_entry['connections'] = [
                timestamp for timestamp in log_entry['connections']
                if current_time - timestamp <= self.TIME_WINDOW
            ]
            
            if not log_entry['connections']:
                del self.connection_log[ip]

    def _trigger_mitigation(self, ip_address: str):
        """Apply mitigation strategies for suspicious IPs"""
        self._block_ip(ip_address)

    def _block_ip(self, ip_address: str):
        """Block an IP address temporarily"""
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            
            block_message = f"BLOCKED IP: {ip_address}"
            self.logger.warning(block_message)
            
            if self.verbose:
                print("\n" + "=" * 40)
                print(block_message)
                print(f"Current Blocked IPs: {len(self.blocked_ips)}")
                print("=" * 40 + "\n")
            
            # Schedule IP unblocking
            threading.Timer(
                self.BLOCK_DURATION, 
                self._unblock_ip, 
                args=[ip_address]
            ).start()

    def _unblock_ip(self, ip_address: str):
        """Remove IP from blocked list after duration"""
        with self._lock:
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                
                unblock_message = f"UNBLOCKED IP: {ip_address}"
                self.logger.info(unblock_message)
                
                if self.verbose:
                    print("\n" + "=" * 40)
                    print(unblock_message)
                    print("=" * 40 + "\n")

    def _log_block_attempt(self, ip_address: str, port: int):
        """Log attempts to connect from a blocked IP"""
        block_attempt_msg = f"Block Attempt - IP: {ip_address}, Port: {port}"
        self.logger.warning(block_attempt_msg)
        
        if self.verbose:
            print(block_attempt_msg)

    def simulate_attacks(self):
        """Simulate various connection scenarios for testing"""
        test_scenarios = [
            ('8.8.8.8', 80),     # Public IP for testing
            ('8.8.8.8', 443),    # Multiple ports from same IP
            ('1.2.3.4', 22),     # Another public IP
        ]
        
        print("\n=== Starting Attack Simulation ===")
        for _ in range(15):  # Simulate multiple connection attempts
            for ip, port in test_scenarios:
                result = self.detect_connection(ip, port)
                print(f"Connection from {ip}:{port} - {'Allowed' if result else 'Blocked'}")
                time.sleep(0.5)
        
        print("\n=== Simulation Complete ===")
        print(f"Final Blocked IPs: {self.blocked_ips}\n")

def main():
    # Initialize with verbose output
    dos_system = DoSPreventionSystem(verbose=True)
    
    # Run attack simulation
    dos_system.simulate_attacks()

if __name__ == "__main__":  # Fixed main check
    main()