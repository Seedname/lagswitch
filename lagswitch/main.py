#!/usr/bin/env python3
import argparse
import os
import socket
import select
import time
import threading
import psutil
import logging
import sys
import platform
from collections import defaultdict

# Create package structure
__version__ = "0.1.0"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Connection:
    def __init__(self, client_sock=None, remote_sock=None, pid=None, local_addr=None, remote_addr=None):
        self.client_sock = client_sock
        self.remote_sock = remote_sock
        self.pid = pid
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.client_buffer = b''
        self.remote_buffer = b''
        self.last_active = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connection_id = f"{id(self)}"

class RateLimiter:
    def __init__(self, rate_limit_kbps):
        self.rate_limit_bytes_per_sec = rate_limit_kbps * 125  # Convert kbps to bytes/sec
        self.traffic_counters = defaultdict(int)
        self.last_check = defaultdict(lambda: time.time())
        self.lock = threading.Lock()

    def can_send(self, connection_id, bytes_to_send):
        with self.lock:
            now = time.time()
            time_diff = now - self.last_check[connection_id]
            
            if time_diff > 0:
                # Reset counter based on elapsed time
                allowed_bytes = self.rate_limit_bytes_per_sec * time_diff
                self.traffic_counters[connection_id] = max(0, self.traffic_counters[connection_id] - allowed_bytes)
                self.last_check[connection_id] = now
            
            # Check if sending these bytes would exceed rate limit
            if self.traffic_counters[connection_id] + bytes_to_send <= self.rate_limit_bytes_per_sec:
                self.traffic_counters[connection_id] += bytes_to_send
                return True
            return False

    def wait_time(self, connection_id, bytes_to_send):
        with self.lock:
            current_usage = self.traffic_counters[connection_id]
            if current_usage == 0:
                return 0
            
            # Calculate time needed to clear enough bandwidth
            bytes_needed = bytes_to_send - (self.rate_limit_bytes_per_sec - current_usage)
            if bytes_needed <= 0:
                return 0
            
            return bytes_needed / self.rate_limit_bytes_per_sec

class ProxyServer:
    def __init__(self, target_executable, rate_limit_kbps):
        # Handle cross-platform executable naming
        self.target_executable = self._normalize_target_name(target_executable)
        self.rate_limiter = RateLimiter(rate_limit_kbps)
        self.connections = {}  # key: connection id, value: Connection instance
        self.running = False
        self.pid_cache = {}
        self.connection_cache = {}
        self.system = platform.system().lower()
    
    def _normalize_target_name(self, executable):
        """Normalize target executable name for cross-platform compatibility."""
        if not executable:
            return None
            
        executable = executable.lower()
        
        # If no extension and we're on Windows, add .exe
        if platform.system().lower() == 'windows' and not executable.endswith('.exe'):
            executable += '.exe'
            
        return executable
    
    def get_process_name(self, process):
        """Get process name in a cross-platform way."""
        try:
            if platform.system().lower() == 'windows':
                return process.name().lower()
            else:
                # On Unix-like systems, prefer the full path
                return os.path.basename(process.exe()).lower()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return None

    def is_target_executable(self, pid):
        """Check if the PID belongs to the target executable."""
        if pid is None or self.target_executable is None:
            return False
            
        if pid in self.pid_cache:
            return self.pid_cache[pid]
            
        try:
            process = psutil.Process(pid)
            
            # First try the executable path
            try:
                executable = os.path.basename(process.exe()).lower()
                if self.target_executable in executable:
                    self.pid_cache[pid] = True
                    return True
            except (psutil.AccessDenied, FileNotFoundError):
                pass
                
            # If that fails, try the process name
            try:
                name = process.name().lower()
                if self.target_executable in name:
                    self.pid_cache[pid] = True
                    return True
            except psutil.AccessDenied:
                pass
                
            # If all checks failed
            self.pid_cache[pid] = False
            return False
            
        except (psutil.NoSuchProcess, psutil.Error):
            self.pid_cache[pid] = False
            return False

    def get_connection_key(self, laddr, raddr):
        """Generate a unique key for a connection based on addresses."""
        if not laddr or not raddr:
            return None
        return f"{laddr[0]}:{laddr[1]}-{raddr[0]}:{raddr[1]}"

    def apply_rate_limit_to_connection(self, conn_key, data_size):
        """Apply rate limiting to a connection."""
        # This is a simplified example - in a real implementation,
        # you would need to intercept and delay actual network packets
        if not self.rate_limiter.can_send(conn_key, data_size):
            wait_time = self.rate_limiter.wait_time(conn_key, data_size)
            if wait_time > 0:
                logger.debug(f"Rate limiting connection {conn_key} - delaying {wait_time:.2f}s")
                time.sleep(wait_time)
        return True

    def monitor_connections(self):
        """
        Continuously polls the system's network connections to find connections
        belonging to the target process.
        """
        while self.running:
            try:
                # Poll all current TCP connections
                connections = psutil.net_connections(kind='tcp')
                
                # Track target process connections
                target_connections = []
                
                for conn in connections:
                    pid = conn.pid
                    if not self.is_target_executable(pid):
                        continue
                        
                    # We found a connection for our target process
                    if not conn.laddr or not conn.raddr:
                        continue  # Skip connections without addresses
                    
                    laddr = conn.laddr
                    raddr = conn.raddr
                    
                    # Create a unique key for this connection
                    conn_key = self.get_connection_key(laddr, raddr)
                    if not conn_key:
                        continue
                        
                    # Track new connections we haven't seen before
                    if conn_key not in self.connection_cache:
                        logger.info(f"New target connection (PID: {pid}): {laddr.ip}:{laddr.port} -> {raddr.ip}:{raddr.port}")
                        
                        # Create a new connection record
                        connection = Connection(
                            pid=pid,
                            local_addr=laddr,
                            remote_addr=raddr
                        )
                        
                        self.connection_cache[conn_key] = connection
                    
                    # Mark as active for this polling cycle
                    target_connections.append(conn_key)
                
                # Remove connections that are no longer active
                for key in list(self.connection_cache.keys()):
                    if key not in target_connections:
                        logger.info(f"Connection closed: {key}")
                        del self.connection_cache[key]
                
                # Here we'll log active connections periodically
                if self.connection_cache:
                    active_count = len(self.connection_cache)
                    logger.debug(f"Active target connections: {active_count}")
                
            except Exception as e:
                logger.error(f"Error monitoring connections: {str(e)}")
            
            time.sleep(2)  # Poll every 2 seconds

    def network_interception(self):
        """
        In a real implementation, this method would intercept and manipulate network traffic.
        This is a placeholder for demonstration - actual network interception would require
        OS-specific methods like WinDivert on Windows or pf/ipfw on macOS.
        """
        logger.info("Starting network interception...")
        
        while self.running:
            # For each active connection, we would intercept and rate-limit traffic
            for conn_key, connection in list(self.connection_cache.items()):
                # Simulating traffic for demonstration purposes
                simulated_traffic_size = 1024  # 1KB
                
                # Apply rate limiting
                self.apply_rate_limit_to_connection(conn_key, simulated_traffic_size)
            
            time.sleep(0.1)  # Check frequently but don't burn CPU

    def start(self):
        self.running = True
        system_name = platform.system()
        logger.info(f"Starting lagswtich on {system_name} for target: {self.target_executable}")
        logger.info(f"Rate limit: {self.rate_limiter.rate_limit_bytes_per_sec/1000:.2f} KB/s")
        
        # This is a monitoring demo only - not actually intercepting traffic
        logger.warning("NOTE: This is a monitoring demonstration only!")
        logger.warning("      Actual traffic interception requires admin/root privileges")
        logger.warning("      and platform-specific packet capture/redirection.")
        
        try:
            # Thread to monitor connections
            monitor_thread = threading.Thread(target=self.monitor_connections, daemon=True)
            monitor_thread.start()
            
            # Thread to simulate network interception (in a real implementation)
            intercept_thread = threading.Thread(target=self.network_interception, daemon=True)
            intercept_thread.start()
            
            # Main loop
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Shutting down lagswtich...")
        finally:
            self.running = False

def main():
    parser = argparse.ArgumentParser(description='Application-specific network rate limiting tool (lagswtich)')
    parser.add_argument('--target', required=True, help='Target executable name (e.g., chrome, firefox.exe)')
    parser.add_argument('--rate-limit', type=int, default=100, help='Rate limit in kbps for target executable')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    if os.geteuid() == 0 if hasattr(os, 'geteuid') else False:
        logger.info("Running with elevated privileges")
    else:
        logger.warning("Not running with elevated privileges - some features may be limited")
    
    proxy = ProxyServer(args.target, args.rate_limit)
    proxy.start()

if __name__ == "__main__":
    main()