#!/usr/bin/env python3
"""
Secure Command Receiver with Verification and Replay Protection
"""

import socket
import threading
import json
import time
from crypto_manager import CryptoManager

class CommandReceiver:
    def __init__(self, crypto_manager, drone_main):
        self.crypto_mgr = crypto_manager
        self.drone = drone_main
        self.running = False
        self.thread = None
        
        # Command statistics for anomaly detection
        self.command_stats = {
            'total_received': 0,
            'valid_commands': 0,
            'rejected_commands': 0,
            'last_command_time': 0
        }
        
    def start(self):
        """Start command receiver thread"""
        self.running = True
        self.thread = threading.Thread(target=self._listen_loop)
        self.thread.daemon = True
        self.thread.start()
        print("Command receiver started")
        
    def stop(self):
        """Stop command receiver"""
        self.running = False
        if self.thread:
            self.thread.join()
            
    def _listen_loop(self):
        """Main listening loop for commands"""
        # Simulate listening on multiple ports for different bands
        ports = [10001, 10002, 10003]  # 2.4GHz, 5GHz, 900MHz
        
        while self.running:
            # This is a simulation - in real implementation, use actual socket listening
            # For now, we'll simulate command reception for testing
            time.sleep(2)
            
    def process_command(self, command_data):
        """Process and verify an incoming command"""
        self.command_stats['total_received'] += 1
        
        # Verify cryptographic signature
        if not self.crypto_mgr.verify_signature(command_data):
            print("Command signature verification failed")
            self.command_stats['rejected_commands'] += 1
            return False
            
        # Check for replay attacks
        replay_ok, replay_msg = self.crypto_mgr.check_replay_attack(command_data)
        if not replay_ok:
            print(f"Replay attack detected: {replay_msg}")
            self.command_stats['rejected_commands'] += 1
            return False
            
        # Rate limiting check
        if not self._check_rate_limit():
            print("Rate limit exceeded - command rejected")
            self.command_stats['rejected_commands'] += 1
            return False
            
        # Execute the command
        try:
            self.drone.execute_command(
                command_data['command_type'],
                command_data.get('parameters', {})
            )
            self.command_stats['valid_commands'] += 1
            self.command_stats['last_command_time'] = time.time()
            return True
            
        except Exception as e:
            print(f"Error executing command: {e}")
            return False
            
    def _check_rate_limit(self):
        """Check if command rate is within limits"""
        current_time = time.time()
        time_since_last = current_time - self.command_stats['last_command_time']
        
        # Allow max 10 commands per second
        if time_since_last < 0.1:  # 100ms between commands
            return False
            
        return True
        
    def get_stats(self):
        """Get command processing statistics"""
        return self.command_stats.copy()