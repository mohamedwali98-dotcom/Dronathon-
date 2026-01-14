#!/usr/bin/env python3
"""
Main Ground Station Control Software
Handles mission planning, drone management, and security monitoring
"""

import json
import time
import threading
from command_sender import CommandSender
from crypto_manager import CryptoManager
from gui_dashboard import GUIDashboard

class GroundStation:
    def __init__(self):
        self.crypto_mgr = CryptoManager("keys/gs_private.pem", "keys/gs_public.pem")
        self.command_sender = CommandSender(self.crypto_mgr)
        self.gui = GUIDashboard(self)
        self.active_drones = {}
        self.mission_plans = {}
        
    def start_mission(self, mission_data):
        """Start a new rescue mission"""
        mission_id = f"mission_{int(time.time())}"
        self.mission_plans[mission_id] = mission_data
        
        # Send mission initialization commands to all drones
        init_commands = [
            self._create_command("initialize_mission", mission_data),
            self._create_command("load_ai_model", {"model_type": "victim_detection"}),
            self._create_command("enable_autocalibration", {})
        ]
        
        for drone_id in self.active_drones:
            for cmd in init_commands:
                self.command_sender.send_command(drone_id, cmd)
                
        self.gui.update_mission_status(mission_id, "ACTIVE")
        
    def _create_command(self, command_type, parameters):
        """Create a signed command packet"""
        return {
            "command_id": f"cmd_{int(time.time()*1000)}",
            "timestamp": time.time(),
            "nonce": self.crypto_mgr.generate_nonce(),
            "sequence_num": self.command_sender.get_next_sequence(),
            "command_type": command_type,
            "parameters": parameters
        }
        
    def add_drone(self, drone_id, public_key):
        """Register a new drone with the ground station"""
        self.active_drones[drone_id] = {
            'public_key': public_key,
            'status': 'CONNECTED',
            'last_heartbeat': time.time()
        }
        self.gui.update_drone_status(drone_id, "CONNECTED")
        
    def handle_telemetry(self, drone_id, telemetry_data):
        """Process incoming telemetry from drones"""
        if drone_id in self.active_drones:
            self.active_drones[drone_id].update({
                'last_heartbeat': time.time(),
                'telemetry': telemetry_data
            })
            self.gui.update_telemetry(drone_id, telemetry_data)
            
    def run(self):
        """Main ground station loop"""
        print("Starting Ground Station...")
        self.gui.start()
        
        # Start background monitoring
        monitor_thread = threading.Thread(target=self._monitor_drones)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Shutting down Ground Station...")

    def _monitor_drones(self):
        """Background thread to monitor drone health"""
        while True:
            current_time = time.time()
            for drone_id, drone_info in self.active_drones.items():
                if current_time - drone_info['last_heartbeat'] > 10:  # 10 second timeout
                    self.gui.update_drone_status(drone_id, "LOST_CONNECTION")
                    # Trigger failover procedures
                    self._handle_drone_timeout(drone_id)
            time.sleep(5)
            
    def _handle_drone_timeout(self, drone_id):
        """Handle drone communication timeout"""
        print(f"Drone {drone_id} connection lost - initiating failover")
        # Could trigger mesh network activation or other drone assistance

if __name__ == "__main__":
    gs = GroundStation()
    gs.run()