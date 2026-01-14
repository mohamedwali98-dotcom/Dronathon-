#!/usr/bin/env python3
"""
Main Drone Control Software
Runs on Raspberry Pi 4 with camera, IMU, LiDAR, and WiFi
"""

import time
import threading
import json
from command_receiver import CommandReceiver
from crypto_manager import CryptoManager
from security_monitor import SecurityMonitor
from navigation_fallback import NavigationSystem
from anomaly_detector import AnomalyDetector
from ai_autocalibration import AIAutocalibration

class DroneMain:
    def __init__(self, drone_id="DRONE_001"):
        self.drone_id = drone_id
        self.is_armed = False
        self.current_mission = None
        self.telemetry_data = {}
        
        # Initialize subsystems
        print(f"Initializing {drone_id}...")
        self.crypto_mgr = CryptoManager(f"keys/drone_private.pem", f"keys/drone_public.pem")
        self.navigation = NavigationSystem()
        self.anomaly_detector = AnomalyDetector()
        self.autocalibration = AIAutocalibration()
        self.security_monitor = SecurityMonitor(self)
        self.command_receiver = CommandReceiver(self.crypto_mgr, self)
        
        # Load AI models
        self._load_ai_models()
        
    def _load_ai_models(self):
        """Load pre-trained AI models"""
        print("Loading AI models...")
        try:
            # Load victim detection model
            self.anomaly_detector.load_model("models/victim_detection_model.pth")
            
            # Load autocalibration model
            self.autocalibration.load_model("models/autocalibration_model.pth")
            
            print("AI models loaded successfully")
        except Exception as e:
            print(f"Error loading AI models: {e}")
            
    def arm_drone(self):
        """Arm the drone for flight"""
        if self.navigation.initialize_sensors():
            self.is_armed = True
            self.autocalibration.start_calibration()
            print("Drone armed and ready")
            return True
        return False
        
    def execute_command(self, command_type, parameters):
        """Execute a verified command"""
        print(f"Executing command: {command_type}")
        
        if command_type == "initialize_mission":
            self.current_mission = parameters
            self._start_mission_execution()
            
        elif command_type == "takeoff":
            if self.is_armed:
                self.navigation.takeoff(parameters.get('altitude', 10))
                
        elif command_type == "goto_waypoint":
            self.navigation.fly_to_waypoint(parameters)
            
        elif command_type == "enable_autocalibration":
            self.autocalibration.enable()
            
        elif command_type == "emergency_land":
            self._emergency_land()
            
        elif command_type == "load_ai_model":
            self._load_ai_models()
            
        else:
            print(f"Unknown command: {command_type}")
            
    def _start_mission_execution(self):
        """Start mission execution"""
        if not self.current_mission:
            return
            
        mission_thread = threading.Thread(target=self._run_mission)
        mission_thread.daemon = True
        mission_thread.start()
        
    def _run_mission(self):
        """Main mission execution loop"""
        print("Starting mission execution...")
        
        while self.current_mission and self.is_armed:
            # Get sensor data
            sensor_data = self.navigation.get_sensor_data()
            
            # Run victim detection
            detections = self.anomaly_detector.detect_victims(sensor_data)
            
            # Update autocalibration
            self.autocalibration.update(sensor_data)
            
            # Run anomaly detection
            anomalies = self.anomaly_detector.detect_anomalies(sensor_data)
            
            # Update telemetry
            self._update_telemetry(sensor_data, detections, anomalies)
            
            # Check security
            self.security_monitor.check_security_status(sensor_data)
            
            time.sleep(0.1)  # 10Hz loop
            
    def _update_telemetry(self, sensor_data, detections, anomalies):
        """Update telemetry data"""
        self.telemetry_data = {
            'timestamp': time.time(),
            'position': sensor_data.get('position', {}),
            'velocity': sensor_data.get('velocity', {}),
            'attitude': sensor_data.get('attitude', {}),
            'battery': sensor_data.get('battery', 100),
            'detections': len(detections),
            'anomalies': len(anomalies),
            'calibration_status': self.autocalibration.get_status()
        }
        
    def _emergency_land(self):
        """Execute emergency landing procedure"""
        print("EMERGENCY LANDING ACTIVATED")
        self.is_armed = False
        self.current_mission = None
        self.navigation.emergency_land()
        
    def get_telemetry(self):
        """Get current telemetry data"""
        return self.telemetry_data.copy()
        
    def run(self):
        """Main drone loop"""
        print(f"{self.drone_id} starting main loop...")
        
        # Start command receiver
        self.command_receiver.start()
        
        # Start security monitor
        self.security_monitor.start()
        
        try:
            while True:
                # Main loop can handle high-level state management
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("Shutting down drone...")
            self.command_receiver.stop()
            self.security_monitor.stop()

if __name__ == "__main__":
    drone = DroneMain()
    drone.run()