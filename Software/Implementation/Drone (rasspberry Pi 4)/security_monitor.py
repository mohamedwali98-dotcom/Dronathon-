#!/usr/bin/env python3
"""
Security Monitoring and Anomaly Detection
Monitors for security threats and triggers responses
"""

import time
import threading
from enum import Enum

class SecurityLevel(Enum):
    NORMAL = 1
    ELEVATED = 2
    HIGH = 3
    CRITICAL = 4

class SecurityMonitor:
    def __init__(self, drone_main):
        self.drone = drone_main
        self.security_level = SecurityLevel.NORMAL
        self.running = False
        self.thread = None
        self.security_events = []
        
        # Security thresholds
        self.thresholds = {
            'max_attitude_deviation': 30.0,  # degrees
            'max_velocity_deviation': 5.0,   # m/s
            'max_position_drift': 10.0,      # meters
            'min_battery_level': 20.0,       # percent
            'max_temperature': 80.0          # celsius
        }
        
    def start(self):
        """Start security monitoring"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop)
        self.thread.daemon = True
        self.thread.start()
        print("Security monitor started")
        
    def stop(self):
        """Stop security monitoring"""
        self.running = False
        if self.thread:
            self.thread.join()
            
    def _monitor_loop(self):
        """Main security monitoring loop"""
        while self.running:
            sensor_data = self.drone.navigation.get_sensor_data()
            self.check_security_status(sensor_data)
            time.sleep(0.5)  # 2Hz monitoring
            
    def check_security_status(self, sensor_data):
        """Check current security status based on sensor data"""
        new_level = SecurityLevel.NORMAL
        alerts = []
        
        # Check battery level
        battery = sensor_data.get('battery', 100)
        if battery < self.thresholds['min_battery_level']:
            alerts.append(f"Low battery: {battery}%")
            new_level = SecurityLevel.ELEVATED
            
        # Check temperature
        temperature = sensor_data.get('temperature', 25)
        if temperature > self.thresholds['max_temperature']:
            alerts.append(f"High temperature: {temperature}°C")
            new_level = max(new_level, SecurityLevel.HIGH)
            
        # Check position consistency (anti-spoofing)
        if self._check_position_spoofing(sensor_data):
            alerts.append("Possible position spoofing detected")
            new_level = SecurityLevel.CRITICAL
            
        # Check attitude anomalies
        if self._check_attitude_anomalies(sensor_data):
            alerts.append("Unusual attitude detected")
            new_level = max(new_level, SecurityLevel.ELEVATED)
            
        # Update security level and trigger responses
        if new_level != self.security_level:
            self.security_level = new_level
            self._handle_security_level_change(alerts)
            
        # Log security events
        for alert in alerts:
            self._log_security_event(alert)
            
    def _check_position_spoofing(self, sensor_data):
        """Check for GNSS spoofing using multi-sensor consistency"""
        position = sensor_data.get('position', {})
        velocity = sensor_data.get('velocity', {})
        
        # In real implementation, compare:
        # - GPS position vs Visual-Inertial Odometry position
        # - Expected movement vs actual movement
        # - Signal quality metrics
        
        # For now, return False (no spoofing detected)
        return False
        
    def _check_attitude_anomalies(self, sensor_data):
        """Check for unusual attitude that might indicate attack or failure"""
        attitude = sensor_data.get('attitude', {})
        roll = abs(attitude.get('roll', 0))
        pitch = abs(attitude.get('pitch', 0))
        
        if roll > self.thresholds['max_attitude_deviation']:
            return True
        if pitch > self.thresholds['max_attitude_deviation']:
            return True
            
        return False
        
    def _handle_security_level_change(self, alerts):
        """Handle changes in security level"""
        print(f"Security level changed to: {self.security_level}")
        
        for alert in alerts:
            print(f"SECURITY ALERT: {alert}")
            
        if self.security_level == SecurityLevel.CRITICAL:
            # Trigger emergency procedures
            self.drone.execute_command("emergency_land", {})
            
    def _log_security_event(self, event):
        """Log security event with timestamp"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {event}"
        self.security_events.append(log_entry)
        
        # Keep only recent events
        if len(self.security_events) > 100:
            self.security_events = self.security_events[-100:]
            
    def get_security_status(self):
        """Get current security status"""
        return {
            'level': self.security_level.name,
            'recent_events': self.security_events[-5:]  # Last 5 events
        }