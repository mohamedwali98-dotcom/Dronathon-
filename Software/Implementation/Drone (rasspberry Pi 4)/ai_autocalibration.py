#!/usr/bin/env python3
"""
Real-time AI Autocalibration for PID Controllers
Uses machine learning to optimize drone flight performance
"""

import time
import numpy as np
from anomaly_detector import PyTorchModel

class AIAutocalibration:
    def __init__(self):
        self.calibration_model = PyTorchModel()
        self.is_enabled = False
        self.is_calibrating = False
        
        # PID parameters that will be adjusted
        self.pid_params = {
            'roll': {'Kp': 1.0, 'Ki': 0.1, 'Kd': 0.05},
            'pitch': {'Kp': 1.0, 'Ki': 0.1, 'Kd': 0.05},
            'yaw': {'Kp': 1.0, 'Ki': 0.1, 'Kd': 0.05},
            'altitude': {'Kp': 1.0, 'Ki': 0.1, 'Kd': 0.05}
        }
        
        # Performance metrics
        self.performance_history = []
        self.calibration_log = []
        
    def load_model(self, model_path):
        """Load pre-trained autocalibration model"""
        success = self.calibration_model.load_model(model_path)
        if success:
            print("Autocalibration model loaded successfully")
        return success
        
    def enable(self):
        """Enable autocalibration system"""
        self.is_enabled = True
        print("AI autocalibration enabled")
        
    def disable(self):
        """Disable autocalibration system"""
        self.is_enabled = False
        self.is_calibrating = False
        print("AI autocalibration disabled")
        
    def start_calibration(self):
        """Start calibration process"""
        if not self.is_enabled:
            print("Autocalibration not enabled")
            return
            
        self.is_calibrating = True
        print("Starting AI autocalibration...")
        
    def update(self, sensor_data):
        """Update calibration based on current sensor data"""
        if not self.is_enabled or not self.is_calibrating:
            return
            
        # Calculate current performance metrics
        performance = self._calculate_performance(sensor_data)
        self.performance_history.append(performance)
        
        # Keep history manageable
        if len(self.performance_history) > 1000:
            self.performance_history = self.performance_history[-1000:]
            
        # Run calibration adjustment every 100 updates
        if len(self.performance_history) % 100 == 0:
            self._adjust_pid_parameters()
            
    def _calculate_performance(self, sensor_data):
        """Calculate current flight performance metrics"""
        attitude = sensor_data.get('attitude', {})
        velocity = sensor_data.get('velocity', {})
        
        # Calculate stability metrics
        roll_stability = 1.0 / (1.0 + abs(attitude.get('roll', 0)))
        pitch_stability = 1.0 / (1.0 + abs(attitude.get('pitch', 0)))
        
        # Calculate responsiveness metrics
        speed = np.sqrt(velocity.get('vx', 0)**2 + velocity.get('vy', 0)**2)
        responsiveness = min(1.0, speed / 10.0)  # Normalize to 0-1
        
        overall_performance = (roll_stability + pitch_stability + responsiveness) / 3.0
        
        return {
            'timestamp': time.time(),
            'roll_stability': roll_stability,
            'pitch_stability': pitch_stability, 
            'responsiveness': responsiveness,
            'overall': overall_performance
        }
        
    def _adjust_pid_parameters(self):
        """Adjust PID parameters using AI model"""
        if not self.calibration_model.model_loaded:
            # Use rule-based adjustment if no model
            self._rule_based_adjustment()
            return
            
        # Prepare input features for AI model
        input_features = self._prepare_calibration_features()
        
        # Get AI recommendations
        adjustments = self.calibration_model.predict(input_features)
        
        # Apply adjustments
        self._apply_pid_adjustments(adjustments)
        
    def _prepare_calibration_features(self):
        """Prepare features for calibration model"""
        if not self.performance_history:
            return {}
            
        recent_performance = self.performance_history[-10:]  # Last 10 samples
        
        features = {
            'mean_performance': np.mean([p['overall'] for p in recent_performance]),
            'performance_trend': self._calculate_performance_trend(),
            'current_pid_params': self.pid_params.copy(),
            'stability_variance': np.var([p['roll_stability'] for p in recent_performance])
        }
        
        return features
        
    def _calculate_performance_trend(self):
        """Calculate performance trend over recent history"""
        if len(self.performance_history) < 10:
            return 0
            
        recent = [p['overall'] for p in self.performance_history[-10:]]
        return np.polyfit(range(len(recent)), recent, 1)[0]  # Linear trend
        
    def _rule_based_adjustment(self):
        """Rule-based PID adjustment fallback"""
        if not self.performance_history:
            return
            
        recent_performance = self.performance_history[-10:]
        avg_performance = np.mean([p['overall'] for p in recent_performance])
        
        if avg_performance < 0.7:
            # Increase aggressiveness for poor performance
            for axis in self.pid_params:
                self.pid_params[axis]['Kp'] *= 1.1
                self.pid_params[axis]['Kd'] *= 1.05
                
            self.calibration_log.append(f"Rule-based: Increased PID gains (performance: {avg_performance:.3f})")
            
        elif avg_performance > 0.9:
            # Reduce aggressiveness for excellent performance (prevent overshoot)
            for axis in self.pid_params:
                self.pid_params[axis]['Kp'] *= 0.95
                self.pid_params[axis]['Ki'] *= 0.9
                
            self.calibration_log.append(f"Rule-based: Decreased PID gains (performance: {avg_performance:.3f})")
            
    def _apply_pid_adjustments(self, adjustments):
        """Apply PID parameter adjustments"""
        # In real implementation, this would apply the AI-suggested adjustments
        # For now, simulate small random adjustments
        for axis in self.pid_params:
            # Small random walk for simulation
            adjustment = np.random.normal(1.0, 0.05)
            self.pid_params[axis]['Kp'] *= adjustment
            
        self.calibration_log.append("AI-based: Applied PID adjustments")
        
    def get_status(self):
        """Get current calibration status"""
        if not self.performance_history:
            current_performance = 0
        else:
            current_performance = self.performance_history[-1]['overall']
            
        return {
            'enabled': self.is_enabled,
            'calibrating': self.is_calibrating,
            'current_performance': current_performance,
            'pid_parameters': self.pid_params.copy(),
            'recent_adjustments': self.calibration_log[-5:] if self.calibration_log else []
        }
        
    def get_pid_parameters(self):
        """Get current PID parameters"""
        return self.pid_params.copy()