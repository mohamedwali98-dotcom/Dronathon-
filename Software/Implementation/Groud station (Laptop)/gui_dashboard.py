#!/usr/bin/env python3
"""
GUI Dashboard for Ground Station
Provides real-time monitoring and control interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time

class GUIDashboard:
    def __init__(self, ground_station):
        self.gs = ground_station
        self.root = tk.Tk()
        self.root.title("Rescue Drone Command Center")
        self.root.geometry("1200x800")
        
        self.drone_frames = {}
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Mission control section
        mission_frame = ttk.LabelFrame(main_frame, text="Mission Control", padding="10")
        mission_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(mission_frame, text="Start New Mission", 
                  command=self.start_mission_dialog).grid(row=0, column=0, padx=5)
        ttk.Button(mission_frame, text="Emergency Stop", 
                  command=self.emergency_stop).grid(row=0, column=1, padx=5)
                  
        # Drones status section
        drones_frame = ttk.LabelFrame(main_frame, text="Drone Fleet Status", padding="10")
        drones_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Create drone status panels
        self.drones_container = ttk.Frame(drones_frame)
        self.drones_container.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Telemetry display
        telemetry_frame = ttk.LabelFrame(main_frame, text="Telemetry & Alerts", padding="10")
        telemetry_frame.grid(row=1, column=1, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.telemetry_text = scrolledtext.ScrolledText(telemetry_frame, width=50, height=20)
        self.telemetry_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Security monitor
        security_frame = ttk.LabelFrame(main_frame, text="Security Monitor", padding="10")
        security_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.security_status = ttk.Label(security_frame, text="All Systems Secure", foreground="green")
        self.security_status.grid(row=0, column=0)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
    def start_mission_dialog(self):
        """Dialog to start a new mission"""
        # Simplified mission start
        mission_data = {
            "search_area": {"lat": 36.8065, "lon": 10.1815, "radius": 1000},
            "priority_zones": [],
            "max_altitude": 120,
            "estimated_duration": 3600
        }
        self.gs.start_mission(mission_data)
        self.log_telemetry("SYSTEM", "New mission started")
        
    def emergency_stop(self):
        """Emergency stop all drones"""
        for drone_id in self.gs.active_drones:
            cmd = self.gs._create_command("emergency_land", {})
            self.gs.command_sender.send_command(drone_id, cmd)
        self.log_telemetry("SYSTEM", "EMERGENCY STOP ACTIVATED")
        
    def update_drone_status(self, drone_id, status):
        """Update drone status in UI"""
        if drone_id not in self.drone_frames:
            self._create_drone_panel(drone_id)
            
        frame = self.drone_frames[drone_id]
        status_label = frame.children['status']
        
        color = "green" if status == "CONNECTED" else "red"
        status_label.config(text=f"Status: {status}", foreground=color)
        
    def _create_drone_panel(self, drone_id):
        """Create status panel for a new drone"""
        frame = ttk.LabelFrame(self.drones_container, text=f"Drone {drone_id}", padding="5")
        frame.grid(row=len(self.drone_frames), column=0, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(frame, text=f"ID: {drone_id}", name='id').grid(row=0, column=0, sticky=tk.W)
        status_label = ttk.Label(frame, text="Status: UNKNOWN", name='status')
        status_label.grid(row=1, column=0, sticky=tk.W)
        
        self.drone_frames[drone_id] = frame
        
    def update_telemetry(self, drone_id, telemetry):
        """Update telemetry display"""
        telemetry_str = f"\n[{time.strftime('%H:%M:%S')}] {drone_id}:\n"
        for key, value in telemetry.items():
            telemetry_str += f"  {key}: {value}\n"
            
        self.telemetry_text.insert(tk.END, telemetry_str)
        self.telemetry_text.see(tk.END)
        
    def log_telemetry(self, source, message):
        """Log system messages"""
        timestamp = time.strftime('%H:%M:%S')
        self.telemetry_text.insert(tk.END, f"[{timestamp}] {source}: {message}\n")
        self.telemetry_text.see(tk.END)
        
    def update_mission_status(self, mission_id, status):
        """Update mission status display"""
        self.log_telemetry("MISSION", f"{mission_id} - {status}")
        
    def start(self):
        """Start the GUI"""
        self.log_telemetry("SYSTEM", "Ground Station GUI Started")
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.root.quit()