import os
import json
import asyncio
import streamlit as st
from datetime import datetime
import threading
from log_watcher import LogWatcher
from threat_detector import ThreatDetector
from response_engine import ResponseEngine
import logging

class TargetSystemMonitor:
    def __init__(self, target_name, target_log_path):
        self.target_name = target_name
        self.target_log_path = target_log_path
        
        # Create target-specific directories
        self.target_dir = f"target_systems/{target_name}"
        self.target_config_dir = f"{self.target_dir}/config"
        self.target_logs_dir = f"{self.target_dir}/logs"
        
        # Create necessary directories
        os.makedirs(self.target_dir, exist_ok=True)
        os.makedirs(self.target_config_dir, exist_ok=True)
        os.makedirs(self.target_logs_dir, exist_ok=True)
        
        # Initialize target-specific logging
        self.setup_logging()
        
        # Initialize components with target-specific configs
        self.response_engine = ResponseEngine(config_path=f"{self.target_config_dir}/response_config.json")
        self.threat_detector = ThreatDetector()
        
        # Link components
        self.threat_detector.response_engine = self.response_engine
        
    def setup_logging(self):
        """Setup target-specific logging"""
        logging.basicConfig(
            filename=f"{self.target_logs_dir}/alerts.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
        
    def create_default_configs(self):
        """Create default configurations for the target system"""
        # Response config
        response_config = {
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "sender": "alerts@example.com",
                "password": "",
                "recipients": ["admin@example.com"],
                "severity_levels": {
                    "warning": {
                        "enabled": True,
                        "threshold": 5,
                        "cooldown": 3600
                    },
                    "critical": {
                        "enabled": True,
                        "threshold": 10,
                        "cooldown": 3600
                    }
                }
            },
            "slack": {
                "enabled": False,
                "webhook_url": ""
            },
            "actions": {
                "block_ip": True,
                "notify_admin": True,
                "log_incident": True
            },
            "block_duration": 3600
        }
        
        # Behavior config
        behavior_config = {
            "suspicious_thresholds": {
                "failed_attempts": 3,
                "ip_changes": 3,
                "time_deviation": 2,
                "success_rate": 0.3
            },
            "profile_window": 30,
            "update_frequency": 3600
        }
        
        # Save configs
        with open(f"{self.target_config_dir}/response_config.json", "w") as f:
            json.dump(response_config, f, indent=4)
            
        with open(f"{self.target_config_dir}/behavior_config.json", "w") as f:
            json.dump(behavior_config, f, indent=4)
            
    def process_logs(self):
        """Process logs from the target system"""
        watcher = LogWatcher(self.target_log_path)
        print(f"Monitoring logs for {self.target_name}...")
        try:
            for line in watcher.watch():
                level, message = self.threat_detector.detect(line)
                if level == "Alert":
                    print(f"[{self.target_name}] ALERT: {message}")
                    self.response_engine.send_alert(message)
                else:
                    print(f"[{self.target_name}] INFO: {message}")
                    self.response_engine.send_normal(message)
        except Exception as e:
            print(f"Error in log processing for {self.target_name}: {str(e)}")
            raise
            
    def run_dashboard(self):
        """Run the target-specific dashboard"""
        st.set_page_config(page_title=f"Cyber Threat Monitor - {self.target_name}")
        st.title(f"Cyber Threat Monitor - {self.target_name}")
        
        # Add target-specific dashboard components
        st.sidebar.title(f"{self.target_name} Controls")
        
        # Display alerts
        st.header("Recent Alerts")
        alerts = self.response_engine.get_alerts()
        if alerts:
            for alert in alerts:
                st.warning(alert["message"])
        else:
            st.info("No recent alerts")
            
        # Display system status
        st.header("System Status")
        status = self.response_engine.get_system_status()
        st.json(status)
        
        # Display blocked IPs
        st.header("Blocked IPs")
        blocked_ips = self.response_engine.get_blocked_ips()
        if blocked_ips:
            st.table(blocked_ips)
        else:
            st.info("No blocked IPs")
            
def main():
    # Get target system details
    target_name = input("Enter target system name: ")
    target_log_path = input("Enter path to target system's log file: ")
    
    # Initialize target system monitor
    monitor = TargetSystemMonitor(target_name, target_log_path)
    
    # Create default configs if they don't exist
    if not os.path.exists(f"{monitor.target_config_dir}/response_config.json"):
        monitor.create_default_configs()
    
    # Start log processing in a separate thread
    log_thread = threading.Thread(target=monitor.process_logs)
    log_thread.daemon = True
    log_thread.start()
    
    # Run the dashboard
    monitor.run_dashboard()
    
if __name__ == "__main__":
    main() 