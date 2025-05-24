import streamlit as st
import os
import json
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

class TargetDashboard:
    def __init__(self):
        self.target_systems_dir = "target_systems"
        self.target_systems = self.get_target_systems()
        
    def get_target_systems(self):
        """Get list of all target systems"""
        if not os.path.exists(self.target_systems_dir):
            return []
        return [d for d in os.listdir(self.target_systems_dir) 
                if os.path.isdir(os.path.join(self.target_systems_dir, d))]
    
    def get_target_alerts(self, target_name):
        """Get alerts for a specific target system"""
        alert_file = f"{self.target_systems_dir}/{target_name}/logs/alerts.log"
        if not os.path.exists(alert_file):
            return []
            
        alerts = []
        with open(alert_file, 'r') as f:
            for line in f:
                if "ALERT" in line:
                    alerts.append({
                        'timestamp': line.split(' - ')[0],
                        'message': line.split(' - ')[-1].strip()
                    })
        return alerts
    
    def get_target_status(self, target_name):
        """Get system status for a specific target"""
        config_file = f"{self.target_systems_dir}/{target_name}/config/response_config.json"
        if not os.path.exists(config_file):
            return {}
            
        with open(config_file, 'r') as f:
            config = json.load(f)
            
        return {
            'name': target_name,
            'email_enabled': config['email']['enabled'],
            'slack_enabled': config['slack']['enabled'],
            'actions': config['actions']
        }
    
    def get_blocked_ips(self, target_name):
        """Get blocked IPs for a specific target"""
        blocked_file = f"{self.target_systems_dir}/{target_name}/config/blocked_ips.json"
        if not os.path.exists(blocked_file):
            return []
            
        with open(blocked_file, 'r') as f:
            return json.load(f)
    
    def run(self):
        """Run the target systems dashboard"""
        st.set_page_config(page_title="Cyber Threat Monitor - Target Systems", layout="wide")
        st.title("Cyber Threat Monitor - Target Systems")
        
        # Sidebar for target selection
        st.sidebar.title("Target Systems")
        selected_target = st.sidebar.selectbox(
            "Select Target System",
            self.target_systems,
            index=0 if self.target_systems else None
        )
        
        if not selected_target:
            st.warning("No target systems found. Please run start_target_system.py to add target systems.")
            return
            
        # Create tabs for different views
        tab1, tab2, tab3 = st.tabs(["Overview", "Alerts", "Configuration"])
        
        with tab1:
            st.header(f"Overview - {selected_target}")
            
            # System Status
            status = self.get_target_status(selected_target)
            st.subheader("System Status")
            st.json(status)
            
            # Blocked IPs
            blocked_ips = self.get_blocked_ips(selected_target)
            st.subheader("Blocked IPs")
            if blocked_ips:
                st.table(blocked_ips)
            else:
                st.info("No blocked IPs")
                
            # Alert Statistics
            alerts = self.get_target_alerts(selected_target)
            if alerts:
                df = pd.DataFrame(alerts)
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                
                # Alert timeline
                st.subheader("Alert Timeline")
                fig = px.scatter(df, x='timestamp', y='message',
                               title=f"Alerts for {selected_target}")
                st.plotly_chart(fig)
                
                # Alert types
                st.subheader("Alert Types")
                alert_types = df['message'].str.extract(r'\[(.*?)\]')[0].value_counts()
                fig = px.pie(values=alert_types.values, names=alert_types.index,
                           title="Alert Distribution")
                st.plotly_chart(fig)
        
        with tab2:
            st.header(f"Recent Alerts - {selected_target}")
            alerts = self.get_target_alerts(selected_target)
            if alerts:
                for alert in alerts[-10:]:  # Show last 10 alerts
                    st.warning(f"{alert['timestamp']} - {alert['message']}")
            else:
                st.info("No recent alerts")
        
        with tab3:
            st.header(f"Configuration - {selected_target}")
            config_file = f"{self.target_systems_dir}/{selected_target}/config/response_config.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                st.json(config)
            else:
                st.error("Configuration file not found")

def main():
    dashboard = TargetDashboard()
    dashboard.run()

if __name__ == "__main__":
    main() 