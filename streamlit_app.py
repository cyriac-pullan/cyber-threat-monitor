import streamlit as st
import requests
import os
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Page config
st.set_page_config(
    page_title="Cyber Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

# API Configuration
API_URL = os.environ.get("API_URL", "http://localhost:8000")

def call_api(endpoint):
    """Make API calls with proper error handling"""
    try:
        response = requests.get(f"{API_URL}/api/{endpoint}")
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API call failed with status code: {response.status_code}")
            return None
    except Exception as e:
        st.error(f"Error calling API: {str(e)}")
        return None

# Custom CSS
st.markdown("""
    <style>
    .main {
        background-color: #0E1117;
    }
    .stAlert {
        padding: 1rem;
        border-radius: 0.5rem;
    }
    .metric-card {
        background-color: #1E1E1E;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    </style>
    """, unsafe_allow_html=True)

# Main dashboard layout
st.title("🛡️ Advanced Cyber Threat Monitor Dashboard")

# Add sidebar for settings
st.sidebar.title("Settings")
refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 1, 10, 2)
st.sidebar.markdown("---")
st.sidebar.markdown("### System Status")
st.sidebar.markdown("🟢 System Active")
st.sidebar.markdown("### Quick Actions")
if st.sidebar.button("Refresh Data"):
    st.experimental_rerun()

# Add tabs for different views
tab1, tab2, tab3 = st.tabs(["Overview", "Network Analysis", "Threat Intelligence"])

with tab1:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### Real-time Alert Feed")
        alerts_placeholder = st.empty()
    
    with col2:
        st.markdown("### Advanced Metrics")
        metrics_placeholder = st.empty()
    
    # Charts
    st.markdown("### Analytics")
    col3, col4 = st.columns(2)
    with col3:
        timeline_placeholder = st.empty()
    with col4:
        distribution_placeholder = st.empty()
    
    st.markdown("### Hourly Distribution")
    hourly_placeholder = st.empty()

with tab2:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### Network Analysis")
        network_placeholder = st.empty()
    
    with col2:
        st.markdown("### Anomaly Detection")
        anomaly_placeholder = st.empty()

with tab3:
    st.markdown("### Threat Intelligence")
    st.markdown("Enter an IP address to check its threat intelligence:")
    ip_to_check = st.text_input("IP Address")
    if ip_to_check:
        threat_data = call_api(f"threat-intelligence/{ip_to_check}")
        if threat_data:
            st.json(threat_data)
        else:
            st.error("Could not fetch threat intelligence data")

# Main loop
while True:
    # Fetch data from API
    alerts_data = call_api("alerts")
    risk_data = call_api("risk-assessment")
    status_data = call_api("status")
    
    if alerts_data:
        # Update real-time alert feed
        alerts_text = ""
        for alert in alerts_data[-10:]:  # Show last 10 alerts
            alerts_text += f"""
            <div style='background-color: #1E1E1E; padding: 10px; margin: 5px 0; border-radius: 5px;'>
                <div style='color: {alert["color"]}; font-weight: bold;'>{alert["type"]}</div>
                <div style='color: #888;'>{alert["timestamp"]}</div>
                <div style='color: #fff;'>{alert["message"]}</div>
            </div>
            """
        alerts_placeholder.markdown(alerts_text, unsafe_allow_html=True)
    
    if risk_data:
        # Update metrics
        metrics_placeholder.plotly_chart(
            create_advanced_metrics(risk_data), 
            use_container_width=True
        )
    
    if status_data:
        # Update network graph and anomaly detection
        network_placeholder.plotly_chart(
            create_network_graph(status_data), 
            use_container_width=True
        )
        
        if "anomalies" in status_data:
            anomaly_placeholder.dataframe(
                pd.DataFrame(status_data["anomalies"]),
                use_container_width=True,
                hide_index=True
            )
    
    time.sleep(refresh_interval) 