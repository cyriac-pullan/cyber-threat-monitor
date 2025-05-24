import streamlit as st
import time
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
import json
from ml_detector import MLDetector
from plotly.subplots import make_subplots
import networkx as nx
import requests

def get_alert_color(alert_type):
    """Get color for different alert types"""
    color_map = {
        'Brute Force': '#FF0000',      # Bright Red
        'Impossible Travel': '#8B0000', # Dark Red
        'Scanning': '#FF4500',         # Orange Red
        'Suspicious': '#FF8C00',       # Dark Orange
        'Blacklisted IP': '#B22222',   # Firebrick Red
        'Credential Guessing': '#FF6347', # Tomato Red
        'Unusual Login Time': '#CD5C5C',  # Indian Red
        'Other': '#4682B4'             # Steel Blue
    }
    return color_map.get(alert_type, '#4682B4')  # Default to steel blue if type not found

# Page config
st.set_page_config(
    page_title="Cyber Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

# Constants
ALERTS_LOG_FILE = "alerts.log"
REFRESH_INTERVAL = 2  # Default refresh interval in seconds

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

# Initialize ML detector
ml_detector = MLDetector()

def read_alerts():
    try:
        with open(ALERTS_LOG_FILE, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        return []

def parse_alert_line(line):
    try:
        # Parse timestamp and message
        parts = line.split(" - ", 2)
        if len(parts) != 3:
            return None
        timestamp_str, level, message = parts
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
        
        # Skip system messages about severity levels and email configuration
        if any(x in message for x in [
            "Severity level",
            "Email notifications are",
            "Checking severity email",
            "Recent alerts count",
            "Time since last",
            "Skipping",
            "No email needed",
            "Preparing to send email",
            "Connecting to SMTP server",
            "Attempting SMTP login",
            "Sending email message",
            "server listening on",
            "Final configuration loaded",
            "Email config found"
        ]):
            return None
        
        # Extract alert type and details
        alert_type = "Other"
        details = {}
        is_security_alert = False
        
        if "[Brute Force]" in message:
            alert_type = "Brute Force"
            details = parse_brute_force(message)
            is_security_alert = True
        elif "[Credential Guessing]" in message:
            alert_type = "Credential Guessing"
            details = parse_credential_guessing(message)
            is_security_alert = True
        elif "[Scanning]" in message:
            alert_type = "Scanning"
            details = parse_scanning(message)
            is_security_alert = True
        elif "[Suspicious]" in message:
            alert_type = "Suspicious Login"
            details = parse_suspicious(message)
            is_security_alert = True
        elif "[Impossible Travel]" in message:
            alert_type = "Impossible Travel"
            details = parse_impossible_travel(message)
            is_security_alert = True
        elif "[Unusual Login Time]" in message:
            alert_type = "Unusual Login Time"
            details = parse_unusual_time(message)
            is_security_alert = True
        elif "[Blacklisted IP]" in message:
            alert_type = "Blacklisted IP"
            details = parse_blacklisted(message)
            is_security_alert = True
        elif "Successful login" in message:
            alert_type = "Login Success"
            details = parse_login(message)
        elif "Failed login" in message:
            alert_type = "Login Failed"
            details = parse_login(message)
        elif "Blocked IP" in message or "Unblocked IP" in message:
            alert_type = "System"
            details = parse_system(message)
        elif "Email alert sent successfully" in message:
            alert_type = "Email"
            details = parse_system(message)
            
        return {
            "timestamp": timestamp,
            "level": level,
            "type": alert_type,
            "message": message.strip(),
            "details": details,
            "is_security_alert": is_security_alert
        }
    except Exception as e:
        return None

def parse_brute_force(message):
    try:
        # Extract user and IP from message
        user = message.split("User: ")[1].split(" IP:")[0]
        ip = message.split("IP: ")[1].split(" -")[0]
        attempts = int(message.split("attempts (")[1].split(")")[0])
        return {"user": user, "ip": ip, "attempts": attempts}
    except:
        return {}

def parse_scanning(message):
    try:
        users = int(message.split("users (")[1].split(")")[0])
        ip = message.split("from IP ")[1]
        return {"users_affected": users, "ip": ip}
    except:
        return {}

def parse_suspicious(message):
    try:
        user = message.split("user ")[1].split(" from")[0]
        ips = message.split("IPs in last hour: ")[1].strip("{}").split(", ")
        return {"user": user, "ips": ips}
    except:
        return {}

def parse_impossible_travel(message):
    try:
        user = message.split("User ")[1].split(" logged")[0]
        zones = message.split("zones in short time: ")[1].strip("{}").split(", ")
        return {"user": user, "zones": zones}
    except:
        return {}

def parse_unusual_time(message):
    try:
        user = message.split("User ")[1].split(" logged")[0]
        hour = int(message.split("hour ")[1].split(":")[0])
        return {"user": user, "hour": hour}
    except:
        return {}

def parse_blacklisted(message):
    try:
        ip = message.split("IP ")[1]
        return {"ip": ip}
    except:
        return {}

def parse_login(message):
    try:
        user = message.split("User ")[1].split(" logged")[0]
        ip = message.split("from IP ")[1]
        return {"user": user, "ip": ip}
    except:
        return {}

def parse_logout(message):
    try:
        user = message.split("User ")[1].split(" logged")[0]
        return {"user": user}
    except:
        return {}

def parse_system(message):
    try:
        return {"message": message}
    except:
        return {}

def parse_credential_guessing(message):
    try:
        user = message.split("User ")[1].split(" succeeded")[0]
        ip = message.split("from IP ")[1]
        return {"user": user, "ip": ip}
    except:
        return {}

def create_alert_dataframe(alerts):
    parsed_alerts = [parse_alert_line(line) for line in alerts]
    # Filter out None values but keep all types of events
    parsed_alerts = [a for a in parsed_alerts if a is not None]
    return pd.DataFrame(parsed_alerts)

def plot_alert_timeline(df):
    """Create an interactive timeline of alerts"""
    # Filter for security alerts only
    security_alert_types = [
        'Brute Force',
        'Impossible Travel',
        'Scanning',
        'Suspicious Login',
        'Blacklisted IP',
        'Credential Guessing',
        'Unusual Login Time'
    ]
    
    # Filter for security alerts
    alert_df = df[df['type'].isin(security_alert_types)]
    
    if alert_df.empty:
        return go.Figure()
        
    # Create scatter plot
    fig = go.Figure()
    
    # Add scatter points for each alert type
    for alert_type in alert_df['type'].unique():
        type_df = alert_df[alert_df['type'] == alert_type]
        fig.add_trace(go.Scatter(
            x=type_df['timestamp'],
            y=[alert_type] * len(type_df),
            mode='markers',
            name=alert_type,
            marker=dict(
                size=10,
                color=get_alert_color(alert_type)
            ),
            hovertemplate=(
                "<b>%{y}</b><br>" +
                "Time: %{x|%Y-%m-%d %H:%M:%S}<br>" +
                "Count: %{customdata}<br>" +
                "<extra></extra>"
            ),
            customdata=[len(type_df[type_df['timestamp'] == t]) for t in type_df['timestamp']]
        ))
    
    # Update layout
    fig.update_layout(
        title="Security Alert Timeline",
        xaxis_title="Time",
        yaxis_title="Alert Type",
        showlegend=True,
        hovermode='closest',
        template='plotly_dark',
        height=400
    )
    
    return fig

def plot_alert_distribution(df):
    """Create a pie chart showing the distribution of alert types"""
    # Filter for security alerts only
    security_alert_types = [
        'Brute Force',
        'Impossible Travel',
        'Scanning',
        'Suspicious Login',
        'Blacklisted IP',
        'Credential Guessing',
        'Unusual Login Time'
    ]
    
    # Filter for security alerts
    alert_df = df[df['type'].isin(security_alert_types)]
    
    if alert_df.empty:
        return go.Figure()
        
    # Count alerts by type
    alert_counts = alert_df['type'].value_counts()
    
    # Create pie chart
    fig = go.Figure(data=[go.Pie(
        labels=alert_counts.index,
        values=alert_counts.values,
        hole=.3,
        marker=dict(colors=[get_alert_color(alert_type) for alert_type in alert_counts.index]),
        hovertemplate=(
            "<b>%{label}</b><br>" +
            "Count: %{value}<br>" +
            "Percentage: %{percent:.1%}<br>" +
            "<extra></extra>"
        )
    )])
    
    # Update layout
    fig.update_layout(
        title="Security Alert Distribution",
        showlegend=True,
        template='plotly_dark',
        height=400,
        annotations=[dict(
            text=f"Total Alerts:<br>{len(alert_df)}",
            x=0.5, y=0.5,
            font_size=20,
            showarrow=False
        )]
    )
    
    return fig

def plot_hourly_distribution(df):
    if df.empty:
        return go.Figure()
    
    df['hour'] = df['timestamp'].dt.hour
    hourly_counts = df.groupby('hour').size()
    
    fig = px.bar(
        x=hourly_counts.index,
        y=hourly_counts.values,
        title="Alerts by Hour",
        labels={'x': 'Hour of Day', 'y': 'Number of Alerts'},
        template="plotly_dark"
    )
    return fig

def get_threat_intelligence(ip):
    """Get threat intelligence data for an IP"""
    try:
        # Check if IP is private
        ip_parts = ip.split('.')
        is_private = (
            ip.startswith('10.') or
            ip.startswith('172.16.') or
            ip.startswith('192.168.') or
            ip.startswith('127.')
        )
        
        if is_private:
            return {
                "ip": ip,
                "abuse_confidence": 0,
                "country": "Private Network",
                "domain": "Local Network",
                "total_reports": 0,
                "last_reported": "Never",
                "risk_level": "Low",
                "is_private": True
            }
            
        # Load API key from config
        with open("config/threat_intel_config.json", "r") as f:
            config = json.load(f)
            api_key = config.get("abuseipdb_key")
            
        if not api_key:
            st.warning("AbuseIPDB API key not configured. Please add your API key in config/threat_intel_config.json")
            return None
            
        response = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
            headers={
                'Key': api_key,
                'Accept': 'application/json'
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            data = data.get("data", {})
            
            # Format the data with better defaults and formatting
            return {
                "ip": data.get("ipAddress", ip),
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", "Never"),
                "risk_level": "High" if data.get("abuseConfidenceScore", 0) > 80 
                            else "Medium" if data.get("abuseConfidenceScore", 0) > 50 
                            else "Low",
                "is_private": False
            }
    except Exception as e:
        st.error(f"Error fetching threat intelligence: {str(e)}")
        return None

def format_anomaly_patterns(patterns):
    """Format anomaly patterns into a more readable format"""
    formatted_patterns = []
    for pattern in patterns:
        formatted_pattern = {
            "Cluster ID": pattern['cluster_id'],
            "Size": pattern['size'],
            "Common IPs": ", ".join(pattern['common_ips']),
            "Time Range": f"{pattern['time_range']['start'].strftime('%Y-%m-%d %H:%M:%S')} to {pattern['time_range']['end'].strftime('%Y-%m-%d %H:%M:%S')}",
            "Anomaly Score": f"{pattern['avg_anomaly_score']:.2f}"
        }
        formatted_patterns.append(formatted_pattern)
    return formatted_patterns

def create_network_graph(df):
    """Create a network graph of IPs and users"""
    G = nx.Graph()
    
    # Add nodes and edges
    for _, row in df.iterrows():
        if 'details' in row and isinstance(row['details'], dict):
            if 'ip' in row['details']:
                G.add_node(row['details']['ip'], type='ip', count=1)
            if 'user' in row['details']:
                G.add_node(row['details']['user'], type='user', count=1)
            if 'ip' in row['details'] and 'user' in row['details']:
                G.add_edge(row['details']['ip'], row['details']['user'])
    
    # Update node counts
    for node in G.nodes():
        G.nodes[node]['count'] = sum(1 for _, row in df.iterrows() 
                                   if row.get('details', {}).get('ip') == node or 
                                   row.get('details', {}).get('user') == node)
    
    # Create plot with fixed seed for stable layout
    pos = nx.spring_layout(G, k=1, iterations=50, seed=42)  # Added fixed seed
    
    # Create figure
    fig = go.Figure()
    
    # Add edges
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#888'),
        hoverinfo='none',
        mode='lines'))
    
    # Add nodes
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(f"{node}<br>Count: {G.nodes[node]['count']}")
        node_color.append('red' if G.nodes[node]['type'] == 'ip' else 'blue')
        node_size.append(10 + G.nodes[node]['count'] * 2)  # Size based on count
    
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="top center",
        marker=dict(
            showscale=False,
            color=node_color,
            size=node_size,
            line_width=2)))
    
    fig.update_layout(
        title="Network of IPs and Users",
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20,l=5,r=5,t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=600)  # Increased height for better visibility
    
    return fig

def create_advanced_metrics(df):
    """Create advanced metrics visualization"""
    if df.empty:
        return go.Figure()
    
    # Calculate metrics only for security alerts
    security_df = df[df['is_security_alert'] == True]
    total_alerts = len(security_df)
    unique_ips = security_df['details'].apply(lambda x: x.get('ip', '')).nunique()
    unique_users = security_df['details'].apply(lambda x: x.get('user', '')).nunique()
    
    # Create subplot
    fig = make_subplots(
        rows=2, cols=2,
        specs=[[{"type": "indicator"}, {"type": "indicator"}],
               [{"type": "indicator"}, {"type": "indicator"}]]
    )
    
    # Add indicators
    fig.add_trace(
        go.Indicator(
            mode="number",
            value=total_alerts,
            title="Security Alerts",
            domain={'row': 0, 'column': 0}
        ),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Indicator(
            mode="number",
            value=unique_ips,
            title="Suspicious IPs",
            domain={'row': 0, 'column': 1}
        ),
        row=1, col=2
    )
    
    fig.add_trace(
        go.Indicator(
            mode="number",
            value=unique_users,
            title="Affected Users",
            domain={'row': 1, 'column': 0}
        ),
        row=2, col=1
    )
    
    # Add threat level indicator
    threat_level = "High" if total_alerts > 100 else "Medium" if total_alerts > 50 else "Low"
    fig.add_trace(
        go.Indicator(
            mode="gauge+number",
            value=total_alerts,
            title="Threat Level",
            gauge={'axis': {'range': [0, 100]},
                  'bar': {'color': "red" if threat_level == "High" else "orange" if threat_level == "Medium" else "green"}},
            domain={'row': 1, 'column': 1}
        ),
        row=2, col=2
    )
    
    fig.update_layout(height=400, showlegend=False)
    return fig

# Update main dashboard layout
st.title("🛡️ Advanced Cyber Threat Monitor Dashboard")

# Add sidebar for settings
st.sidebar.title("Settings")
refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 1, 10, REFRESH_INTERVAL)
st.sidebar.markdown("---")
st.sidebar.markdown("### System Status")
st.sidebar.markdown("🟢 System Active")
st.sidebar.markdown("### Quick Actions")
if st.sidebar.button("Export Alert Log"):
    st.sidebar.download_button(
        label="Download Alert Log",
        data="\n".join(read_alerts()),
        file_name="alerts_export.log",
        mime="text/plain"
    )

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
    
    col1, col2 = st.columns([2, 1])
    with col1:
        ip_to_check = st.text_input("IP Address")
    with col2:
        if st.button("Check IP"):
            if ip_to_check:
                with st.spinner("Fetching threat intelligence..."):
                    threat_data = get_threat_intelligence(ip_to_check)
                    if threat_data:
                        # Display threat information in a structured format
                        st.markdown("### Threat Assessment")
                        
                        # Risk level indicator
                        risk_color = {
                            "High": "🔴",
                            "Medium": "🟡",
                            "Low": "🟢"
                        }.get(threat_data["risk_level"], "⚪")
                        
                        st.markdown(f"""
                        #### {risk_color} Risk Level: {threat_data["risk_level"]}
                        
                        **IP Information:**
                        - IP Address: {threat_data["ip"]}
                        - Country: {threat_data["country"] if threat_data["country"] != "Unknown" else "Not Available"}
                        - Domain: {threat_data["domain"] if threat_data["domain"] != "Unknown" else "Not Available"}
                        {f"*This is a private IP address in your local network*" if threat_data.get("is_private", False) else ""}
                        
                        **Threat Metrics:**
                        - Abuse Confidence Score: {threat_data["abuse_confidence"]}%
                        - Total Reports: {threat_data["total_reports"]}
                        - Last Reported: {threat_data["last_reported"] if threat_data["last_reported"] != "Never" else "No reports"}
                        """)
                        
                        # Add recommendations based on risk level
                        if threat_data["risk_level"] == "High":
                            st.warning("""
                            **Recommended Actions:**
                            1. Block this IP immediately
                            2. Review all activity from this IP
                            3. Check for any successful logins
                            4. Update firewall rules
                            """)
                        elif threat_data["risk_level"] == "Medium":
                            st.info("""
                            **Recommended Actions:**
                            1. Monitor this IP closely
                            2. Review recent activity
                            3. Consider blocking if suspicious activity continues
                            """)
                    else:
                        st.error("Could not fetch threat intelligence data")
            else:
                st.warning("Please enter an IP address to check")

# Main loop
while True:
    alerts = read_alerts()
    df = create_alert_dataframe(alerts)
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Update real-time alert feed
    if alerts:
        last_alerts = alerts[-10:]  # Show last 10 alerts
        last_alerts.reverse()
        alerts_text = ""
        for alert in last_alerts:
            parsed = parse_alert_line(alert)
            if parsed:
                # Determine color and icon based on alert type
                if parsed["type"] == "Brute Force":
                    color = "#FF4444"
                    icon = "🔒"
                elif parsed["type"] == "Scanning":
                    color = "#FF8800"
                    icon = "🔍"
                elif parsed["type"] == "Impossible Travel":
                    color = "#FF0000"
                    icon = "✈️"
                elif parsed["type"] == "Blacklisted IP":
                    color = "#CC0000"
                    icon = "⛔"
                elif parsed["type"] == "Suspicious Login":
                    color = "#FFAA00"
                    icon = "⚠️"
                elif parsed["type"] == "Login Success":
                    color = "#00FF00"
                    icon = "✅"
                elif parsed["type"] == "Login Failed":
                    color = "#FFA500"
                    icon = "❌"
                elif parsed["type"] == "Email":
                    color = "#00AAFF"
                    icon = "📧"
                else:
                    color = "#00AAFF"
                    icon = "ℹ️"
                
                alerts_text += f"""
                <div style='background-color: #1E1E1E; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid {color};'>
                    <div style='display: flex; align-items: center; margin-bottom: 8px;'>
                        <span style='font-size: 1.2em; margin-right: 8px;'>{icon}</span>
                        <span style='color: {color}; font-weight: bold; font-size: 1.1em;'>{parsed['type']}</span>
                    </div>
                    <div style='color: #888; font-size: 0.9em; margin-bottom: 5px;'>{parsed['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</div>
                    <div style='color: #fff;'>{parsed['message']}</div>
                </div>
                """
        alerts_placeholder.markdown(alerts_text, unsafe_allow_html=True)
    
    # Update metrics
    if not df.empty:
        metrics_placeholder.plotly_chart(
            create_advanced_metrics(df), 
            use_container_width=True,
            key=f"metrics_chart_{current_time}"
        )
    
    # Update network graph and anomaly detection
    if not df.empty:
        network_placeholder.plotly_chart(
            create_network_graph(df), 
            use_container_width=True,
            key=f"network_chart_{current_time}"
        )
        
        # Update anomaly detection
        log_entries = df.to_dict('records')
        anomalies = ml_detector.detect_anomalies(log_entries)
        if anomalies:
            patterns = ml_detector.get_anomaly_patterns(anomalies)
            formatted_patterns = format_anomaly_patterns(patterns)
            
            # Create a table for anomaly patterns
            pattern_df = pd.DataFrame(formatted_patterns)
            anomaly_placeholder.dataframe(
                pattern_df,
                use_container_width=True,
                hide_index=True,
                height=400  # Limit the height of the table
            )
    
    # Update other visualizations
    if not df.empty:
        timeline_placeholder.plotly_chart(
            plot_alert_timeline(df), 
            use_container_width=True, 
            key=f"timeline_chart_{current_time}"
        )
        distribution_placeholder.plotly_chart(
            plot_alert_distribution(df), 
            use_container_width=True, 
            key=f"distribution_chart_{current_time}"
        )
        hourly_placeholder.plotly_chart(
            plot_hourly_distribution(df), 
            use_container_width=True, 
            key=f"hourly_chart_{current_time}"
        )
    
    time.sleep(refresh_interval)
