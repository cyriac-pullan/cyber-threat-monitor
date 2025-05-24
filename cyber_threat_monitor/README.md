# 🛡️ Cyber Threat Monitor

A real-time cyber threat monitoring system that detects and responds to suspicious activities in authentication logs. This system provides advanced threat detection, automated response actions, and a modern web-based dashboard for monitoring and analysis.

## 🌟 Features

- **Real-time Log Monitoring**: Continuously monitors authentication logs for suspicious activities
- **Advanced Threat Detection**:
  - Brute Force Detection
  - Port Scanning Detection
  - Suspicious Login Patterns
  - Impossible Travel Detection
  - Unusual Login Time Detection
  - Blacklisted IP Detection
- **Automated Response**:
  - IP Blocking
  - Email Notifications
  - Slack Integration
  - Incident Logging
- **Modern Dashboard**:
  - Real-time Alert Feed
  - Interactive Visualizations
  - Alert Statistics
  - Historical Analysis
- **Risk Scoring**:
  - User Risk Assessment
  - IP Risk Assessment
  - Pattern-based Anomaly Detection

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- iptables (for IP blocking functionality)
- SMTP server (for email notifications)
- Slack workspace (for Slack notifications)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cyber-threat-monitor.git
   cd cyber-threat-monitor
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure the system:
   - Edit `config/response_config.json` for notification settings
   - Edit `config/attack_patterns.json` for detection thresholds
   - Edit `config/blacklist.json` for known malicious IPs

### Usage

1. Start the system:
   ```bash
   python run.py
   ```

2. Access the dashboard:
   - Open your browser and navigate to `http://localhost:8501`

3. Monitor logs:
   - The system will automatically monitor `sample_logs/auth.log`
   - Alerts will be displayed in real-time on the dashboard
   - Automated responses will be executed based on configuration

## 📊 Dashboard Features

- **Real-time Alert Feed**: View the latest security alerts
- **Alert Statistics**: Monitor alert distribution and trends
- **Interactive Charts**:
  - Alert Timeline
  - Alert Distribution
  - Hourly Activity
- **System Status**: Monitor system health and blocked IPs
- **Export Capabilities**: Download alert logs for analysis

## ⚙️ Configuration

### Response Configuration (`config/response_config.json`)
- Email notification settings
- Slack integration
- Automated actions
- IP blocking duration

### Attack Patterns (`config/attack_patterns.json`)
- Brute force thresholds
- Scanning detection parameters
- Suspicious login patterns
- Time-based rules

### Blacklist (`config/blacklist.json`)
- Known malicious IPs
- Custom block rules

## 🔒 Security Features

- Automated IP blocking
- Risk-based scoring
- Pattern recognition
- Real-time monitoring
- Incident logging
- Multiple notification channels

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Streamlit for the dashboard framework
- Plotly for interactive visualizations
- The open-source community for various tools and libraries

## 📞 Support

For support, please open an issue in the GitHub repository or contact the maintainers. 