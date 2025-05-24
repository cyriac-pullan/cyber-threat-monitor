import logging
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from datetime import datetime
import subprocess
import socket
import threading
import time

logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class ResponseEngine:
    def __init__(self):
        self.config = self._load_config()
        self.setup_logging()
        self.alert_history = []
        self.blocked_ips = {}
        self._load_blocked_ips()
        self.blocked_connections = set()  # Track blocked connections in memory
        self.last_email_sent = {
            "warning": 0,
            "critical": 0
        }
        
        # Start background tasks
        self._start_background_tasks()

    def _load_config(self):
        """Load configuration from file with proper error handling"""
        config_path = "config/response_config.json"
        logging.info(f"Attempting to load configuration from {config_path}")
        
        try:
            if not os.path.exists(config_path):
                logging.error(f"Configuration file not found: {config_path}")
                return self._get_default_config()
                
            # Try different encodings
            encodings = ['utf-8', 'utf-8-sig', 'latin1']
            config = None
            
            for encoding in encodings:
                try:
                    with open(config_path, "r", encoding=encoding) as f:
                        config = json.load(f)
                        logging.info(f"Successfully loaded config with {encoding} encoding")
                        break
                except UnicodeDecodeError:
                    continue
                    
            if config is None:
                logging.error("Failed to load configuration with any supported encoding")
                return self._get_default_config()
                
            # Validate email configuration
            if "email" not in config:
                logging.error("Email configuration missing in config file")
                config["email"] = self._get_default_config()["email"]
            elif not isinstance(config["email"], dict):
                logging.error("Invalid email configuration format")
                config["email"] = self._get_default_config()["email"]
            else:
                logging.info(f"Email config found: enabled={config['email'].get('enabled')}, "
                           f"sender={config['email'].get('sender')}, "
                           f"recipients={config['email'].get('recipients')}")
                
            logging.info(f"Final configuration loaded successfully")
            return config
            
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {str(e)}")
            return self._get_default_config()
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
            return self._get_default_config()
            
    def _get_default_config(self):
        """Return default configuration"""
        return {
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "sender": "alerts@example.com",
                "password": "",
                "recipients": ["admin@example.com"],
                "severity_levels": {
                    "warning": {
                        "enabled": False,
                        "threshold": 5,
                        "cooldown": 3600,
                        "subject": "Warning Level"
                    },
                    "critical": {
                        "enabled": False,
                        "threshold": 10,
                        "cooldown": 3600,
                        "subject": "Critical Level"
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
            "block_duration": 3600  # 1 hour in seconds
        }

    def setup_logging(self):
        # Add console handler
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

    def _load_blocked_ips(self):
        try:
            with open("config/blocked_ips.json", "r") as f:
                data = json.load(f)
                # Convert list to dictionary with current time
                self.blocked_ips = {ip: time.time() for ip in data}
        except:
            self.blocked_ips = {}

    def _save_blocked_ips(self):
        """Save blocked IPs to file with proper error handling"""
        try:
            # Ensure we have a valid list of IPs
            if not isinstance(self.blocked_ips, dict):
                logging.error("Invalid blocked_ips data structure")
                return
                
            # Convert to list of IPs
            ip_list = list(self.blocked_ips.keys())
            
            # Ensure the config directory exists
            os.makedirs("config", exist_ok=True)
            
            # Save to file with proper error handling
            with open("config/blocked_ips.json", "w") as f:
                json.dump(ip_list, f, indent=4)
                
            logging.info(f"Successfully saved {len(ip_list)} blocked IPs to file")
            
        except Exception as e:
            logging.error(f"Error saving blocked IPs: {str(e)}")
            raise

    def _start_background_tasks(self):
        # Start IP unblocking task
        threading.Thread(target=self._unblock_ips_task, daemon=True).start()
        
        # Start alert history cleanup task
        threading.Thread(target=self._cleanup_alert_history, daemon=True).start()

    def _unblock_ips_task(self):
        while True:
            current_time = time.time()
            to_unblock = set()
            
            for ip, block_time in self.blocked_ips.items():
                if current_time - block_time > self.config["block_duration"]:
                    to_unblock.add(ip)
            
            for ip in to_unblock:
                self.unblock_ip(ip)
            
            time.sleep(60)  # Check every minute

    def _cleanup_alert_history(self):
        while True:
            current_time = time.time()
            self.alert_history = [
                alert for alert in self.alert_history
                if current_time - alert["timestamp"] < 86400  # Keep last 24 hours
            ]
            time.sleep(3600)  # Cleanup every hour

    def block_ip(self, ip):
        """Block an IP address at application level"""
        # Validate IP address format
        try:
            # Check if IP is already blocked
            if ip in self.blocked_ips:
                logging.info(f"IP {ip} is already blocked")
                return
            
            # Validate IP format
            parts = ip.split('.')
            if len(parts) != 4:
                if ip != "different":
                    logging.warning(f"Invalid IP format: {ip}")
                return
            
            # Validate each octet
            for part in parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    logging.warning(f"Invalid IP octet in {ip}")
                    return
            
            # Add to blocked IPs list
            self.blocked_ips[ip] = time.time()
            self.blocked_connections.add(ip)
            
            # Ensure the config directory exists
            os.makedirs("config", exist_ok=True)
            
            # Save blocked IPs with proper error handling
            try:
                self._save_blocked_ips()
                logging.info(f"Successfully saved blocked IPs to file")
            except Exception as e:
                logging.error(f"Failed to save blocked IPs to file: {str(e)}")
                raise
            
            # Log the block action
            logging.info(f"Blocked IP: {ip}")
            
            # Create a detailed incident report
            incident_details = {
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "action": "blocked",
                "reason": "Suspicious activity detected",
                "recommendation": "Review and consider adding to firewall rules"
            }
            
            # Save detailed incident report
            self._save_incident_report(incident_details)
            
            # If email notifications are enabled, send a detailed report
            if self.config["email"]["enabled"]:
                self.send_email_alert(
                    f"IP Blocked: {ip}",
                    f"IP {ip} has been blocked due to suspicious activity.\n"
                    f"Time: {incident_details['timestamp']}\n"
                    f"Reason: {incident_details['reason']}\n"
                    f"Recommendation: {incident_details['recommendation']}"
                )
            
        except Exception as e:
            logging.error(f"Failed to block IP {ip}: {str(e)}")
            # Re-raise the exception to ensure the error is not silently ignored
            raise

    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if ip not in self.blocked_ips:
            return
        
        try:
            # Remove from blocked lists
            del self.blocked_ips[ip]
            self.blocked_connections.discard(ip)
            self._save_blocked_ips()
            
            # Log the unblock action
            logging.info(f"Unblocked IP: {ip}")
            
            # Create unblock report
            incident_details = {
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "action": "unblocked",
                "reason": "Block duration expired",
                "recommendation": "Monitor for suspicious activity"
            }
            
            # Save unblock report
            self._save_incident_report(incident_details)
            
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip}: {str(e)}")

    def _save_incident_report(self, incident_details):
        """Save detailed incident report to a JSON file"""
        try:
            report_file = "config/incident_reports.json"
            reports = []
            
            # Load existing reports if file exists
            if os.path.exists(report_file):
                with open(report_file, "r") as f:
                    reports = json.load(f)
            
            # Add new report
            reports.append(incident_details)
            
            # Save updated reports
            with open(report_file, "w") as f:
                json.dump(reports, f, indent=4)
                
        except Exception as e:
            logging.error(f"Failed to save incident report: {str(e)}")

    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        return ip in self.blocked_connections

    def get_blocked_ips_report(self):
        """Get a detailed report of currently blocked IPs"""
        current_time = time.time()
        active_blocks = []
        
        for ip, block_time in self.blocked_ips.items():
            time_remaining = self.config["block_duration"] - (current_time - block_time)
            if time_remaining > 0:
                active_blocks.append({
                    "ip": ip,
                    "blocked_at": datetime.fromtimestamp(block_time).isoformat(),
                    "time_remaining": int(time_remaining),
                    "status": "active"
                })
        
        return active_blocks

    def send_email_alert(self, subject, message):
        """Send email alert with enhanced error handling and logging"""
        if not self.config["email"]["enabled"]:
            logging.info("Email notifications are disabled in config")
            return
            
        if not self.config["email"].get("password"):
            logging.error("Email password not configured")
            return
            
        try:
            logging.info(f"Preparing to send email to {self.config['email']['recipients']}")
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config["email"]["sender"]
            msg['To'] = ", ".join(self.config["email"]["recipients"])
            msg['Subject'] = subject
            
            # Add message body
            msg.attach(MIMEText(message, 'plain'))
            
            # Connect to SMTP server
            logging.info(f"Connecting to SMTP server: {self.config['email']['smtp_server']}:{self.config['email']['smtp_port']}")
            server = smtplib.SMTP(self.config["email"]["smtp_server"], self.config["email"]["smtp_port"])
            server.starttls()
            
            # Login
            logging.info("Attempting SMTP login...")
            server.login(self.config["email"]["sender"], self.config["email"]["password"])
            
            # Send email
            logging.info("Sending email message...")
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Email alert sent successfully: {subject}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logging.error(f"SMTP Authentication failed: {str(e)}")
            logging.error("Please check your email credentials and ensure 2FA is properly configured")
            return False
        except smtplib.SMTPException as e:
            logging.error(f"SMTP error occurred: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Failed to send email alert: {str(e)}")
            logging.error(f"Email configuration: SMTP={self.config['email']['smtp_server']}, "
                        f"Port={self.config['email']['smtp_port']}, "
                        f"Sender={self.config['email']['sender']}")
            return False

    def send_slack_alert(self, message):
        """Send Slack alert"""
        if not self.config["slack"]["enabled"]:
            return
        
        try:
            payload = {"text": message}
            response = requests.post(
                self.config["slack"]["webhook_url"],
                json=payload
            )
            response.raise_for_status()
            logging.info("Slack alert sent")
        except Exception as e:
            logging.error(f"Failed to send Slack alert: {str(e)}")

    def send_alert(self, message):
        """Handle alert events"""
        print("ALERT:", message)
        logging.warning(message)
        
        # Add to alert history
        self.alert_history.append({
            "timestamp": time.time(),
            "message": message
        })
        
        # Extract IP and user with improved parsing
        ip = None
        user = "Unknown"
        
        # Try different patterns for IP extraction
        if "IP: " in message:
            ip = message.split("IP: ")[1].split()[0]
        elif "from " in message:
            ip = message.split("from ")[1].split()[0]
            
        # Try different patterns for user extraction
        if "User: " in message:
            user = message.split("User: ")[1].split()[0]
        elif "User " in message:
            user = message.split("User ")[1].split()[0]
        elif "user " in message:
            user = message.split("user ")[1].split()[0]
        
        # Take automated actions
        if self.config["actions"]["block_ip"] and ip:
            self.block_ip(ip)
        
        if self.config["actions"]["notify_admin"]:
            # Extract alert type and details
            alert_type = "Security Alert"
            if "[" in message and "]" in message:
                alert_type = message.split("[")[1].split("]")[0]
            
            # Create detailed email content with proper emoji encoding
            subject = f"Security Alert: {alert_type}"  # Removed emoji from subject
            
            # Create detailed message
            message_content = f"""
Cyber Threat Monitor - Security Alert

🚨 Alert Details
--------------
• Alert Type: {alert_type}
• Severity: {'High' if alert_type in ['Brute Force', 'Impossible Travel'] else 'Medium'}
• Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• User: {user}
• IP Address: {ip if ip else 'N/A'}

📊 Alert Information
-----------------
• Message: {message}
• Status: Active
• Action Taken: {'IP Blocked' if ip and self.config["actions"]["block_ip"] else 'Alert Generated'}

🛡️ System Status
---------------
• Blocked IPs: {len(self.blocked_ips)}
• Total Alerts (24h): {len(self.alert_history)}
• Active Security Measures: {', '.join([k for k, v in self.config['actions'].items() if v])}

⚠️ Recommended Actions
-------------------
1. Review the alert details above
2. Check system logs for additional context
3. Verify affected user account: {user}
4. Review IP blocking status: {ip if ip else 'N/A'}
5. Consider implementing additional security measures

For more details, please check the Cyber Threat Monitor dashboard.
"""
            
            # Send email alert
            self.send_email_alert(subject, message_content)
            
            # Send Slack alert
            self.send_slack_alert(f"🚨 *Security Alert*\n{message}")
        
        if self.config["actions"]["log_incident"]:
            self._log_incident(message)

    def send_normal(self, message):
        """Handle normal events"""
        print("INFO:", message)
        logging.info(message)

    def _log_incident(self, message):
        """Log incident details to a separate file"""
        try:
            with open("incidents.log", "a") as f:
                f.write(f"{datetime.now()} - {message}\n")
        except Exception as e:
            logging.error(f"Failed to log incident: {str(e)}")

    def get_alert_history(self, hours=24):
        """Get alert history for the specified time period"""
        current_time = time.time()
        return [
            alert for alert in self.alert_history
            if current_time - alert["timestamp"] < hours * 3600
        ]

    def get_blocked_ips(self):
        """Get currently blocked IPs"""
        return list(self.blocked_ips.keys())

    def _check_severity_email(self, status, recent_alerts):
        """Check if we should send a severity-based email"""
        if not self.config["email"]["enabled"]:
            logging.info("Email notifications are disabled in config")
            return

        current_time = time.time()
        severity_config = self.config["email"]["severity_levels"].get(status)
        
        logging.info(f"Checking severity email for status: {status}")
        logging.info(f"Recent alerts count: {len(recent_alerts)}")
        
        if not severity_config or not severity_config["enabled"]:
            logging.info(f"Severity level {status} is not enabled in config")
            return
            
        if len(recent_alerts) >= severity_config["threshold"]:
            # Check cooldown period
            time_since_last = current_time - self.last_email_sent[status]
            logging.info(f"Time since last {status} email: {time_since_last} seconds")
            
            if time_since_last >= severity_config["cooldown"]:
                logging.info(f"Sending {status} level email - {len(recent_alerts)} alerts exceed threshold of {severity_config['threshold']}")
                # Prepare email content
                subject = f"Security Alert: {status.upper()}"  # Simplified subject without emoji
                
                # Group alerts by type
                alert_groups = {}
                for alert in recent_alerts:
                    alert_type = alert.get('type', 'Other')
                    if alert_type not in alert_groups:
                        alert_groups[alert_type] = []
                    alert_groups[alert_type].append(alert)
                
                # Create detailed message
                message = f"""
Cyber Threat Monitor - {status.upper()} Level Security Alert

📊 Alert Summary
---------------
• Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• Alert Level: {status.upper()}
• Total Alerts: {len(recent_alerts)}
• Threshold: {severity_config['threshold']} alerts
• Time Window: Last {severity_config['cooldown']//60} minutes

📈 Alert Distribution
-------------------"""
                
                # Add alert type distribution
                for alert_type, alerts in alert_groups.items():
                    message += f"\n• {alert_type}: {len(alerts)} alerts"
                
                message += f"""

🔍 Recent Alerts
--------------"""
                
                # Add recent alerts with timestamps
                for alert in recent_alerts[-5:]:
                    # Convert float timestamp to datetime
                    timestamp = datetime.fromtimestamp(alert.get('timestamp', current_time))
                    message += f"\n• [{timestamp.strftime('%H:%M:%S')}] {alert['message']}"
                
                message += f"""

🛡️ System Status
---------------
• Blocked IPs: {len(self.blocked_ips)}
• Total Alerts (24h): {len(self.alert_history)}
• Active Security Measures: {', '.join([k for k, v in self.config['actions'].items() if v])}

⚠️ Recommended Actions
-------------------
1. Review the alert details above
2. Check system logs for additional context
3. Verify affected user accounts
4. Review IP blocking status
5. Consider implementing additional security measures

For more details, please check the Cyber Threat Monitor dashboard.
"""
                
                # Send email alert
                self.send_email_alert(subject, message)
                
                # Update last sent time
                self.last_email_sent[status] = current_time
            else:
                logging.info(f"Skipping {status} email - cooldown period not elapsed")
        else:
            logging.info(f"No {status} email needed - {len(recent_alerts)} alerts below threshold of {severity_config['threshold']}")

    def get_system_status(self):
        """Get current system status including blocked IPs and recent alerts"""
        current_time = time.time()
        recent_alerts = [
            alert for alert in self.alert_history
            if current_time - alert["timestamp"] < 3600  # Last hour
        ]
        
        # Calculate system status based on recent alerts
        status = "normal"
        if len(recent_alerts) > self.config["email"]["severity_levels"]["critical"]["threshold"]:
            status = "critical"
        elif len(recent_alerts) > self.config["email"]["severity_levels"]["warning"]["threshold"]:
            status = "warning"
            
        # Check if we should send severity-based email
        self._check_severity_email(status, recent_alerts)
            
        return {
            "status": status,
            "blocked_ips": len(self.blocked_ips),
            "recent_alerts": len(recent_alerts),
            "last_alert": recent_alerts[-1]["message"] if recent_alerts else None,
            "timestamp": datetime.now().isoformat()
        }

    def get_alerts(self):
        """Get recent alerts"""
        current_time = time.time()
        recent_alerts = [
            {
                "id": i,
                "message": alert["message"],
                "timestamp": alert["timestamp"],
                "time_ago": int(current_time - alert["timestamp"])
            }
            for i, alert in enumerate(self.alert_history)
            if current_time - alert["timestamp"] < 86400  # Last 24 hours
        ]
        return recent_alerts

    def acknowledge_alert(self, alert_id):
        """Acknowledge an alert by its ID"""
        try:
            alert_id = int(alert_id)
            if 0 <= alert_id < len(self.alert_history):
                # You could add an 'acknowledged' field to the alert here
                logging.info(f"Alert {alert_id} acknowledged")
                return True
        except (ValueError, IndexError):
            pass
        return False

    def test_email_config(self):
        """Test email configuration and send a test email"""
        logging.info("Testing email configuration...")
        
        # Check if email is enabled
        if not self.config["email"]["enabled"]:
            logging.error("Email notifications are disabled in config")
            return False
            
        # Check required fields
        required_fields = ["smtp_server", "smtp_port", "sender", "password", "recipients"]
        missing_fields = [field for field in required_fields if not self.config["email"].get(field)]
        
        if missing_fields:
            logging.error(f"Missing required email configuration fields: {', '.join(missing_fields)}")
            return False
            
        try:
            # Create test message
            subject = "🔍 Cyber Threat Monitor - Email Configuration Test"
            message = f"""
Cyber Threat Monitor - Email Configuration Test

📧 Email Configuration Details
---------------------------
• SMTP Server: {self.config['email']['smtp_server']}
• SMTP Port: {self.config['email']['smtp_port']}
• Sender: {self.config['email']['sender']}
• Recipients: {', '.join(self.config['email']['recipients'])}

✅ Configuration Status
--------------------
• Email Notifications: Enabled
• Warning Level: {self.config['email']['severity_levels']['warning']['enabled']}
• Critical Level: {self.config['email']['severity_levels']['critical']['enabled']}

🕒 Test Information
----------------
• Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• System Status: Active
• Configuration: Valid

If you received this email, your email configuration is working correctly.
You will now receive security alerts based on your configured thresholds.

For any issues, please check the system logs or contact the system administrator.
"""
            # Send test email
            success = self.send_email_alert(subject, message)
            if success:
                logging.info("✅ Test email sent successfully!")
            return success
            
        except Exception as e:
            logging.error(f"❌ Failed to send test email: {str(e)}")
            return False

    def _save_config(self, config):
        """Save configuration to file with proper encoding"""
        config_path = "config/response_config.json"
        try:
            # Ensure config directory exists
            os.makedirs("config", exist_ok=True)
            
            # Save with UTF-8 encoding
            with open(config_path, "w", encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
                
            logging.info(f"Configuration saved successfully to {config_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to save configuration: {str(e)}")
            return False
