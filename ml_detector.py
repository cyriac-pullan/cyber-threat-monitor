import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime
from typing import List, Dict, Any

class MLDetector:
    def __init__(self, model_path: str = "models/anomaly_detector.joblib"):
        # Initialize with robust defaults
        self.isolation_forest = IsolationForest(
            n_estimators=200,
            max_samples='auto',
            contamination=0.1,
            max_features=1.0,
            bootstrap=False,
            random_state=42,
            verbose=0
        )
        self.dbscan = DBSCAN(eps=0.5, min_samples=3)
        self.scaler = StandardScaler()
        self.model_path = model_path
        self._initialize_model()

    def _initialize_model(self) -> None:
        """Safely initialize or load model"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            if os.path.exists(self.model_path):
                self.isolation_forest = joblib.load(self.model_path)
            else:
                # Train with minimal dummy data
                dummy_data = np.random.rand(10, 7)  # 7 features
                self.isolation_forest.fit(dummy_data)
                self._save_model()
                
        except Exception as e:
            print(f"Model initialization warning: {str(e)}")
            # Fallback to fresh model
            self.isolation_forest = IsolationForest(
                n_estimators=200,
                contamination=0.1,
                random_state=42
            )

    def _extract_features(self, log_entries: List[Dict]) -> np.ndarray:
        """Convert log entries to numerical features"""
        features = []
        for entry in log_entries:
            try:
                # Extract time-based features
                timestamp = entry.get('timestamp', datetime.now())
                hour = timestamp.hour
                minute = timestamp.minute
                weekday = timestamp.weekday()
                
                # Extract IP-based features
                ip = entry.get('details', {}).get('ip', '0.0.0.0')
                ip_parts = ip.split('.')[:4]  # Ensure exactly 4 parts
                ip_numeric = [int(part) if part.isdigit() else 0 for part in ip_parts]
                
                features.append([hour, minute, weekday] + ip_numeric)
            except Exception as e:
                print(f"Skipping malformed log entry: {str(e)}")
                continue
                
        return np.array(features) if features else np.empty((0, 7))

    def _save_model(self) -> bool:
        """Safely save the current model"""
        try:
            joblib.dump(self.isolation_forest, self.model_path)
            return True
        except Exception as e:
            print(f"Failed to save model: {str(e)}")
            return False

    def detect_anomalies(self, log_entries: List[Dict]) -> List[Dict]:
        """Detect anomalies in log entries"""
        if not log_entries or len(log_entries) < 2:
            return []

        try:
            features = self._extract_features(log_entries)
            if len(features) < 2:
                return []
                
            scaled_features = self.scaler.fit_transform(features)
            anomaly_scores = self.isolation_forest.fit_predict(scaled_features)
            
            # Cluster only anomalies for efficiency
            anomaly_mask = (anomaly_scores == -1)
            if np.any(anomaly_mask):
                anomaly_features = scaled_features[anomaly_mask]
                clusters = self.dbscan.fit_predict(anomaly_features)
            else:
                clusters = np.array([])
            
            # Prepare results
            anomalies = []
            cluster_iter = iter(clusters) if clusters.size > 0 else iter([])
            
            for i, score in enumerate(anomaly_scores):
                if score == -1:
                    try:
                        cluster = next(cluster_iter)
                    except StopIteration:
                        cluster = -1
                        
                    anomalies.append({
                        'entry': log_entries[i],
                        'anomaly_score': abs(self.isolation_forest.score_samples(
                            [scaled_features[i]])[0]),
                        'cluster': int(cluster)
                    })
            
            return anomalies
            
        except Exception as e:
            print(f"Anomaly detection failed: {str(e)}")
            return []

    def update_model(self, new_log_entries: List[Dict]) -> bool:
        """Update the model with new data"""
        if not new_log_entries:
            return False
            
        try:
            features = self._extract_features(new_log_entries)
            if len(features) < 2:
                return False
                
            scaled_features = self.scaler.fit_transform(features)
            self.isolation_forest.fit(scaled_features)
            return self._save_model()
            
        except Exception as e:
            print(f"Model update failed: {str(e)}")
            return False

    def get_anomaly_patterns(self, anomalies: List[Dict]) -> List[Dict]:
        """Analyze patterns in detected anomalies"""
        patterns = []
        clusters = {}
        
        # Group anomalies by cluster
        for anomaly in anomalies:
            cluster = anomaly['cluster']
            clusters.setdefault(cluster, []).append(anomaly)
        
        # Analyze each cluster
        for cluster_id, cluster_anomalies in clusters.items():
            if cluster_id == -1 or not cluster_anomalies:
                continue
                
            # Extract features from cluster
            ips = [a['entry'].get('details', {}).get('ip', '0.0.0.0') for a in cluster_anomalies]
            times = [a['entry']['timestamp'] for a in cluster_anomalies]
            scores = [a['anomaly_score'] for a in cluster_anomalies]
            
            # Calculate time differences
            time_diffs = []
            if len(times) > 1:
                sorted_times = sorted(times)
                time_diffs = [(sorted_times[i+1] - sorted_times[i]).total_seconds() 
                            for i in range(len(sorted_times)-1)]
            
            patterns.append({
                'cluster_id': cluster_id,
                'size': len(cluster_anomalies),
                'common_ips': list(set(ips)),
                'ip_count': len(set(ips)),
                'time_range': {
                    'start': min(times),
                    'end': max(times),
                    'duration_seconds': (max(times) - min(times)).total_seconds(),
                    'avg_interval': np.mean(time_diffs) if time_diffs else 0
                },
                'score_stats': {
                    'avg': np.mean(scores),
                    'std': np.std(scores),
                    'max': max(scores),
                    'min': min(scores)
                }
            })
        
        return patterns