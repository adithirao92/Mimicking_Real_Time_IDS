# from sklearn.ensemble import IsolationForest
# import numpy as np

# class DetectionEngine:
#     def __init__(self):
#         self.anomaly_detector = IsolationForest(
#             contamination=0.1,
#             random_state=42
#         )
#         self.signature_rules = self.load_signature_rules()
#         self.training_data = None  # Store normal traffic data

#     def load_signature_rules(self):
#         return {
#             'syn_flood': {
#                 'condition': lambda features: (
#                     features['tcp_flags'] == 2 and  # SYN flag
#                     features['packet_rate'] > 100
#                 )
#             },
#             'port_scan': {
#                 'condition': lambda features: (
#                     features['packet_size'] < 100 and
#                     features['packet_rate'] > 50
#                 )
#             }
#         }

#     def train_anomaly_detector(self, normal_traffic_data):
#         if len(normal_traffic_data) == 0:
#             raise ValueError("Training data cannot be empty")
#         self.anomaly_detector.fit(normal_traffic_data)
#         self.training_data = normal_traffic_data  # Save the training data

#     def detect_threats(self, features):
#         threats = []

#         # Signature-based detection
#         for rule_name, rule in self.signature_rules.items():
#             if rule['condition'](features):
#                 threats.append({
#                     'type': 'signature',
#                     'rule': rule_name,
#                     'confidence': 1.0
#                 })

#         # Ensure the anomaly detector is trained before using it
#         if self.training_data is None:
#             raise RuntimeError("Anomaly detector has not been trained. Call 'train_anomaly_detector' first.")

#         # Anomaly-based detection
#         feature_vector = np.array([[
#             features['packet_size'],
#             features['packet_rate'],
#             features['byte_rate']
#         ]])

#         anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
#         if anomaly_score < -0.5:  # Threshold for anomaly detection
#             threats.append({
#                 'type': 'anomaly',
#                 'score': anomaly_score,
#                 'confidence': min(1.0, abs(anomaly_score))
#             })

#         return threats

# import numpy as np
# from sklearn.ensemble import IsolationForest
# from sklearn.preprocessing import StandardScaler

# class DetectionEngine:
#     def __init__(self):
#         self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
#         self.scaler = StandardScaler()
#         self.signature_rules = self.load_signature_rules()
#         self.training_data = None
#         self.anomaly_threshold = None

#     def load_signature_rules(self):
#         return {
#             'syn_flood': {'condition': lambda f: f.get('tcp_flags') == 2 and f['packet_rate'] > 100},
#             'port_scan': {'condition': lambda f: f['packet_size'] < 100 and f['packet_rate'] > 50}
#         }

#     def train_anomaly_detector(self, normal_traffic_data):
#         if normal_traffic_data.size == 0:
#             raise ValueError("Training data cannot be empty")

#         normal_traffic_data = self.scaler.fit_transform(normal_traffic_data)
#         self.anomaly_detector.fit(normal_traffic_data)
#         self.training_data = normal_traffic_data

#         # 🔥 Adjusted Threshold: Use 1st percentile instead of 5th percentile
#         scores = self.anomaly_detector.score_samples(self.training_data)
#         self.anomaly_threshold = np.percentile(scores, 1)  # Make it less strict

#     def detect_threats(self, features):
#         threats = []

#         # Signature-based detection
#         for rule_name, rule in self.signature_rules.items():
#             if rule['condition'](features):
#                 threats.append({'type': 'signature', 'rule': rule_name, 'confidence': 1.0})

#         if self.training_data is None:
#             raise RuntimeError("Anomaly detector has not been trained.")

#         feature_vector = np.array([[features['packet_size'], features['packet_rate'], features['byte_rate']]])
#         feature_vector = self.scaler.transform(feature_vector)

#         anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]

#         # 🔥 New Condition: Less aggressive anomaly detection
#         if anomaly_score < self.anomaly_threshold:
#             threats.append({'type': 'anomaly', 'score': anomaly_score, 'confidence': min(1.0, abs(anomaly_score))})

#         return threats

# # 🚀 TRAIN IDS WITH MORE REALISTIC NORMAL TRAFFIC DATA
# normal_traffic = np.array([
#     [600, 10, 100],  # Typical web request
#     [650, 15, 120],  # Slightly different normal packet
#     [550, 12, 110],  # Another variation of normal traffic
#     [580, 9, 95]     # More normal data
# ] * 25)  # Multiply to get 100 samples

# engine = DetectionEngine()
# engine.train_anomaly_detector(normal_traffic)

# # ✅ TESTING IDS WITH BOTH THREAT AND NO-THREAT CASES
# test_packet_normal = {'packet_size': 600, 'packet_rate': 10, 'byte_rate': 100, 'tcp_flags': 0}  # No Threat
# test_packet_anomalous = {'packet_size': 50, 'packet_rate': 120, 'byte_rate': 500, 'tcp_flags': 2}  # SYN Flood Attack

# threats_normal = engine.detect_threats(test_packet_normal)
# threats_anomalous = engine.detect_threats(test_packet_anomalous)

# print(f"🚀 Threats detected (Normal Case): {threats_normal}")      # Expected: []
# print(f"🔥 Threats detected (Anomalous Case): {threats_anomalous}")  # Expected: [{...threat info...}]

# import numpy as np
# from sklearn.ensemble import IsolationForest
# from sklearn.preprocessing import StandardScaler

# class DetectionEngine:
#     def __init__(self):
#         self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
#         self.scaler = StandardScaler()
#         self.signature_rules = self.load_signature_rules()
#         self.training_data = None
#         self.anomaly_threshold = None

#     def load_signature_rules(self):
#         return {
#             'syn_flood': {'condition': lambda f: f.get('tcp_flags') == 2 and f['packet_rate'] > 100},
#             'port_scan': {'condition': lambda f: f['packet_size'] < 100 and f['packet_rate'] > 50},
#             'ddos_attack': {'condition': lambda f: f['packet_rate'] > 500 and f['byte_rate'] > 1000},
#             'malware_traffic': {'condition': lambda f: f['packet_size'] > 1000 and f['byte_rate'] > 2000},
#             'data_exfiltration': {'condition': lambda f: f['packet_size'] > 1500 and f['packet_rate'] > 30}
#         }

#     def train_anomaly_detector(self, normal_traffic_data):
#         if normal_traffic_data.size == 0:
#             raise ValueError("Training data cannot be empty")

#         normal_traffic_data = self.scaler.fit_transform(normal_traffic_data)
#         self.anomaly_detector.fit(normal_traffic_data)
#         self.training_data = normal_traffic_data

#         scores = self.anomaly_detector.score_samples(self.training_data)
#         self.anomaly_threshold = np.percentile(scores, 1)  # Less strict detection

#     def detect_threats(self, features):
#         threats = []

#         # Signature-based detection
#         for rule_name, rule in self.signature_rules.items():
#             if rule['condition'](features):
#                 threats.append({'type': 'signature', 'rule': rule_name, 'confidence': 1.0})

#         if self.training_data is None:
#             raise RuntimeError("Anomaly detector has not been trained.")

#         feature_vector = np.array([[features['packet_size'], features['packet_rate'], features['byte_rate']]])
#         feature_vector = self.scaler.transform(feature_vector)

#         anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]

#         if anomaly_score < self.anomaly_threshold:
#             threats.append({'type': 'anomaly', 'score': anomaly_score, 'confidence': min(1.0, abs(anomaly_score))})

#         return threats
    
#     def get_threat_type(self, threat):
#         threat_mapping = {
#             "Port Scan": "Reconnaissance Attack",
#             "DDoS": "Denial of Service",
#             "SQL Injection": "Web Attack",
#             "Brute Force": "Authentication Attack",
#         }
#         return threat_mapping.get(threat, "Unknown Threat") 

# # 🚀 TRAIN IDS WITH MORE REALISTIC NORMAL TRAFFIC DATA
# normal_traffic = np.array([
#     [600, 10, 100], [650, 15, 120], [550, 12, 110], [580, 9, 95]
# ] * 25)  # 100 samples of normal traffic

# engine = DetectionEngine()
# engine.train_anomaly_detector(normal_traffic)

# # ✅ TESTING IDS WITH MULTIPLE THREAT TYPES
# test_cases = [
#     {'desc': "Normal Traffic", 'features': {'packet_size': 600, 'packet_rate': 10, 'byte_rate': 100, 'tcp_flags': 0}},
#     {'desc': "SYN Flood Attack", 'features': {'packet_size': 50, 'packet_rate': 120, 'byte_rate': 500, 'tcp_flags': 2}},
#     {'desc': "Port Scan", 'features': {'packet_size': 80, 'packet_rate': 60, 'byte_rate': 200, 'tcp_flags': 0}},
#     {'desc': "DDoS Attack", 'features': {'packet_size': 500, 'packet_rate': 600, 'byte_rate': 1200, 'tcp_flags': 0}},
#     {'desc': "Malware Traffic", 'features': {'packet_size': 1200, 'packet_rate': 20, 'byte_rate': 2500, 'tcp_flags': 0}},
#     {'desc': "Data Exfiltration", 'features': {'packet_size': 1600, 'packet_rate': 40, 'byte_rate': 1800, 'tcp_flags': 0}}
# ]

# for case in test_cases:
#     threats = engine.detect_threats(case['features'])
#     print(f"🚀 {case['desc']}: {threats}")







import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json

class DetectionEngine:
    def __init__(self, test_mode=False):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.signature_rules = self.load_signature_rules()
        self.test_mode = test_mode
        self._init_detection_rules()

    def _init_detection_rules(self):
        self.threat_categories = {
            'port_scan': "Reconnaissance",
            'ddos_attack': "Denial of Service",
            'syn_flood': "Network Flood",
            'malware_traffic': "Malware Activity",
            'data_exfiltration': "Data Theft",
            'vertical_scan': "Targeted Reconnaissance",
            'udp_flood': "Network Flood",
            'tcp_fragmentation': "Protocol Anomaly",
            'http_anomaly': "Protocol Anomaly",
            'tunneled_traffic': "Covert Channel",
            'high_short_flow': "Burst Attack",
            'low_and_slow': "Slow Attack"
        }

    def load_signature_rules(self):
        return {
            # Flood/DoS Attacks
            'syn_flood': {
                'condition': lambda f: (f.get('tcp_flags') == 2 and 
                                     f['packet_rate'] > 100),
                'severity': 'critical',
                'description': 'SYN flood attack detected (high SYN packets rate)'
            },
            'ddos_attack': {
                'condition': lambda f: (f['packet_rate'] > 500 and 
                                      f['byte_rate'] > 1000),
                'severity': 'critical',
                'description': 'Potential DDoS attack (extremely high traffic volume)'
            },
            'udp_flood': {
                'condition': lambda f: (f.get('protocol') == 'udp' and 
                                      f['packet_rate'] > 300),
                'severity': 'high',
                'description': 'UDP flood attack detected'
            },
            
            # Scanning/Probing
            'port_scan': {
                'condition': lambda f: (f['packet_size'] < 100 and 
                                      f['packet_rate'] > 50 and 
                                      f['flow_duration'] < 5),  # Short burst in seconds
                'severity': 'medium',
                'description': 'Port scanning activity detected'
            },
            'vertical_scan': {
    'condition': lambda f: (len(set(f.get('dst_ports', []))) == 1 and  # Fixed parentheses
                          f['packet_rate'] > 30 and
                          f['flow_duration'] < 10),
    'severity': 'medium',
    'description': 'Vertical port scan (single host, multiple ports)'
},
            
            # Suspicious Behavior
            'data_exfiltration': {
                'condition': lambda f: (f['packet_size'] > 1500 and 
                                      f['packet_rate'] > 30 and
                                      f['flow_duration'] > 60),  # Sustained over 1 minute
                'severity': 'high',
                'description': 'Possible data exfiltration attempt'
            },
            'tunneled_traffic': {
                'condition': lambda f: (f['byte_rate'] > 500 and 
                                      f.get('protocol') in ['dns', 'icmp'] and
                                      f['flow_duration'] > 30),
                'severity': 'high',
                'description': 'Possible tunneling through DNS/ICMP'
            },
            
            # Protocol Anomalies
            'tcp_fragmentation': {
                'condition': lambda f: (f.get('tcp_flags') is None and 
                                      f['packet_size'] > 1000),
                'severity': 'medium',
                'description': 'TCP fragmentation attack attempt'
            },
            'http_anomaly': {
                'condition': lambda f: (f.get('protocol') == 'http' and 
                                      f['packet_size'] > 2000 and
                                      f['flow_duration'] < 2),
                'severity': 'medium',
                'description': 'Oversized HTTP packets in short timeframe'
            },
            
            # Threshold-based Rules
            'high_short_flow': {
                'condition': lambda f: (f['packet_rate'] > 200 and 
                                      f['flow_duration'] < 3),
                'severity': 'medium',
                'description': 'High packet rate in short flow duration'
            },
            'low_and_slow': {
                'condition': lambda f: (f['packet_rate'] < 5 and 
                                      f['flow_duration'] > 3600),  # 1 hour
                'severity': 'low',
                'description': 'Low-and-slow potential attack'
            }
        }

    def detect_threats(self, features):
        threats = []
        
        try:
            # Signature-based detection
            for rule_name, rule in self.signature_rules.items():
                try:
                    if rule['condition'](features):
                        threats.append({
                            'type': 'signature',
                            'rule': rule_name,
                            'category': self.threat_categories.get(rule_name, "Unknown"),
                            'severity': rule['severity'],
                            'confidence': 1.0,
                            'features': features,
                            'description': rule.get('description', '')
                        })
                except Exception as e:
                    print(f"Error evaluating rule {rule_name}: {str(e)}")
                    continue

            # Anomaly detection (only in live mode)
            if not self.test_mode and hasattr(self, 'anomaly_threshold'):
                try:
                    feature_vector = np.array([[features['packet_size'], 
                                             features['packet_rate'], 
                                             features['byte_rate']]])
                    feature_vector = self.scaler.transform(feature_vector)
                    anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
                    
                    if anomaly_score < self.anomaly_threshold:
                        threats.append({
                            'type': 'anomaly',
                            'score': float(anomaly_score),
                            'confidence': min(1.0, abs(anomaly_score)),
                            'features': features,
                            'description': 'Anomalous traffic pattern detected'
                        })
                except Exception as e:
                    print(f"Anomaly detection error: {str(e)}")

        except Exception as e:
            print(f"Detection error: {str(e)}")
            return []

        return threats

    def train_anomaly_detector(self, normal_traffic_data):
        """Train the anomaly detector with normal traffic data"""
        try:
            normal_traffic_data = self.scaler.fit_transform(normal_traffic_data)
            self.anomaly_detector.fit(normal_traffic_data)
            scores = self.anomaly_detector.score_samples(normal_traffic_data)
            self.anomaly_threshold = np.percentile(scores, 1)  # 1% percentile
            print("✅ Anomaly detector trained successfully")
        except Exception as e:
            print(f"Error training anomaly detector: {str(e)}")
            raise


