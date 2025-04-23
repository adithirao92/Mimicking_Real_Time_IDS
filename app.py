# from flask import Flask, render_template, request
# import numpy as np
# from sklearn.ensemble import IsolationForest
# from sklearn.preprocessing import StandardScaler

# app = Flask(__name__)

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
#         normal_traffic_data = self.scaler.fit_transform(normal_traffic_data)
#         self.anomaly_detector.fit(normal_traffic_data)
#         scores = self.anomaly_detector.score_samples(normal_traffic_data)
#         self.anomaly_threshold = np.percentile(scores, 1)

#     def detect_threats(self, features):
#         threats = []

#         for rule_name, rule in self.signature_rules.items():
#             if rule['condition'](features):
#                 threats.append({'type': 'signature', 'rule': rule_name, 'confidence': 1.0})

#         feature_vector = np.array([[features['packet_size'], features['packet_rate'], features['byte_rate']]])
#         feature_vector = self.scaler.transform(feature_vector)

#         anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
#         if anomaly_score < self.anomaly_threshold:
#             threats.append({'type': 'anomaly', 'score': anomaly_score, 'confidence': min(1.0, abs(anomaly_score))})

#         return threats

# normal_traffic = np.array([
#     [600, 10, 100], [650, 15, 120], [550, 12, 110], [580, 9, 95]
# ] * 25)

# engine = DetectionEngine()
# engine.train_anomaly_detector(normal_traffic)

# @app.route("/", methods=["GET", "POST"])
# def index():
#     if request.method == "POST":
#         packet_size = int(request.form["packet_size"])
#         packet_rate = int(request.form["packet_rate"])
#         byte_rate = int(request.form["byte_rate"])
#         tcp_flags = int(request.form["tcp_flags"])

#         test_packet = {
#             "packet_size": packet_size,
#             "packet_rate": packet_rate,
#             "byte_rate": byte_rate,
#             "tcp_flags": tcp_flags,
#         }

#         threats_detected = engine.detect_threats(test_packet)
#         return render_template("results.html", threats=threats_detected)

#     return render_template("index.html")

# if __name__ == "__main__":
#     app.run(debug=True)



# from flask import Flask, render_template, jsonify
# from threading import Thread
# from PacketCapture import PacketCapture
# from Building_the_Detection_Engine import DetectionEngine
# from Traffic_Analysis_Module import TrafficAnalyzer
# from Building_the_Alert_System import AlertSystem
# import time
# from datetime import datetime
# import queue

# app = Flask(__name__)

# # Global state
# threats = []
# stats = {
#     'packets_processed': 0,
#     'threats_detected': 0,
#     'last_alert': None
# }

# # Complete test packets dictionary
# TEST_PACKETS = {
#     'normal': {
#         'packet_size': 600,
#         'packet_rate': 10,
#         'byte_rate': 100,
#         'tcp_flags': 0,
#         'src_ip': '192.168.1.100',
#         'dst_ip': '192.168.1.1'
#     },
#     'port_scan': {
#         'packet_size': 80,
#         'packet_rate': 60,
#         'byte_rate': 200,
#         'tcp_flags': 0,
#         'src_ip': '10.0.0.15',
#         'dst_ip': '192.168.1.100'
#     },
#     'syn_flood': {
#         'packet_size': 50,
#         'packet_rate': 120,
#         'byte_rate': 500,
#         'tcp_flags': 2,  # SYN flag
#         'src_ip': '172.16.0.5',
#         'dst_ip': '192.168.1.100'
#     },
#     'ddos': {
#         'packet_size': 500,
#         'packet_rate': 600,
#         'byte_rate': 1200,
#         'tcp_flags': 0,
#         'src_ip': '185.143.223.1',
#         'dst_ip': '192.168.1.100'
#     },
#     'data_exfil': {
#         'packet_size': 1600,
#         'packet_rate': 40,
#         'byte_rate': 1800,
#         'tcp_flags': 0,
#         'src_ip': '192.168.1.50',
#         'dst_ip': '45.33.12.75'
#     }
# }

# def init_ids(test_mode=False):
#     return {
#         'capture': PacketCapture(test_mode),
#         'analyzer': TrafficAnalyzer(),
#         'detector': DetectionEngine(test_mode),
#         'alerter': AlertSystem()
#     }

# def run_ids(ids, interface="en0"):
#     try:
#         ids['capture'].start_capture(interface)
        
#         while True:
#             try:
#                 packet = ids['capture'].packet_queue.get(timeout=1)
#                 if not packet:
#                     continue
                    
#                 print(f"Processing packet: {packet.summary()}")  # Debug print
                
#                 features = ids['analyzer'].analyze_packet(packet)
#                 if not features:
#                     print("Skipping non-TCP/IP packet")
#                     continue
                    
#                 print(f"Features extracted: {features}")  # Debug print
                
#                 detected = ids['detector'].detect_threats(features)
                
#                 if detected:
#                     print(f"Threats detected: {detected}")  # Debug print
#                     for threat in detected:
#                         alert = ids['alerter'].generate_alert(threat)
#                         threats.append(alert)
                        
#             except queue.Empty:
#                 continue
#             except Exception as e:
#                 print(f"Error processing packet: {str(e)}")
#                 import traceback
#                 traceback.print_exc()
                
#     except KeyboardInterrupt:
#         print("Stopping IDS...")
#     except Exception as e:
#         print(f"Fatal error: {str(e)}")
#         import traceback
#         traceback.print_exc()
#     finally:
#         ids['capture'].stop()

# @app.route('/')
# def dashboard():
#     return render_template('dashboard.html')

# @app.route('/api/threats')
# def get_threats():
#     return jsonify({
#         'threats': threats[-100:],  # Last 100 alerts
#         'stats': stats
#     })

# @app.route('/api/test/<test_type>')
# def run_test(test_type):
#     if test_type in TEST_PACKETS:
#         # Create a mock packet with timestamp
#         test_packet = {
#             **TEST_PACKETS[test_type],
#             'timestamp': datetime.now(),
#             'IP': type('', (), {'src': TEST_PACKETS[test_type]['src_ip'], 
#                                'dst': TEST_PACKETS[test_type]['dst_ip']}),
#             'TCP': type('', (), {'flags': TEST_PACKETS[test_type]['tcp_flags']})
#         }
        
#         ids['capture'].inject_test_packet(test_packet)
#         return jsonify({
#             'status': f'Injected {test_type} test',
#             'expected_threat': list(ids['detector'].signature_rules.keys())
#         })
#     return jsonify({'error': 'Invalid test type', 'valid_types': list(TEST_PACKETS.keys())}), 400

# if __name__ == '__main__':
#     ids = init_ids(test_mode=False)  # Set test_mode=True for development
#     Thread(target=run_ids, args=(ids,), daemon=True).start()
#     app.run(debug=True, port=5000)






# from flask import Flask, render_template, jsonify
# from threading import Thread
# from PacketCapture import PacketCapture
# from Building_the_Detection_Engine import DetectionEngine
# from Traffic_Analysis_Module import TrafficAnalyzer
# from Building_the_Alert_System import AlertSystem
# import time
# from datetime import datetime
# import queue

# app = Flask(__name__)

# # Global state
# threats = []
# stats = {
#     'packets_processed': 0,
#     'threats_detected': 0,
#     'last_alert': None
# }

# # Complete test packets dictionary
# TEST_PACKETS = {
#     'normal': {
#         'packet_size': 600,
#         'packet_rate': 10,
#         'byte_rate': 100,
#         'tcp_flags': 0,
#         'src_ip': '192.168.1.100',
#         'dst_ip': '192.168.1.1'
#     },
#     'port_scan': {
#         'packet_size': 80,
#         'packet_rate': 60,
#         'byte_rate': 200,
#         'tcp_flags': 0,
#         'src_ip': '10.0.0.15',
#         'dst_ip': '192.168.1.100'
#     },
#     'syn_flood': {
#         'packet_size': 50,
#         'packet_rate': 120,
#         'byte_rate': 500,
#         'tcp_flags': 2,  # SYN flag
#         'src_ip': '172.16.0.5',
#         'dst_ip': '192.168.1.100'
#     },
#     'ddos': {
#         'packet_size': 500,
#         'packet_rate': 600,
#         'byte_rate': 1200,
#         'tcp_flags': 0,
#         'src_ip': '185.143.223.1',
#         'dst_ip': '192.168.1.100'
#     },
#     'data_exfil': {
#         'packet_size': 1600,
#         'packet_rate': 40,
#         'byte_rate': 1800,
#         'tcp_flags': 0,
#         'src_ip': '192.168.1.50',
#         'dst_ip': '45.33.12.75'
#     }
# }

# def init_ids(test_mode=False):
#     return {
#         'capture': PacketCapture(test_mode),
#         'analyzer': TrafficAnalyzer(),
#         'detector': DetectionEngine(test_mode),
#         'alerter': AlertSystem()
#     }

# def run_ids(ids, interface="en0"):
#     try:
#         ids['capture'].start_capture(interface)
        
#         while True:
#             try:
#                 packet = ids['capture'].packet_queue.get(timeout=1)
#                 if not packet:
#                     continue
                    
#                 print(f"Processing packet: {packet.summary()}")  # Debug print
                
#                 # Update packets processed count
#                 stats['packets_processed'] += 1
                
#                 features = ids['analyzer'].analyze_packet(packet)
#                 if not features:
#                     print("Skipping non-TCP/IP packet")
#                     continue
                    
#                 print(f"Features extracted: {features}")  # Debug print
                
#                 detected = ids['detector'].detect_threats(features)
                
#                 if detected:
#                     print(f"Threats detected: {detected}")  # Debug print
#                     for threat in detected:
#                         alert = ids['alerter'].generate_alert(threat)
#                         threats.append(alert)
#                         # Update threat count and last alert time
#                         stats['threats_detected'] += 1
#                         stats['last_alert'] = datetime.now().timestamp()
                        
#             except queue.Empty:
#                 continue
#             except Exception as e:
#                 print(f"Error processing packet: {str(e)}")
#                 import traceback
#                 traceback.print_exc()
                
#     except KeyboardInterrupt:
#         print("Stopping IDS...")
#     except Exception as e:
#         print(f"Fatal error: {str(e)}")
#         import traceback
#         traceback.print_exc()
#     finally:
#         ids['capture'].stop()

# @app.route('/')
# def dashboard():
#     return render_template('dashboard.html')

# @app.route('/api/threats')
# def get_threats():
#     return jsonify({
#         'threats': threats[-100:],  # Last 100 alerts
#         'stats': {
#             'packets_processed': stats['packets_processed'],
#             'threats_detected': stats['threats_detected'],
#             'last_alert': stats['last_alert']
#         }
#     })

# @app.route('/api/test/<test_type>')
# def run_test(test_type):
#     if test_type in TEST_PACKETS:
#         # Create a mock packet with timestamp
#         test_packet = {
#             **TEST_PACKETS[test_type],
#             'timestamp': datetime.now(),
#             'IP': type('', (), {'src': TEST_PACKETS[test_type]['src_ip'], 
#                                'dst': TEST_PACKETS[test_type]['dst_ip']}),
#             'TCP': type('', (), {'flags': TEST_PACKETS[test_type]['tcp_flags']})
#         }
        
#         ids['capture'].inject_test_packet(test_packet)
        
#         # Update stats for test packets too
#         stats['packets_processed'] += 1
#         if test_type != 'normal':  # Only count as threat if not normal traffic
#             stats['threats_detected'] += 1
#             stats['last_alert'] = datetime.now().timestamp()
        
#         return jsonify({
#             'status': f'Injected {test_type} test',
#             'expected_threat': list(ids['detector'].signature_rules.keys())
#         })
#     return jsonify({'error': 'Invalid test type', 'valid_types': list(TEST_PACKETS.keys())}), 400

# if __name__ == '__main__':
#     ids = init_ids(test_mode=False)  # Set test_mode=True for development
#     Thread(target=run_ids, args=(ids,), daemon=True).start()
#     app.run(debug=True, port=5000)



from flask import Flask, render_template, jsonify, request
from threading import Thread
from PacketCapture import PacketCapture
from Building_the_Detection_Engine import DetectionEngine
from Traffic_Analysis_Module import TrafficAnalyzer
from Building_the_Alert_System import AlertSystem
import time
from datetime import datetime
import queue
import ipaddress
from functools import lru_cache

app = Flask(__name__)

# Global state
threats = []
stats = {
    'packets_processed': 0,
    'threats_detected': 0,
    'last_alert': None
}

# Complete test packets dictionary
TEST_PACKETS = {
    'normal': {
        'packet_size': 600,
        'packet_rate': 10,
        'byte_rate': 100,
        'tcp_flags': 0,
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.1'
    },
    'port_scan': {
        'packet_size': 80,
        'packet_rate': 60,
        'byte_rate': 200,
        'tcp_flags': 0,
        'src_ip': '10.0.0.15',
        'dst_ip': '192.168.1.100'
    },
    'syn_flood': {
        'packet_size': 50,
        'packet_rate': 120,
        'byte_rate': 500,
        'tcp_flags': 2,  # SYN flag
        'src_ip': '172.16.0.5',
        'dst_ip': '192.168.1.100'
    },
    'ddos': {
        'packet_size': 500,
        'packet_rate': 600,
        'byte_rate': 1200,
        'tcp_flags': 0,
        'src_ip': '185.143.223.1',
        'dst_ip': '192.168.1.100'
    },
    'data_exfil': {
        'packet_size': 1600,
        'packet_rate': 40,
        'byte_rate': 1800,
        'tcp_flags': 0,
        'src_ip': '192.168.1.50',
        'dst_ip': '45.33.12.75'
    }
}

def init_ids(test_mode=False):
    return {
        'capture': PacketCapture(test_mode),
        'analyzer': TrafficAnalyzer(),
        'detector': DetectionEngine(test_mode),
        'alerter': AlertSystem()
    }

def run_ids(ids, interface="en0"):
    try:
        ids['capture'].start_capture(interface)
        
        while True:
            try:
                packet = ids['capture'].packet_queue.get(timeout=1)
                if not packet:
                    continue
                    
                print(f"Processing packet: {packet.summary()}")  # Debug print
                
                # Update packets processed count
                stats['packets_processed'] += 1
                
                features = ids['analyzer'].analyze_packet(packet)
                if not features:
                    print("Skipping non-TCP/IP packet")
                    continue
                    
                print(f"Features extracted: {features}")  # Debug print
                
                detected = ids['detector'].detect_threats(features)
                
                if detected:
                    print(f"Threats detected: {detected}")  # Debug print
                    for threat in detected:
                        alert = ids['alerter'].generate_alert(threat)
                        threats.append(alert)
                        # Update threat count and last alert time
                        stats['threats_detected'] += 1
                        stats['last_alert'] = datetime.now().timestamp()
                        
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error processing packet: {str(e)}")
                import traceback
                traceback.print_exc()
                
    except KeyboardInterrupt:
        print("Stopping IDS...")
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        ids['capture'].stop()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/threats')
def get_threats():
    return jsonify({
        'threats': threats[-100:],  # Last 100 alerts
        'stats': {
            'packets_processed': stats['packets_processed'],
            'threats_detected': stats['threats_detected'],
            'last_alert': stats['last_alert']
        }
    })

@app.route('/api/check_ip', methods=['POST'])
def check_ip():
    ip_address = request.form.get('ip')
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    try:
        # Validate IP address
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({'error': 'Invalid IP address format'}), 400
    
    # Check if IP exists in any threat
    ip_threats = []
    for threat in threats:
        if threat.get('features', {}).get('src_ip') == ip_address:
            ip_threats.append({
                'timestamp': threat.get('timestamp'),
                'type': threat.get('category'),
                'severity': threat.get('severity'),
                'confidence': threat.get('confidence'),
                'description': threat.get('description')
            })
    
    # Check external threat intelligence
    threat_intel = check_external_threat_intelligence(ip_address)
    
    # Perform additional analysis
    analysis = analyze_ip(ip_address)
    
    return jsonify({
        'ip': ip_address,
        'threats_found': len(ip_threats) > 0,
        'threat_details': ip_threats,
        'threat_intel': threat_intel,
        'analysis': analysis
    })

@lru_cache(maxsize=1024)
def check_external_threat_intelligence(ip_address):
    """Check multiple threat intelligence sources"""
    results = {
        'reputation': 'unknown',
        'threat_types': [],
        'sources': []
    }
    
    # 1. Check if IP is in any of our test malicious IPs
    known_malicious_ips = {
        '185.143.223.1': {'reputation': 'malicious', 'threat_type': 'DDoS'},
        '10.0.0.15': {'reputation': 'suspicious', 'threat_type': 'Scanner'}
    }
    
    if ip_address in known_malicious_ips:
        results.update(known_malicious_ips[ip_address])
        results['sources'].append('Internal Database')
    
    # 2. Check if IP is private/reserved (not routable on public internet)
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            results['reputation'] = 'internal'
            results['threat_types'].append('Internal Network IP')
            results['sources'].append('IP Analysis')
    except ValueError:
        pass
    
    # 3. Check if IP is in suspicious ranges (you can expand this)
    suspicious_ranges = [
        '192.168.1.0/24',  # Example: your local network
        '10.0.0.0/8'       # Private network range
    ]
    
    for network in suspicious_ranges:
        if ipaddress.ip_address(ip_address) in ipaddress.ip_network(network):
            results['reputation'] = 'suspicious'
            results['threat_types'].append('Local Network IP')
            results['sources'].append('Network Analysis')
            break
    
    return results

def analyze_ip(ip_address):
    """Perform additional analysis on the IP address"""
    analysis = {
        'ip_type': 'public',
        'is_malicious': False,
        'risk_factors': [],
        'recommendations': []
    }
    
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        
        # Determine IP type
        if ip_obj.is_private:
            analysis['ip_type'] = 'private'
            analysis['risk_factors'].append('Internal network IP')
        elif ip_obj.is_multicast:
            analysis['ip_type'] = 'multicast'
        elif ip_obj.is_loopback:
            analysis['ip_type'] = 'loopback'
        elif ip_obj.is_link_local:
            analysis['ip_type'] = 'link-local'
        
        # Check for suspicious characteristics
        if str(ip_obj).startswith('172.') and ip_obj.is_private:
            analysis['risk_factors'].append('Potential AWS/cloud internal IP')
        
        # Basic reputation check (in a real system, use a proper reputation service)
        if ip_address in ['185.143.223.1', '10.0.0.15']:
            analysis['is_malicious'] = True
            analysis['risk_factors'].append('Known malicious IP in test data')
        
        # Generate recommendations
        if analysis['ip_type'] == 'private' and not analysis['is_malicious']:
            analysis['recommendations'].append('Monitor internal traffic from this IP')
        elif analysis['is_malicious']:
            analysis['recommendations'].append('Block this IP immediately')
        else:
            analysis['recommendations'].append('No immediate action needed')
            
    except ValueError:
        analysis['error'] = 'Invalid IP address'
    
    return analysis

@app.route('/api/test/<test_type>')
def run_test(test_type):
    if test_type in TEST_PACKETS:
        # Create a mock packet with timestamp
        test_packet = {
            **TEST_PACKETS[test_type],
            'timestamp': datetime.now(),
            'IP': type('', (), {'src': TEST_PACKETS[test_type]['src_ip'], 
                               'dst': TEST_PACKETS[test_type]['dst_ip']}),
            'TCP': type('', (), {'flags': TEST_PACKETS[test_type]['tcp_flags']})
        }
        
        ids['capture'].inject_test_packet(test_packet)
        
        # Update stats for test packets too
        stats['packets_processed'] += 1
        if test_type != 'normal':  # Only count as threat if not normal traffic
            stats['threats_detected'] += 1
            stats['last_alert'] = datetime.now().timestamp()
        
        return jsonify({
            'status': f'Injected {test_type} test',
            'expected_threat': list(ids['detector'].signature_rules.keys())
        })
    return jsonify({'error': 'Invalid test type', 'valid_types': list(TEST_PACKETS.keys())}), 400

if __name__ == '__main__':
    ids = init_ids(test_mode=False)  # Set test_mode=True for development
    Thread(target=run_ids, args=(ids,), daemon=True).start()
    app.run(debug=True, port=5000)