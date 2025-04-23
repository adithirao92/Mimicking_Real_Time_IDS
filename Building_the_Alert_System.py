# import logging
# import json
# from datetime import datetime

# class AlertSystem:
#     def __init__(self, log_file="ids_alerts.log"):
#         self.logger = logging.getLogger("IDS_Alerts")
#         self.logger.setLevel(logging.INFO)

#         handler = logging.FileHandler(log_file)
#         formatter = logging.Formatter(
#             '%(asctime)s - %(levelname)s - %(message)s'
#         )
#         handler.setFormatter(formatter)
#         self.logger.addHandler(handler)

#     def generate_alert(self, threat, packet_info):
#         alert = {
#             'timestamp': datetime.now().isoformat(),
#             'threat_type': threat['type'],
#             'source_ip': packet_info.get('source_ip'),
#             'destination_ip': packet_info.get('destination_ip'),
#             'confidence': threat.get('confidence', 0.0),
#             'details': threat
#         }

#         self.logger.warning(json.dumps(alert))

#         if threat['confidence'] > 0.8:
#             self.logger.critical(
#                 f"High confidence threat detected: {json.dumps(alert)}"
#             )
#             # Implement additional notification methods here
#             # (e.g., email, Slack, SIEM integration)







import json
import logging
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.log_file = log_file
        self.logger = logging.getLogger("IDS_Alerts")
        self._setup_logging()
        
    def _setup_logging(self):
        handler = logging.FileHandler(self.log_file)
        formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def generate_alert(self, threat):
        try:
            # Convert non-serializable objects
            if 'features' in threat:
                features = threat['features']
                if 'tcp_flags' in features:
                    features['tcp_flags'] = str(features['tcp_flags'])
            
            alert = {
                'timestamp': datetime.now().isoformat(),
                **threat
            }
            
            self._log_alert(alert)
            return alert
            
        except Exception as e:
            print(f"Error generating alert: {str(e)}")
            return None

    def _log_alert(self, alert):
        try:
            log_entry = json.dumps(alert, default=self._json_serializer)
            
            if alert.get('severity') == 'critical':
                self.logger.critical(log_entry)
            elif alert.get('confidence', 0) > 0.8:
                self.logger.error(log_entry)
            else:
                self.logger.warning(log_entry)
                
        except Exception as e:
            print(f"Error logging alert: {str(e)}")

    def _json_serializer(self, obj):
        """Handle non-serializable objects"""
        if hasattr(obj, '__str__'):
            return str(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")