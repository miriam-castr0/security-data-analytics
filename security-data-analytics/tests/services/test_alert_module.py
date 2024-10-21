import os, sys
import unittest
from unittest.mock import Mock, patch
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if src_path not in sys.path:
    sys.path.append(src_path)
from src.broker.kafka_producer import Producer
from src.utils.constants import TIMESTAMP_KEY
from src.services.alert_module import AlertModule  # ajuste conforme necessário

class TestAlertModule(unittest.TestCase):

    def setUp(self):
        self.topics = ['test_topic']
        self.alert_module = AlertModule(topics=self.topics)

    @patch.object(Producer, 'send_to_topic')
    def test_alert_threats(self, mock_send_to_topic):
        threat_report = Mock()
        threat_report.id = 1
        threat_report.pcap_id = 'pcap_1234'
        threat_report.dest_ip = '192.168.0.1'
        threat_report.source_ip = '10.0.0.1'
        threat_report.status.value = 2
        threat_report.protocol = 6
        threat_report.ip_count = 5
        threat_report.timestamp.isoformat.return_value = '2024-06-25T10:00:00Z'
        threat_report.last_updated.isoformat.return_value = '2024-06-25T10:05:00Z'
        prediction_time = '2024-06-25T10:10:00Z'

        threat_json = {
            'id': threat_report.id,
            'pcap_id': threat_report.pcap_id,
            'dest_ip': threat_report.dest_ip,
            'source_ip': threat_report.source_ip,
            'status': int(threat_report.status.value),
            'protocol': threat_report.protocol,
            'ip_count': threat_report.ip_count,
            'timestamp': threat_report.timestamp.isoformat(),
            'prediciton_time': prediction_time,
            'last_updated': threat_report.last_updated.isoformat()
        }

        self.alert_module.alert_threats(threat_json)
        
        mock_send_to_topic.assert_called_once_with(key='1', message=threat_json)

    @patch.object(Producer, 'send_to_topic')
    def test_alert_model_accuracy(self, mock_send_to_topic):
        results = [
            ('2024-06-25T10:00:00Z', 0.95, 0.93, 0.96, 0.02, 0.98, 0.04, 'source1', '2024-06-25T10:00:01Z')
        ]
        
        self.alert_module.alert_model_accuracy(results)
        
        expected_message = [{
            'prediction_time': '2024-06-25T10:00:00Z',
            'accuracy': 0.95,
            'f1': 0.93,
            'true_positive_rate': 0.96,
            'false_positive_rate': 0.02,
            'true_negative_rate': 0.98,
            'false_negative_rate': 0.04,
            'data_source': 'source1',
            TIMESTAMP_KEY: '2024-06-25T10:00:01Z'
        }]
        
        mock_send_to_topic.assert_called_once_with(key=str(expected_message[0]['accuracy']), message=expected_message)

