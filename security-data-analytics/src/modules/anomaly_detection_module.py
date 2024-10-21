from src.services.anomaly_detection_engine import AnomalyDetectionEngine
from src.utils.common_functions import new_consumer_thread
from src.utils.constants import ANOMALY_DETECTION_TOPIC


# TODO Put here all logic related to module

def init_anomaly_detector():
    anomaly_detector_engine = AnomalyDetectionEngine()
    return new_consumer_thread(ANOMALY_DETECTION_TOPIC, anomaly_detector_engine.processing_pcap_file)
