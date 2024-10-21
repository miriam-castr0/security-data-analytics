import logging
import os
import sys
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if src_path not in sys.path:
    sys.path.append(src_path)

import src.modules.data_processing_and_transformation_module as DPTE
import src.modules.real_time_analytics_and_stream_processing_module as RASP
import src.modules.anomaly_detection_module as ADE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


if __name__ == "__main__":
    RASP.init_dashboard()
    ADE.init_anomaly_detector()
    kafka_consumer = DPTE.init_pcap_reconstructor()
    kafka_consumer.wait_for_connection_to_finish()
    kafka_consumer.wait_for_consumption_to_finish()

