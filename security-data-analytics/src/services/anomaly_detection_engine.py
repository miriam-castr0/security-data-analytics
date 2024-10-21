import logging
import os
import time

from src.services.alert_module import AlertModule
from src.broker.kafka_producer import Producer
from src.lucid.lucid_cnn import predict_pcap
from src.services.real_time_analytics_stream_processing import RealTimeAnalyticsStreamProcessing
from src.services.threat_classification_module import ThreatClassificationModule
from src.services.reporting_module import ReportingModule
from src.utils.constants import MODEL_PATH, MAX_RETRIES, ALERT_THREATS_TOPIC
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



class AnomalyDetectionEngine():
    def __init__(self):
        self.pcap_data = None
        self.model_filename = MODEL_PATH.split('/')[-1].strip()
        self.filename_prefix = self.model_filename.split('n')[0] + 'n-'
        self.time_window = int(self.filename_prefix.split('t-')[0])
        self.max_flow_len = int(self.filename_prefix.split('t-')[1].split('n-')[0])
        self.dashboard = RealTimeAnalyticsStreamProcessing()
        self.threat_report = ReportingModule()
        self.threat_classification = ThreatClassificationModule()
        self.alert_module = AlertModule(ALERT_THREATS_TOPIC)



    def processing_pcap_file(self, pcap_id, file_path):
        pt0 = time.time()
        for retry in range(MAX_RETRIES):
            try:
                #self.__read_pcap_file(file_path)
                pcap_id = pcap_id
                keys, X_samples, Y_pred, ddos_rate, prediction_time = self.__detect_ddos(file_path)

                if len(X_samples) > 0:
                    keys_classification, Y_pred_classification, prediction_time_cls, ddos_rate_type = self.threat_classification.classify_threat(keys, X_samples, Y_pred)

                
                # update results to populate dashboards and return a df with info, some data processing is done
                threat_report_data_frame = self.dashboard.update_results(keys, Y_pred, ddos_rate, prediction_time, keys_classification, Y_pred_classification,)
                logger.info(f"threat report: {threat_report_data_frame}")

                self.dashboard.update_ddos_rate_type(ddos_rate_type, prediction_time_cls, Y_pred_classification)

                pt1 = time.time()
                prediction_time = pt1-pt0
                threats= self.threat_report.store_reports(threat_report_data_frame, int(pcap_id), prediction_time)

                if threats:  # verify if it's not empty and there are threats
                    logger.info(f"threat: {threats}")
                    self.__alert_ddos_detection(threats)
                    

                    pcap_response = self.threat_report.update_pcap(pcap_id=int(pcap_id), ddos_rate=ddos_rate, is_analised=True, error=False,prediction_time=prediction_time)
                    pcap_update = {
                        'id': pcap_response.id,
                        'probe_id': pcap_response.probe_id,
                        'filename': pcap_response.filename,
                        'ddos_rate': pcap_response.ddos_rate,
                        'number_packets': pcap_response.number_packets,
                        'detection_time': pcap_response.detection_time,
                        'is_analysed': pcap_response.is_analysed
                    }
                    logger.info(f"pcap update: {pcap_update}")

                elif not threats:  # There are no threats
                    # dont alert SD, only updates pcap entry because it is analyzed
                    pcap_response = self.threat_report.update_pcap(int(pcap_id), ddos_rate, is_analised=True, error=False, prediction_time=prediction_time)
                    logger.info(f"pcap update: {pcap_response}")
                break
            except Exception as e:
                logger.error(f"Error processing PCAP file on attempt {retry + 1}: {e}")

                # All tries fail
                if retry == MAX_RETRIES - 1:
                    logger.error("Max retries reached, unable to process PCAP file")
                    self.threat_report.update_pcap(int(pcap_id), ddos_rate=None, is_analised=False, error=True, prediction_time=None)
        pt2 = time.time()
        total_time = pt2-pt0
        logger.info(f"Total Time: {total_time}")
        # Remove file
        try:
            os.remove(file_path)
        except Exception as e:
            logger.error(f"Error removing PCAP file: {e}")

    """  def __read_pcap_file(self, file_path):
        # Read the reconstructed pcap file into a bytes object --> just for log pruposes
        with open(file_path, 'rb') as f:
            # TODO Valorates another ways of read a 2GB size file
            self.pcap_data = f.read()
        logger.info(f"PCAP data size: {len(self.pcap_data)} bytes")
        # TODO Important: self.pcap_data its not used, why do it ? """

    def __detect_ddos(self, file_path):
        keys, X_samples, Y_pred, ddos_rate, prediction_time = predict_pcap(file_path, MODEL_PATH, self.time_window,
                                                                self.max_flow_len)
        logger.info(f"DDoS detection completed. Rate: {ddos_rate}, Prediction time: {prediction_time}")
        return keys, X_samples, Y_pred, ddos_rate, prediction_time

    def __alert_ddos_detection(self, threats):
        # send alert after post, this way we have the complete object with threat report id a stuff
        for threat in threats:
            self.alert_module.alert_threats(threat)
