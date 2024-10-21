import json
import logging
import os
import threading

from pandas import Timestamp
import src.database.spds_interactions as spds_interactions
import requests

DDOS_STATUS_KEY = 'ddos_status'
PCAP_ID_KEY = 'pcap_id'
STATUS_KEY = 'status'
SOURCE_IP_KEY = 'source_ip'
DEST_IP_KEY = 'dest_ip'
TIMESTAMP_KEY= 'timestamp'
PROTOCOL_KEY = 'protocol'
DDOS_TYPE_KEY = 'ddos_type'
IP_COUNT = 'ip_count'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportingModule:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ReportingModule, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if not self._initialized:
            self.pcap_url = os.getenv('PCAP')
            self.threat_url = os.environ.get('THREAT_REPORT')
            self._initialized = True

    def __send_post(self, url, data):
        # TODO develop that with future (?)
        headers = {'Content-Type': 'application/json'}
        status_code = None
        count_tries = 0
        try:
            while status_code != 201 and count_tries < 3:
                response = requests.post(url, headers=headers, json=data)
                status_code = response.status_code
                if response.status_code == 201:
                    logger.info(f"Threat Response: {response.json()}")
                    return response.json()
                else:
                    logger.error(f"error: {response.status_code}, message: {response.text}")
                count_tries += 1

        except requests.exceptions.RequestException as e:
            logger.error(str(e))

    def filter_by_ddos(self, group):
        return (group['ddos_status'] == True).any()

    def convert_dates_to_string(self, data):
        for key, value in data.items():
            if isinstance(value, Timestamp):
                data[key] = str(value)
        return data

    def store_reports(self, data_df, pcap_id, prediction_time):
        threat_reports = []
    

        threats_grouped = data_df[data_df[DDOS_STATUS_KEY]].groupby([SOURCE_IP_KEY, DEST_IP_KEY, PROTOCOL_KEY, DDOS_TYPE_KEY])\
                                                            .agg(ip_count=(SOURCE_IP_KEY, 'size'), timestamp=(TIMESTAMP_KEY, 'first'))\
                                                            .reset_index()

        for index, row in threats_grouped.iterrows():
            
            threat_data = row.to_dict()  # Convert line in dict excluding 'ddos_status'
            threat_data[PCAP_ID_KEY] = pcap_id
           

            # Convert date to string
            threat_data = self.convert_dates_to_string(threat_data)

            logger.info(f"threat json: {threat_data}")
            threat_report = spds_interactions.create_threat_report(
                            pcap_id=threat_data[PCAP_ID_KEY], 
                            source_ip=threat_data[SOURCE_IP_KEY], 
                            dest_ip = threat_data[DEST_IP_KEY],
                            protocol=threat_data[PROTOCOL_KEY],
                            timestamp = threat_data[TIMESTAMP_KEY],
                            
                            ip_count = threat_data[IP_COUNT]
                        )
            '''ddos_type = threat_data[DDOS_TYPE_KEY],'''
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
            #'ddos_type': threat_report.ddos_type,
            #threat_json =  json.dumps(threat_data)
            if threat_json:
                threat_reports.append(threat_json)
            logger.info(f"threat json: {threat_json}")

        return threat_reports

    def update_pcap(self, pcap_id,  ddos_rate, is_analised, error, prediction_time):
        return spds_interactions.update_pcap(pcap_id=pcap_id, ddos_rate=ddos_rate, is_analised=is_analised, error=error, prediction_time=prediction_time)
