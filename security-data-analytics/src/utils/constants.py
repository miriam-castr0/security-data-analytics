CHUNKS_KEY = 'chunks'
GROUP_ID = 'real-time_analysis'
TIMESTAMP_KEY = "timestamp"
CHUNK_TOPIC = 'PCAP_CHUNK'
ANOMALY_DETECTION_TOPIC = "anomaly_detection"
ALERT_THREATS_TOPIC = "threats_alert"
ALERT_ACCURACY_TOPIC = "acc_alert"
MODEL_PATH = "/security_data_analytics_app/src/lucid/model/10t-10n-DOS2019-LUCID.h5"
RF_MODEL_PATH = "/security_data_analytics_app/src/random_forest/model/10t-10n-DOS2019-randomforest.pkl"
MODEL_FOLDER = "/security_data_analytics_app/src/lucid/model/"
DATASET_FOLDER = "/security_data_analytics_app/src/lucid/model/"
DATASET_FOLDER_RF = "/security_data_analytics_app/src/random_forest/model/"
MAX_RETRIES = 3

N_DDOS_TYPES = 13
DDOS_TYPE_MAP = {'DNS':0, 'SynFlood':1, 'UDPLag':2, 'WebDDoS':3, 'TFTP':4, 'MSSQL': 5, 'LDAP': 6, 'NetBios': 7, 'NTP':8, 'SSDP': 9, 'SNMP': 10, 'UDP':11}

HTTP_BAD_DATA = 400