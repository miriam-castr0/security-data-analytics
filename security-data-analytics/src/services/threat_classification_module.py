import datetime
import logging
import numpy as np
from src.utils.constants import RF_MODEL_PATH
from src.random_forest.random_forest import predict_classification
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
class ThreatClassificationModule():
    def __init__(self):
        self.pcap_data = None
        self.model_filename = RF_MODEL_PATH.split('/')[-1].strip()
        self.filename_prefix = self.model_filename.split('n')[0] + 'n-'
        self.time_window = int(self.filename_prefix.split('t-')[0])
        self.max_flow_len = int(self.filename_prefix.split('t-')[1].split('n-')[0])
       
    def classify_threat(self, keys, X_samples, Y_pred):
        
        
        X_filtered = X_samples[Y_pred == True]
        keys_filtered = keys [Y_pred == True]
        
        
        
        if X_filtered.ndim == 2:
            X_filtered = np.mean(X_filtered, axis=0)
        elif X_filtered.ndim == 3:
            X_filtered = np.mean(X_filtered, axis=1)

        if X_filtered.ndim == 1:
            # Expande para 2D
            X_filtered = np.expand_dims(X_filtered, axis=0)
        
        if len(X_filtered) > 0:
        #chamar modelo para fazer predict com 
            Y_pred_class, prediction_time, ddos_type_rate = predict_classification(X_filtered, RF_MODEL_PATH)

        else:
            Y_pred_class = []
            ddos_type_rate = {}
            prediction_time = datetime.datetime.now()
       
        #logger.info(f"ddos_type_rate: {ddos_type_rate}")


        return keys_filtered, Y_pred_class , prediction_time, ddos_type_rate