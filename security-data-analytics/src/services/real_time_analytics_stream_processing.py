import threading
from datetime import timedelta
import datetime
import traceback
import pandas as pd
import numpy as np
import logging

pd.set_option('display.max_rows', 5)
pd.set_option('display.max_columns', None)

from src.services.dash_application import DashApplication
from src.utils.constants import TIMESTAMP_KEY, DDOS_TYPE_MAP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RealTimeAnalyticsStreamProcessing(DashApplication):
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(RealTimeAnalyticsStreamProcessing, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if not self._initialized:
            super().__init__()
            self.results = None
            self.model_test_results_lucid = None
            self.model_test_results_rf = None
            self.ddos_rate_list = None
            self.ddos_rate_type_list = None
            self._initialized = True

    def update_model_metrics_lucid(self, results):
        current_time = datetime.datetime.now()
        new_data = []
        for result in results:
            new_data.append({
                'prediction_time': result[0],
                'accuracy': result[1],
                'f1': result[2],
                'true_positive_rate': result[3],
                'false_positive_rate': result[4],
                'true_negative_rate': result[5],
                'false_negative_rate': result[6],
                'precision':result[7],
                'recall':result[8],
                'mse': result[9],
                'auc': result[10],
                'data_source': result[11],
                TIMESTAMP_KEY: result[12]
            })
        new_data_frame = pd.DataFrame(new_data)
        if self.model_test_results_lucid is None:
            self.model_test_results_lucid = new_data_frame
        else:
            self.model_test_results_lucid = pd.concat([self.model_test_results_lucid, new_data_frame], ignore_index=True)

        self.model_test_results_lucid = self.model_test_results_lucid[
            self.model_test_results_lucid[TIMESTAMP_KEY] >= (current_time - datetime.timedelta(hours=1))]
        
        logger.info(f"lucid tests: {new_data_frame}")
    
    def update_model_metrics_rf(self, results):
        current_time = datetime.datetime.now()
        new_data = []
        for result in results:
            new_data.append({
                'prediction_time': result[0],
                'accuracy': result[1],
                'f1': result[2],
                'precision':result[3],
                'recall':result[4],
                'mse': result[5],
                'data_source': result[6],
                TIMESTAMP_KEY: result[7]
            })
        new_data_frame = pd.DataFrame(new_data)
        if self.model_test_results_rf is None:
            self.model_test_results_rf = new_data_frame
        else:
            self.model_test_results_rf = pd.concat([self.model_test_results_rf, new_data_frame], ignore_index=True)

        self.model_test_results_rf = self.model_test_results_rf[
            self.model_test_results_rf[TIMESTAMP_KEY] >= (current_time - datetime.timedelta(hours=1))]
        
        logger.info(f"rf tests: {new_data_frame}")

    def update_ddos_rate_type(self, ddos_rate_type, timestamp, Y_pred_classification):
       
        try:
            # Calculate the threshold timestamp
            threshold_timestamp = timestamp - timedelta(minutes=30)

            logger.info(f"threshold timestamp: {threshold_timestamp}")

            

            if self.ddos_rate_type_list is not None:
                self.ddos_rate_type_list = self.ddos_rate_type_list[self.ddos_rate_type_list[TIMESTAMP_KEY] >= threshold_timestamp]

            inverted_ddos_type_map = {v: k for k, v in DDOS_TYPE_MAP.items()}
            new_data = {
                'class': [inverted_ddos_type_map[k] for k in ddos_rate_type.keys()],
                'rate':[item['rate'] for item in ddos_rate_type.values()],
                'ddos_flows_by_class': [item['ddos_flows_by_class'] for item in ddos_rate_type.values()],
                'total_flows': len(Y_pred_classification) ,
                'timestamp': [timestamp] * len(ddos_rate_type)
            }

            df = pd.DataFrame(new_data)

            if self.ddos_rate_type_list is None:
                self.ddos_rate_type_list = df
            else:
                self.ddos_rate_type_list = pd.concat([self.ddos_rate_type_list, df])
            
            self.ddos_rate_type_list = self.ddos_rate_type_list.sort_values(by='class').reset_index(drop=True)
            logger.info(f"DDoS Rate type list:  {self.ddos_rate_type_list}")

        except Exception as e:
            logger.error(f"Error in update_ddos_classification: {traceback.format_exc()}")
            return None

    def update_results(self, keys, Y_pred, ddos_rate, timestamp, keys_classification, Y_pred_Classification):
        key_pred = list(zip(keys, Y_pred))  # join flow keys with the prediction
        key_pred_classification = list(zip(keys_classification, Y_pred_Classification))
        
        # Create a dictionary for classification mapping
        classification_dict = {tuple(key): value for key, value in key_pred_classification}
        try:
            # Calculate the threshold timestamp
            threshold_timestamp = timestamp - timedelta(minutes=30)

            logger.info(f"threshold timestamp: {threshold_timestamp}")

            if self.results is not None:
                # Filter old entries
                self.results = self.results[self.results[TIMESTAMP_KEY] >= threshold_timestamp]
            logger.info(f"results: {self.results}")
            if self.ddos_rate_list is not None:
                self.ddos_rate_list = self.ddos_rate_list[self.ddos_rate_list[TIMESTAMP_KEY] >= threshold_timestamp]

            new_data = []
            self.restructure_data(key_pred, new_data, timestamp, classification_dict)
            logger.info(f"new data: {new_data}")
            logger.info(f"results: {self.results}")
            new_data_frame = self.update_data_frame_results(new_data)

            ddos_rate_aux = (float(ddos_rate), np.count_nonzero(Y_pred == 1), len(Y_pred), timestamp)
            new_ddos_rate_df = pd.DataFrame([ddos_rate_aux], columns=['ddos_rate', 'ddos_flows', 'total_flows', TIMESTAMP_KEY])
            if self.ddos_rate_list is None:
                self.ddos_rate_list = new_ddos_rate_df
            else:
                self.ddos_rate_list = pd.concat([self.ddos_rate_list, new_ddos_rate_df])

            logger.info(f"results: {self.results}")
            logger.info(f"ddos_rate: {self.ddos_rate_list}")
            return new_data_frame

        except Exception as e:
            logger.error(f"Error in update_results: {traceback.format_exc()}")
            return None

        

    def restructure_data(self, key_pred, new_data, timestamp, classification_dict):
        for item in key_pred:
            flow, ddos_status = item
            ip_src, port_src, ip_dst, port_dst, protocol = flow

             # Convert flow to tuple to use as key in classification_dict
            flow_tuple = tuple(flow)
            if ddos_status:
                # Get the ddos_type from the classification_dict or None if not found
                ddos_type = classification_dict.get(flow_tuple, None)
            else:
                ddos_type = None
            new_data.append((ip_src, ip_dst, str(protocol), ddos_status, ddos_type, timestamp))

    def update_data_frame_results(self, new_data):
        new_data_frame = pd.DataFrame(new_data,
                                      columns=['source_ip', 'dest_ip', 'protocol', 'ddos_status', 'ddos_type', TIMESTAMP_KEY])
        if self.results is None:
            self.results = new_data_frame
        else:
            self.results = pd.concat([self.results, new_data_frame])
        return new_data_frame

    