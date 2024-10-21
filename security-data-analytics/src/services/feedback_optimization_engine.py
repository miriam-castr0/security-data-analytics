import logging
import os
import time
from src.lucid.lucid_cnn import test_model
from src.random_forest.random_forest import test_model_rf
from src.services.alert_module import AlertModule
from src.utils.constants import ALERT_ACCURACY_TOPIC, MODEL_FOLDER, DATASET_FOLDER, DATASET_FOLDER_RF

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CHECK_MODEL_TIME = os.environ.get('CHECK_MODEL_TIME')
ACCURACY_THRESHOLD_LUCID = os.environ.get('ACC_THRESHOLD_LUCID')
ACCURACY_THRESHOLD_RF = os.environ.get('ACC_THRESHOLD_RF')

class FeedbackOptimizationEngine:
    def __init__(self, rasp):
        # DPU INIT
        self.rasp = rasp
        self.alert_module = AlertModule(ALERT_ACCURACY_TOPIC)

    def check_model(self):
        # returns an array of results, once more than one test can be done sequentially, it depend on how much
        # datasets there are
        results_lucid = test_model(MODEL_FOLDER, DATASET_FOLDER)
        results_rf = test_model_rf(DATASET_FOLDER_RF)

        return results_lucid, results_rf

    # update the model metrics in dash
    def update_dash_metrics_lucid(self, results):
        self.rasp.update_model_metrics_lucid(results)
    
    def update_dash_metrics_rf(self, results):
        self.rasp.update_model_metrics_rf(results)

    def check_accuracy_lucid(self, results_lucid):
        logger.info(f"Results test lucid: {results_lucid}")
        below_threshold_results = []  # keep the results with a lower accuracy than threshold
        for result in results_lucid:  # verify wich results have a low accuracy
            if result[1] < float(ACCURACY_THRESHOLD_LUCID):
                below_threshold_results.append(result)
        if below_threshold_results: #only if there are below threshold results
            self.alert_module.alert_model_accuracy_lucid(below_threshold_results)
        self.update_dash_metrics_lucid(results_lucid)

    def check_accuracy_rf(self, results_rf):
        logger.info(f"Results test rf: {results_rf}")
        below_threshold_results = []  # keep the results with a lower accuracy than threshold
        for result in results_rf:  # verify wich results have a low accuracy
            if result[1] < float(ACCURACY_THRESHOLD_RF):
                below_threshold_results.append(result)
        if below_threshold_results: #only if there are below threshold results
            self.alert_module.alert_model_accuracy_rf(below_threshold_results)
        self.update_dash_metrics_rf(results_rf)

    def start(self):
        while True:
            results_lucid, results_rf = self.check_model()

            self.check_accuracy_lucid(results_lucid)
            self.check_accuracy_rf(results_rf)

            logger.warning(f'Sleeping ... {int(CHECK_MODEL_TIME)} seconds')
            time.sleep(int(CHECK_MODEL_TIME))
