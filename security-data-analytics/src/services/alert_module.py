import logging
from src.broker.kafka_producer import Producer
from src.utils.constants import TIMESTAMP_KEY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertModule(Producer):
    def __init__(self, topics=None):
        super().__init__(topics)

    def alert_threats(self, threat):
        """
            send the alert to SD about the ddos detection
        """
        
        self.send_to_topic(key=str(1), message=threat)
        logger.info(f"Sent DDoS detection alert: {threat}")
        

    def alert_model_accuracy_lucid(self, results):
        """
            send the alert to SD about the ML model
        """
        json_array = []

        for result in results:
            json_array.append({'prediction_time': result[0],
                               'accuracy': result[1],
                               'f1': result[2],
                               'true_positive_rate': result[3],
                               'false_positive_rate': result[4],
                               'true_negative_rate': result[5],
                               'false_negative_rate': result[6],
                               'precision': result[7],
                               'recall': result[8],
                               'mse': result[9],
                               'auc': result[10],
                               'data_source': result[11],
                               TIMESTAMP_KEY: result[12]})
            logger.info(f"Alert Model info: {json_array}")

        self.send_to_topic(key='lucid',message=json_array)
        pass
    def alert_model_accuracy_lucid(self, results):
        """
            send the alert to SD about the ML model
        """
        json_array = []

        for result in results:
            json_array.append({'prediction_time': result[0],
                               'accuracy': result[1],
                               'f1': result[2],
                               'precision': result[3],
                               'recall': result[4],
                               'mse': result[5],
                               'data_source': result[6],
                               TIMESTAMP_KEY: result[7]})
            logger.info(f"Alert Model info: {json_array}")

        self.send_to_topic(key='rf',message=json_array)
        pass
