import json
import logging
import os
import threading
import time

from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AUTO_OFFSET_RESET_LATEST = 'latest'
AUTO_OFFSET_RESET_EARLIEST = 'earliest'
GROUP_ID = 'security-data-analytics'
KAFKA_SERVER = os.environ.get('KAFKA_BROKER_URL')
DELAY_RETRY_CONNECTION = 5

def safe_deserialize(data):
    try:
        return json.loads(data.decode('utf-8'))
    except json.JSONDecodeError as e:
        # Log error to keep track of how often this occurs and what the data looks like
        logger.error(f"Failed to decode JSON: {e} - Data: {data}")
    except Exception as e:
        logger.error(e)


class Consumer:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(Consumer, cls).__new__(cls)
                cls._instance.auto_offset_reset = AUTO_OFFSET_RESET_EARLIEST
                cls._instance.consumer = None
                cls._instance.consume_thread = None
                cls._instance.subscriptions = {}
                cls._instance.__reconnection_timer_reset()
            return cls._instance

    def add_subscription(self, topic, callback):
        """
            Reconnect to kafka adding the given topic
        """
        if topic not in self.subscriptions:
            self.subscriptions[topic] = callback
            self.__call_to_reconnection_subrutine()
        else:
            logger.warning(f'Subscription requested but was already stored')

    def __reconnect(self):
        def connect_to_kafka(retry=False):
            nonlocal attempt, max_attempt
            if retry:
                logger.warning(f"{threading.get_ident()}: Reconnecting with kafka server {attempt}/{max_attempt}")
            else:
                logger.warning(f"{threading.get_ident()}: Reconnecting with kafka server.")
            try:
                self.consumer = KafkaConsumer(
                    *self.subscriptions.keys(),
                    bootstrap_servers=KAFKA_SERVER,
                    group_id=GROUP_ID,
                    auto_offset_reset=self.auto_offset_reset,
                    value_deserializer=safe_deserialize
                )
                self.consume_thread = threading.Thread(target=self.__processing_messages, daemon=True)
                self.consume_thread.start()
                self.__reconnection_timer_reset()
            except NoBrokersAvailable as e:

                if attempt < max_attempt:
                    logger.error(f'No brokers available, retrying at every {DELAY_RETRY_CONNECTION} seconds')
                    attempt += 1
                    time.sleep(DELAY_RETRY_CONNECTION)
                    connect_to_kafka(True)
                else:
                    logger.error('No brokers available, retry limit reached')

        attempt = 1
        max_attempt = 5
        with self._lock:
            self.stop()
            connect_to_kafka()

    def __processing_messages(self):
        logger.info(f'Consumer was successfully connected to kafka server\n\n')
        for message in self.consumer:
            if message.topic in self.subscriptions:
                self.subscriptions[message.topic](message.key, message.value)

    def __call_to_reconnection_subrutine(self):
        if not self.reconnect_scheduled:
            self.reconnect_scheduled = True
            grace_time = 1.
            logger.warning(f'Starting timer buffer, waiting a gracefully time of {grace_time} seconds')
            self.time_thread = threading.Timer(grace_time, self.__reconnect)
            self.time_thread.start()

    def __reconnection_timer_reset(self):
        self.reconnect_scheduled = False
        self.time_thread = None

        

    def stop(self):
        if self.consumer:
            logger.warning('Stop kafka consumer')
            self.consumer.unsubscribe()
            self.consumer.close()
        self.wait_for_connection_to_finish()
        self.wait_for_consumption_to_finish()

    def wait_for_connection_to_finish(self):
        if self.time_thread and self.time_thread.is_alive() and threading.get_ident() != self.time_thread.ident:
            logger.warning(
                f'[Thread_id: {threading.get_ident()}]: Waiting until finish kafka consumer reconnection thread')
            self.time_thread.join()

    def wait_for_consumption_to_finish(self):
        if self.consume_thread and self.consume_thread.is_alive():
            logger.warning(f'[Thread_id: {threading.get_ident()}]: Waiting until finish kafka consumer thread')
            self.consume_thread.join()
