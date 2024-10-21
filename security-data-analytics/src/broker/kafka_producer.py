import os

from kafka import KafkaProducer
import json
import threading
import time
import logging

from kafka.errors import KafkaError


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
bootstrap_server_default = ['kafka:9092']


class Producer:
    def __init__(self, topic, bootstrap_servers=None):
        self.bootstrap_servers = bootstrap_servers or os.getenv('KAFKA_BROKER_URL', bootstrap_server_default)
        self.topic = topic
        self.producer = None
        self.__start_background_flusher()  # automatic start of flusher

    def send_to_topic(self, key, message, partition=None):
        if not self.producer:
            self.__setup_producer()

        if not partition:
            partition = self.get_partition_based_on_pivot(key)

        key_bytes = key.encode('utf-8') if isinstance(key, str) else key
        message_bytes = self.__value_serializer(message)

        future = self.producer.send(self.topic, key=key_bytes, value=message_bytes, partition=partition)
        future.add_callback(self.__on_send_success)
        future.add_errback(self.__on_send_error)

    def get_partition_based_on_pivot(self, pivot):
        all_partitions = self.producer.partitions_for(self.topic)
        return hash(pivot) % len(all_partitions)

    def __setup_producer(self):
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=self.__value_serializer
            )
            self.running = True
            logger.info(
                f"Successfully connected to Kafka broker at {self.bootstrap_servers}")
        except KafkaError as e:
            logger.error(
                f"Failed to connect to Kafka broker at {self.bootstrap_servers}: {e}")
            raise

    def __on_send_success(self, record_metadata):
        logger.info(
            f"Message sent to {record_metadata.topic} partition {record_metadata.partition} offset {record_metadata.offset}")

    def __on_send_error(self, exception):
        logger.error('Message delivery failed', exc_info=exception)

    def __start_background_flusher(self):
        def flusher():
            while self.running:
                if self.producer:
                    logger.warning('Flushing')
                    self.producer.flush()
                    time.sleep(10)  # Flush every 10 seconds

        self.running = False
        self.flush_thread = threading.Thread(target=flusher)
        self.flush_thread.daemon = True
        self.flush_thread.start()

    def stop(self):
        self.running = False
        if self.flush_thread.is_alive():
            self.flush_thread.join()  # Wait for the flushing thread to finish
        self.producer.close()  # Close the producer to release resources

    def __value_serializer(self, value):
        """Serializes the message into bytes. If the message is not bytes, it converts it using JSON."""
        if isinstance(value, bytes):
            return value
        try:
            return json.dumps(value).encode('utf-8')
        except TypeError:
            raise ValueError("Message is neither bytes nor JSON serializable")