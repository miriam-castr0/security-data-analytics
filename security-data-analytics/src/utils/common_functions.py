import os
import uuid

from src.broker.kafka_consumer import Consumer, AUTO_OFFSET_RESET_LATEST
from src.utils.error_handler import InvalidInputData

kafka_servers = os.getenv('KAFKA_BROKER_URL', 'kafka:9092')



def new_consumer_thread(topic, callback):
    consumer = Consumer()
    consumer.add_subscription(topic, callback)
    return consumer


def validate_input(data, name, check_uuid=False):
    """
    Validate input field and return his value. Raise an InvalidInputData exception if it is not valid

    :param data: Raw message
    :param name: Field name
    :param check_uuid: Check valid UUID
    :return:
    """

    def is_field_in_data():
        if value is None:
            raise InvalidInputData(name)
        return True

    def is_field_uuid():
        try:
            uuid.UUID(str(value))
        except:
            raise InvalidInputData(name, value)

    if not isinstance(data, dict):
        raise InvalidInputData(None)
    value = data.get(name, None)
    if is_field_in_data() and check_uuid:
        is_field_uuid()
    return value
