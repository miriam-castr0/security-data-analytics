import logging

from src.utils.constants import HTTP_BAD_DATA

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class InvalidInputData(Exception):
    def __init__(self, key, value=None):
        self.message = f'Invalid input data or missing key: {key}:{value}'
        super().__init__(self.message)

    def get_data(self):
        return {"message": self.message, "type_error": __name__}, HTTP_BAD_DATA
