import logging
import os
from src.broker.kafka_producer import Producer
from src.utils.chunk_object import ChunkObject
from src.utils.common_functions import validate_input
from src.utils.constants import ANOMALY_DETECTION_TOPIC

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


LATEST_CHUNK_FLAG_KEY = 'is_latest'


class PcapFileReconstructor(Producer):
    __pcap_id_with_chunk_data = {}

    def __init__(self):
        super().__init__(ANOMALY_DETECTION_TOPIC)
        self.chunk = None
        self.output_dir = "/security_data_analytics_app/src/pcap/"
        self.pcap_ids = []

    def process_chunks(self, key, raw_chunk):
        logger.info("Processing a chunk..")

        try:
            self.__validate_input(key, raw_chunk)
            self.__store_chunk_in_memory()
            if self.__is_pcap_file_complete():
                self.__reconstruct_files()

        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)

    def __reconstruct_files(self):
        """
            Reconstruct files from chunks.
            That method block of read of kafka topic until it ends
        """
        logger.info(f"Starting to reconstruct pcap with ID: {self.chunk.pcap_id}")

        chunks = PcapFileReconstructor.__pcap_id_with_chunk_data[self.chunk.pcap_id]
        chunks.sort(key=lambda chunk: chunk[0])  # Sort chunks by sequence

        output_file_path = os.path.join(self.output_dir, f"{self.chunk.pcap_id}.pcap")
        with open(output_file_path, "wb") as output_file:
            for _, chunk_data in chunks:
                output_file.write(chunk_data)

        del PcapFileReconstructor.__pcap_id_with_chunk_data[self.chunk.pcap_id]
        logger.info(f"Pcap was reconstructed successfully at '{output_file_path}' path. Sending it to analyze.")

        # TODO Produces a signal to analitics module sending the file_path
        self.send_to_topic(key=str(self.chunk.pcap_id), message=output_file_path)
        self.chunk = None

    def __store_chunk_in_memory(self):
        if self.chunk.pcap_id not in PcapFileReconstructor.__pcap_id_with_chunk_data:
            PcapFileReconstructor.__pcap_id_with_chunk_data[self.chunk.pcap_id] = []
        PcapFileReconstructor.__pcap_id_with_chunk_data[self.chunk.pcap_id].append((self.chunk.sequence, self.chunk.data))

        logger.info(
            f"Received chunk {str(self.chunk.sequence)}/{str(self.chunk.total_chunks)} for pcap_id: {self.chunk.pcap_id}; "
            f"chunk size: {len(self.chunk.data)} bytes")

    def __is_pcap_file_complete(self):
        return self.chunk.total_chunks == len(PcapFileReconstructor.__pcap_id_with_chunk_data[self.chunk.pcap_id])

    def __validate_input(self, key, raw_chunk):
        logger.info(f"key {key}")
        self.chunk = ChunkObject(
            pcap_id=int(key.decode().split('_',1)[0]),
            total_chunks=int(validate_input(raw_chunk, 'total_chunks')),
            chunk_sequence=int(validate_input(raw_chunk, 'chunk_sequence')),
            chunk_data=validate_input(raw_chunk, 'chunk_data'),
            checksum=validate_input(raw_chunk, 'checksum')
        )
