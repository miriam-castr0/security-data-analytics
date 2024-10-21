from src.utils.common_functions import new_consumer_thread

from src.services.pcap_file_reconstructor import PcapFileReconstructor

from src.utils.constants import CHUNK_TOPIC


# TODO Put here all logic related to module

def init_pcap_reconstructor():
    service = PcapFileReconstructor()
    return new_consumer_thread(CHUNK_TOPIC, service.process_chunks)
