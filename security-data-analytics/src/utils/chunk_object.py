import base64


class ChunkObject:
    def __init__(self, pcap_id, total_chunks, chunk_sequence, chunk_data, checksum):
        self.pcap_id = pcap_id
        self.total_chunks = total_chunks
        self.sequence = chunk_sequence
        self.__decode_chunk_data(chunk_data)
        self.checksum = checksum

    def __decode_chunk_data(self, chunk_data_coded):
        # TODO if you want to change the method of codification, is here
        self.data = base64.b64decode(chunk_data_coded.encode())