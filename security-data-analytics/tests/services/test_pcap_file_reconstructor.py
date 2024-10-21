import base64
import unittest
import os, sys
from unittest.mock import patch, mock_open
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if src_path not in sys.path:
    sys.path.append(src_path)
from src.services.pcap_file_reconstructor import PcapFileReconstructor  # Adjust import based on your file structure

# Disable logging output during tests



class TestPcapFileReconstructor(unittest.TestCase):

    def setUp(self):
        self.reconstructor = PcapFileReconstructor()
        self.reconstructor.output_dir = "/security_data_analytics_app/src/pcap/"  # Set temporary output directory for tests

    def tearDown(self):
        # Clean up any temporary files created during tests
        pass

    @patch.object(PcapFileReconstructor, 'send_to_topic')  # Mock send_to_topic method
    @patch('builtins.open', new_callable=mock_open)
    def test_process_chunks_and_reconstruct_files(self, mock_open, mock_send_to_topic):
        # Simulating first chunk data
        pcap_id = 1234
        chunk_sequence_1 = 1
        mock_key_1 = f"{pcap_id}_{chunk_sequence_1}".encode('utf-8')
        current_chunk_1 = b'chunk1data'
        encoded_chunk_data_1 = base64.b64encode(current_chunk_1).decode()
        mock_raw_chunk_1 = {
            'total_chunks': '2',
            'chunk_sequence': str(chunk_sequence_1),  # Ensure chunk_sequence matches
            'chunk_data': encoded_chunk_data_1,
            'checksum': 'abc123'
        }

        # Simulating second chunk data
        chunk_sequence_2 = 2
        mock_key_2 = f"{pcap_id}_{chunk_sequence_2}".encode('utf-8')
        current_chunk_2 = b'chunk2data'
        encoded_chunk_data_2 = base64.b64encode(current_chunk_2).decode()
        mock_raw_chunk_2 = {
            'total_chunks': '2',
            'chunk_sequence': str(chunk_sequence_2),  # Ensure chunk_sequence matches
            'chunk_data': encoded_chunk_data_2,
            'checksum': 'def456'
        }

        # Calling method under test for the first chunk
        self.reconstructor.process_chunks(mock_key_1, mock_raw_chunk_1)
        # Calling method under test for the second chunk
        self.reconstructor.process_chunks(mock_key_2, mock_raw_chunk_2)

        # Assertions for process_chunks
       
        self.assertIn(pcap_id, self.reconstructor._PcapFileReconstructor__pcap_id_with_chunk_data)
        self.assertEqual(len(self.reconstructor._PcapFileReconstructor__pcap_id_with_chunk_data[pcap_id]), 2)
        mock_send_to_topic.assert_called_once()  # Ensure send_to_topic was called once after all chunks are processed

        # Assertions for __reconstruct_files
        output_file_path = os.path.join(self.reconstructor.output_dir, f"{pcap_id}.pcap")
        mock_open.assert_called_once_with(output_file_path, 'wb')  # Ensure open was called with the correct path and mode
        
    
    @patch('src.utils.common_functions.validate_input')
    @patch.object(PcapFileReconstructor, 'send_to_topic')  # Mock send_to_topic method
    def test_validate_input(self, mock_send_to_topic, mock_validate_input):
        # Example of validating input (mocking validate_input function)
        pcap_id = 1234
        chunk_sequence = 1
        mock_key = f"{pcap_id}_{chunk_sequence}".encode('utf-8')
        current_chunk = b'chunk1data'
        encoded_chunk_data = base64.b64encode(current_chunk).decode()
        
        mock_raw_chunk = {
            'total_chunks': '2',
            'chunk_sequence': str(chunk_sequence),  # Ensure chunk_sequence matches
            'chunk_data': encoded_chunk_data,
            'checking': 'abc123'
        }

        mock_validate_input.side_effect = lambda raw_chunk, key: raw_chunk[key]
        self.reconstructor._PcapFileReconstructor__validate_input(mock_key, mock_raw_chunk)

        self.assertIsNotNone(self.reconstructor.chunk)
        self.assertEqual(self.reconstructor.chunk.pcap_id, pcap_id)
        self.assertEqual(self.reconstructor.chunk.total_chunks, 2)
        self.assertEqual(self.reconstructor.chunk.sequence, chunk_sequence)
        self.assertEqual(self.reconstructor.chunk.data, current_chunk)
        self.assertEqual(self.reconstructor.chunk.checksum, 'abc123')
        mock_send_to_topic.assert_not_called()  # Ensure send_to_topic was not called during validation

