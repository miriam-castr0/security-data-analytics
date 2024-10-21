# Copyright (c) 2022 @ FBK - Fondazione Bruno Kessler
# Author: Roberto Doriguzzi-Corin
# Project: LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import time
import pyshark
import socket
import random
import hashlib
from sklearn.feature_extraction.text import CountVectorizer
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))) #set parent directory
from lucid.util_functions import *
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Sample commands
# split a pcap file into smaller chunks to leverage multi-core CPUs: tcpdump -r dataset.pcap -w dataset-chunk -C 1000
# dataset parsing (first step): python3 lucid_dataset_parser.py --dataset_type SYN2020 --dataset_folder ./sample-dataset/ --packets_per_flow 10 --dataset_id SYN2020 --traffic_type all --time_window 10
# dataset parsing (second step): python3 lucid_dataset_parser.py --preprocess_folder ./sample-dataset/

SOURCE_IP_KEY = 'src_ip'
DESTINY_IP_KEY = 'dst_ip'
PROTOCOL_KEY = 'protocol'
SOURCE_PORT_KEY = 'src_port'
DESTINY_PORT_KEY = 'dst_port'


vector_proto = CountVectorizer()
vector_proto.fit_transform(protocols).todense()

random.seed(SEED)
np.random.seed(SEED)

TCP_PADDING = [0, 0]
UDP_PADDING = [0, 0, 0, 0]
ICMP_PADDING = [0, 0, 0, 0, 0]
LAYER3_ONLY_PADDING = [0, 0, 0, 0, 0, 0]

class PacketFeatures:
    def __init__(self):
        self.id_fwd = (0,0,0,0,0) # 5-tuple src_ip_addr, src_port,,dst_ip_addr,dst_port,protocol
        self.id_bwd = (0,0,0,0,0)  # 5-tuple src_ip_addr, src_port,,dst_ip_addr,dst_port,protocol
        self.features_list = []


    def __str__(self):
        return "{} -> {}".format(self.id_fwd, self.features_list)

def get_highest_layer(packet):
    return int(hashlib.sha256(str(packet.highest_layer).encode('utf-8')).hexdigest(), 16) % 10 ** 8

def eliminate_protocol_duplicate(protocols):
    return [1 if i >= 1 else 0 for i in
                     protocols]

def calculate_protocol_bitmask(protocols):
    return int(np.dot(np.array(protocols), powers_of_two))

def parse_packet(packet):
    packet_features = PacketFeatures()
    tmp_id = {}
    tmp_id[SOURCE_IP_KEY] = 0
    tmp_id[SOURCE_PORT_KEY] = 0
    tmp_id[DESTINY_IP_KEY] = 0
    tmp_id[DESTINY_PORT_KEY] = 0
    tmp_id[PROTOCOL_KEY] = 0

    try:
        packet_features.features_list.append(float(packet.sniff_timestamp))  
        packet_features.features_list.append(int(packet.ip.len))  # packet length
        packet_features.features_list.append(get_highest_layer(packet))  
        packet_features.features_list.append(int(int(packet.ip.flags, 16)))  # IP flags
        tmp_id[SOURCE_IP_KEY] = str(packet.ip.src)  
        tmp_id[DESTINY_IP_KEY] = str(packet.ip.dst)  

        protocols = vector_proto.transform([packet.frame_info.protocols]).toarray().tolist()[0]
        protocols = eliminate_protocol_duplicate(protocols) 
        protocols_value = calculate_protocol_bitmask(protocols)
        packet_features.features_list.append(protocols_value)

        protocol = int(packet.ip.proto)
        tmp_id[PROTOCOL_KEY] = protocol
        if packet.transport_layer != None:
            if protocol == socket.IPPROTO_TCP:
                tmp_id[SOURCE_PORT_KEY] = int(packet.tcp.srcport)
                tmp_id[DESTINY_PORT_KEY] = int(packet.tcp.dstport)
                packet_features.features_list.append(int(packet.tcp.len))  
                packet_features.features_list.append(int(packet.tcp.ack))  
                packet_features.features_list.append(int(packet.tcp.flags, 16))  
                packet_features.features_list.append(int(packet.tcp.window_size_value))  
                packet_features.features_list += TCP_PADDING
            elif protocol == socket.IPPROTO_UDP:
                packet_features.features_list += UDP_PADDING 
                tmp_id[SOURCE_PORT_KEY] = int(packet.udp.srcport)
                packet_features.features_list.append(int(packet.udp.length))  
                tmp_id[DESTINY_PORT_KEY] = int(packet.udp.dstport)
                packet_features.features_list = packet_features.features_list + [0]  
        elif protocol == socket.IPPROTO_ICMP:
            packet_features.features_list += ICMP_PADDING
            packet_features.features_list.append(int(packet.icmp.type))  
        else:
            packet_features.features_list += LAYER3_ONLY_PADDING 
            tmp_id[PROTOCOL_KEY] = 0

        packet_features.id_fwd = (tmp_id[SOURCE_IP_KEY], tmp_id[SOURCE_PORT_KEY], tmp_id[DESTINY_IP_KEY], tmp_id[DESTINY_PORT_KEY], tmp_id[PROTOCOL_KEY])
        packet_features.id_bwd = (tmp_id[DESTINY_IP_KEY], tmp_id[DESTINY_PORT_KEY], tmp_id[SOURCE_IP_KEY], tmp_id[SOURCE_PORT_KEY], tmp_id[PROTOCOL_KEY])


        return packet_features

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        logger.warning(f"Failed to parse packet at timestamp {packet.sniff_timestamp}: {e}")
        return None



# Transforms live traffic into input samples for inference
def process_live_traffic(file_capture,  max_flow_len,time_window=TIME_WINDOW):
 
    start_time = time.time()
    temp_dict = OrderedDict()
    flows_list = []

    start_time_window = start_time
    time_window = start_time_window + time_window

    
    logger.info("Processing file capture")
    while time.time() < time_window:
        try:
            packet = file_capture.next()
            
            packet_features = parse_packet(packet)
            temp_dict = store_packet(packet_features,temp_dict,start_time_window,max_flow_len)
            #print(f"temp_dict: {temp_dict}")
        except StopIteration:
            logger.info("No more packets in capture file")
            break
        except Exception as e:
            logger.error(f"Error occurred", exc_info=True)
            break

    logger.info(f"Completed live traffic processing. Processed {len(temp_dict)} flows.")
    construct_flow_list(temp_dict, flows_list)
    return flows_list

def construct_flow_list(flows, flows_list):
    
    for five_tuple, flow in flows.items():
        
        for flow_key, packet_list in flow.items():
            # relative time wrt the time of the first packet in the flow
            if flow_key != 'label':
                amin = np.amin(packet_list,axis=0)[0]
                packet_list[:, 0] = packet_list[:, 0] - amin

        flows_list.append((five_tuple,flow))


def store_packet(packet_features,temp_dict,start_time_window, max_flow_len):
    if packet_features is not None:
        if packet_features.id_fwd in temp_dict and start_time_window in temp_dict[packet_features.id_fwd] and \
                temp_dict[packet_features.id_fwd][start_time_window].shape[0] < max_flow_len:
            temp_dict[packet_features.id_fwd][start_time_window] = np.vstack(
                [temp_dict[packet_features.id_fwd][start_time_window], packet_features.features_list])
        elif packet_features.id_bwd in temp_dict and start_time_window in temp_dict[packet_features.id_bwd] and \
                temp_dict[packet_features.id_bwd][start_time_window].shape[0] < max_flow_len:
            temp_dict[packet_features.id_bwd][start_time_window] = np.vstack(
                [temp_dict[packet_features.id_bwd][start_time_window], packet_features.features_list])
        else:
            if packet_features.id_fwd not in temp_dict and packet_features.id_bwd not in temp_dict:
                temp_dict[packet_features.id_fwd] = {start_time_window: np.array([packet_features.features_list]), 'label': 0}
            elif packet_features.id_fwd in temp_dict and start_time_window not in temp_dict[packet_features.id_fwd]:
                temp_dict[packet_features.id_fwd][start_time_window] = np.array([packet_features.features_list])
            elif packet_features.id_bwd in temp_dict and start_time_window not in temp_dict[packet_features.id_bwd]:
                temp_dict[packet_features.id_bwd][start_time_window] = np.array([packet_features.features_list])
    return temp_dict


# returns the total number of flows
def count_flows(preprocessed_flows):
    ddos_flows = 0
    total_flows = len(preprocessed_flows)
    ddos_fragments = 0
    total_fragments = 0
    for flow in preprocessed_flows:
        flow_fragments = len(flow[1]) - 1
        total_fragments += flow_fragments
        if flow[1]['label'] > 0:
            ddos_flows += 1
            ddos_fragments += flow_fragments  # the label does not count

    return (total_flows, ddos_flows, total_flows - ddos_flows), (total_fragments, ddos_fragments, total_fragments-ddos_fragments)



# convert the dataset from dictionaries with 5-tuples keys into a list of flow fragments and another list of labels
def dataset_to_list_of_fragments(dataset):
    keys = []
    X = []
    y = []

    for flow in dataset:
        tuple = flow[0]
        flow_data = flow[1]
        label = flow_data['label']
        for key, fragment in flow_data.items():
            if key != 'label':
                X.append(fragment)
                y.append(label)
                keys.append(tuple)

    return X,y,keys


