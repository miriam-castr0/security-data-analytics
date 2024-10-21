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

#Sample commands
# Training: python3 lucid_cnn.py --train ./sample-dataset/  --epochs 100 -cv 5
# Testing: python3  lucid_cnn.py --predict ./sample-dataset/ --model ./sample-dataset/10t-10n-SYN2020-LUCID.h5


import datetime
import logging
import numpy as np
import random as rn
import os
import csv
import pprint
from lucid.util_functions import *
# Seed Random Numbers
from tensorflow.python.keras.models import load_model
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from sklearn.metrics import f1_score, accuracy_score, confusion_matrix, mean_squared_error, precision_score, recall_score, roc_auc_score
from sklearn.utils import shuffle

from lucid.lucid_dataset_parser import *



def predict_pcap(pcap_file, model_path, time_window, max_flow_len): #add model path after..
    """ predict_file = open( 'predictions-' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'a', newline='')
    predict_file.truncate(0)  # clean the file content (as we open the file in append mode)
    predict_writer = csv.DictWriter(predict_file, fieldnames=PREDICT_HEADER)
    predict_writer.writeheader()
    predict_file.flush() """
    keys = []
    X_samples = []
    Y_pred= []
    ddos_rate=None 
    prediction_time = None
    
    file_capture = pyshark.FileCapture(pcap_file)
    data_source = pcap_file.split('/')[-1].strip()
    logger.info(f"Prediction on network traffic from: {data_source}")

    # load the labels, if available
    #labels = parse_labels(args.dataset_type, args.attack_net, args.victim_net)

    # do not forget command sudo ./jetson_clocks.sh on the TX2 board before testing
    

    model = load_model(model_path)

    mins, maxs = static_min_max(time_window)

    while (True):
        samples = process_live_traffic(file_capture, max_flow_len, time_window=time_window)

        if len(samples) > 0:
            X,Y_true,keys_aux = dataset_to_list_of_fragments(samples)
            
            keys.extend(keys_aux)
            
            X = np.array(normalize_and_padding(X, mins, maxs, max_flow_len))
            

            X_samples.extend(X)
            Y_pred_aux = None
            ddos_rate = 0

            X = np.expand_dims(X, axis=3)
       
            #pt0 = time.time()
            Y_pred_aux = np.squeeze(model.predict(X, batch_size=2048) > 0.5,axis=1)
            #model.save(model_path)
            #pt1 = time.time()
            Y_pred.extend(Y_pred_aux)
            
            #[packets] = count_packets_in_dataset([X])
            #ddos_rate  = report_results(np.squeeze(Y_true), Y_pred, packets, model_name_string, data_source, prediction_time,predict_writer)
            #predict_file.flush()
            
            
            

        elif isinstance(file_capture, pyshark.FileCapture) == True:
            logger.info(f"\nNo more packets in file: {data_source}")
            break
    
    prediction_time = datetime.datetime.now()
    ddos_rate = calculate_ddos_rate(Y_pred)
    #predict_file.close()
    keys =  np.array(keys, dtype=np.dtype([('a', '<U30'), ('b', '<U30'), ('c', '<U30'), ('d', '<U30'), ('e', '<U30')]))
    Y_pred = np.array(Y_pred)
    X_samples = np.array(X_samples)
 
    return keys, X_samples, Y_pred, ddos_rate, prediction_time


def calculate_ddos_rate(Y_pred):
    ddos_rate = '{:04.3f}'.format(sum(Y_pred) / len(Y_pred))
    return ddos_rate

def test_model(model_folder, dataset_folder):
    # predict_file = open(OUTPUT_FOLDER + 'predictions-' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'a', newline='')
    # predict_file.truncate(0)  # clean the file content (as we open the file in append mode)
    # predict_writer = csv.DictWriter(predict_file, fieldnames=PREDICT_HEADER)
    # predict_writer.writeheader()
    # predict_file.flush()

   
    results = []
    dataset_filelist = glob.glob(dataset_folder + "/*test.hdf5") #search for the dataset files

    # if args.model is not None:
    #     model_list = [args.model]
    # else:
    model_list = glob.glob(model_folder + "/*.h5") #search for model files

    for model_path in model_list:
        model_filename = model_path.split('/')[-1].strip()
        filename_prefix = model_filename.split('-')[0].strip() + '-' + model_filename.split('-')[1].strip() + '-'
        model = load_model(model_path)

        # warming up the model (necessary for the GPU)
        warm_up_file = dataset_filelist[0]
        filename = warm_up_file.split('/')[-1].strip()
        if filename_prefix in filename:
            X, Y = load_dataset(warm_up_file)
            Y_pred = np.squeeze(model.predict(X, batch_size=2048) > 0.5)

        for dataset_file in dataset_filelist:
            filename = dataset_file.split('/')[-1].strip()
            if filename_prefix in filename:
                X, Y = load_dataset(dataset_file)

                Y_pred = None
                Y_true = Y
                pt0 = time.time()
                Y_pred = np.squeeze(model.predict(X, batch_size=2048) > 0.5)
                pt1 = time.time()
                prediction_time = pt1 - pt0
                timestamp = datetime.datetime.now()
                results.append(test_results(np.squeeze(Y_true), Y_pred, filename, prediction_time, timestamp))
               
        
        return results

def test_results(Y_true, Y_pred, data_source, prediction_time, timestamp):
    if Y_true is not None and len(Y_true.shape) > 0:  # if we have the labels, we can compute the classification accuracy
        Y_true = Y_true.reshape((Y_true.shape[0], 1))
        accuracy = accuracy_score(Y_true, Y_pred)

        f1 = f1_score(Y_true, Y_pred)
        tn, fp, fn, tp = confusion_matrix(Y_true, Y_pred, labels=[0, 1]).ravel()
        tnr = tn / (tn + fp)
        fpr = fp / (fp + tn)
        fnr = fn / (fn + tp)
        tpr = tp / (tp + fn)

        precision = precision_score(Y_true, Y_pred)
        recall = recall_score(Y_true, Y_pred)
        mse = mean_squared_error(Y_true, Y_pred)
        auc = roc_auc_score(Y_true, Y_pred)

    return prediction_time, accuracy, f1, tpr, fpr, tnr, fnr, precision, recall, mse, auc, data_source, timestamp

def report_results(Y_true, Y_pred, packets, model_name, data_source, prediction_time, writer):
    ddos_rate = '{:04.3f}'.format(sum(Y_pred) / Y_pred.shape[0])

    if Y_true is not None and len(Y_true.shape) > 0:  # if we have the labels, we can compute the classification accuracy
        Y_true = Y_true.reshape((Y_true.shape[0], 1))
        accuracy = accuracy_score(Y_true, Y_pred)

        f1 = f1_score(Y_true, Y_pred)
        tn, fp, fn, tp = confusion_matrix(Y_true, Y_pred, labels=[0, 1]).ravel()
        tnr = tn / (tn + fp)
        fpr = fp / (fp + tn)
        fnr = fn / (fn + tp)
        tpr = tp / (tp + fn)

        row = {'Model': model_name, 'Time': '{:04.3f}'.format(prediction_time), 'Packets': packets,
               'Samples': Y_pred.shape[0], 'DDOS%': ddos_rate, 'Accuracy': '{:05.4f}'.format(accuracy), 'F1Score': '{:05.4f}'.format(f1),
               'TPR': '{:05.4f}'.format(tpr), 'FPR': '{:05.4f}'.format(fpr), 'TNR': '{:05.4f}'.format(tnr), 'FNR': '{:05.4f}'.format(fnr), 'Source': data_source}
    else:
        row = {'Model': model_name, 'Time': '{:04.3f}'.format(prediction_time), 'Packets': packets,
               'Samples': Y_pred.shape[0], 'DDOS%': ddos_rate, 'Accuracy': "N/A", 'F1Score': "N/A",
               'TPR': "N/A", 'FPR': "N/A", 'TNR': "N/A", 'FNR': "N/A", 'Source': data_source}
    pprint.pprint(row, sort_dicts=False)
    writer.writerow(row)
    return ddos_rate


