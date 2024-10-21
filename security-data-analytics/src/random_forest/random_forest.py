from collections import Counter
import datetime
import glob
import logging
import os
import time
import joblib
import numpy as np
from sklearn.metrics import f1_score, mean_squared_error, precision_score, recall_score, accuracy_score
from sklearn.utils import shuffle
import h5py
from src.utils.constants import N_DDOS_TYPES, RF_MODEL_PATH

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SEED = 1

def predict_classification(X, model_path):
    
    rf = joblib.load(model_path)
    Y_pred = rf.predict(X)
        
    
    prediction_time = datetime.datetime.now()

    return Y_pred, prediction_time, rate_ddos_type(Y_pred)


def rate_ddos_type(Y_pred):
    counter = Counter(Y_pred)

    # Rate of every classe
    percentages = {cls: {'rate': count / len(Y_pred), 'ddos_flows_by_class': count} for cls, count in counter.items()}

    return percentages



def test_model_rf(dataset_folder):
    results = []
    dataset_file = dataset_folder + "/*" + '-test.hdf5'
    X_test, Y_test = load_dataset(dataset_file)
    X_test, Y_test = shuffle(X_test, Y_test, random_state=SEED)
    
    
    X_test = np.mean(X_test, axis=1)
    
    # get the time_window and the flow_len from the filename
    test_file = glob.glob(dataset_folder + "/*" + '-test.hdf5')[0]
    filename = os.path.basename(test_file)
    


    pt0 = time.time()
    rf = joblib.load(RF_MODEL_PATH)
    Y_pred_test = rf.predict(X_test)
    pt1 = time.time()
    prediction_time = pt1 - pt0
    timestamp = datetime.datetime.now()
    
    results.append(calculate_metrics( Y_test, Y_pred_test,  prediction_time, filename, timestamp))
    logger.info(f"reuslts_rf: {results}")
    return results

def load_dataset(path):
    
    filename = glob.glob(path)[0]
    
    dataset = h5py.File(filename, "r")
    set_x_orig = np.array(dataset["set_x"][:])  # features
    set_y_orig = np.array(dataset["set_y"][:])  # labels

    X_train = np.reshape(set_x_orig, (set_x_orig.shape[0], set_x_orig.shape[1], set_x_orig.shape[2]))
    Y_train = set_y_orig#.reshape((1, set_y_orig.shape[0]))

    
    return X_train, Y_train


def calculate_metrics(Y_true,Y_pred, prediction_time, data_source, timestamp ):


    Y_true = Y_true.reshape((Y_true.shape[0], 1))
    accuracy = accuracy_score(Y_true, Y_pred)

    f1 = f1_score(Y_true, Y_pred, average='weighted')
   
    # Calcular Precision
    precision = precision_score(Y_true, Y_pred, average='weighted')

    # Calcular Recall
    recall = recall_score(Y_true, Y_pred, average='weighted', zero_division=0)

    # Calcular Mean Squared Error (MSE)
    mse = mean_squared_error(Y_true, Y_pred)

    return prediction_time, accuracy, f1, precision, recall, mse, data_source,  timestamp


    
