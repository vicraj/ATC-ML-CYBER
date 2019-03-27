import tensorflow as tf
import numpy as np
import argparse
import math
import sys

def load_dataset(train_file, label_file):
    trainDataSet = tf.data.FixedLengthRecordDataset(train_file, 41, header_bytes=16, buffer_size=1024*16).map(read)
    labelDataSet = tf.data.FixedLengthRecordDataset(label_file, 1, header_bytes=8, buffer_size=1024*16).map(read_label)
    dataset = tf.data.Dataset.zip((trainDataSet, labelDataSet))
    return dataset

def load_main_data(data_dir):
    