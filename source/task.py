import tensorflow as tf
import numpy as np
import argparse
import math
import sys

def read_label(tf_bytestring):
    label = tf.decode_raw(tf_bytestring, tf.uint8)
    return tf.reshape(label, [])

def read_session(tf_bytestring):
    session = tf.decode_raw(tf_bytestring, tf.uint8)
    return tf.cast(session, tf.float32)/256.


def load_dataset(train_file, label_file):
    trainDataSet = tf.data.FixedLengthRecordDataset(train_file, 1*41).map(read_session)
    trainLabelDataSet = tf.data.FixedLengthRecordDataset(label_file, 1).map(read_label)
    dataset = tf.data.Dataset.zip((trainDataSet, trainLabelDataSet))
    return dataset

def loadFiles():
    trainingFile = "datasets/data/training/training.txt"
    trainingLabelFile = "datasets/data/training/trainingLabels.txt"
    testingFile = "datasets/data/testing/testing.txt"
    testingLabelFile = "datasets/data/testing/testingLabels.txt"
    return trainingFile, trainingLabelFile, testingFile, testingLabelFile


