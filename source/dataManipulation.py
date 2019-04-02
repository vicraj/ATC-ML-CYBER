import tensorflow as tf
import numpy as np

import sys

from source.task import load_dataset
from source.task import loadFiles


class DarpaData(object):

    def __init__(self, tf_dataset, one_hot, reshape):
        self.pos = 0
        self.sessions = None
        self.labels = None
        #load data set into memory by chunks of 10000
        tf_dataset = tf_dataset.batch(10000)
        tf_dataset = tf_dataset.repeat(1)
        sessions, labels = tf_dataset.make_one_shot_iterator().get_next()
        if one_hot:
            sessions = tf.one_hot(sessions, 41)
            labels = tf.one_hot(labels, 6)
        with tf.Session() as sess:
            while True:
                try:
                    feats, labs = sess.run([sessions, labels])
                    self.sessions = feats if self.sessions is None else np.concatenate([self.sessions, feats])
                    self.labels = labs if self.labels is None else np.concatenate([self.labels, labs])
                except tf.errors.OutOfRangeError:
                    break


    def next_batch(self, batch_size):
        if self.pos+batch_size > len(self.sessions) or self.pos+batch_size > len(self.labels):
            self.pos = 0
        res = (self.sessions[self.pos:self.pos+batch_size], self.labels[self.pos:self.pos+batch_size])
        self.pos += batch_size
        return res


class Darpa(object):
    def __init__(self, train_dataset, test_dataset, one_hot, reshape):
        self.train = DarpaData(train_dataset, one_hot, reshape)
        self.test = DarpaData(test_dataset, one_hot, reshape)

def read_data_sets(one_hot, reshape):
    train_sessions_file, train_labels_file, test_sessions_file, test_labels_file = loadFiles()
    train_dataset = load_dataset(train_sessions_file, train_labels_file)
    train_dataset = train_dataset.shuffle(60000)
    test_dataset = load_dataset(test_sessions_file, test_labels_file)
    darpa = Darpa(train_dataset, test_dataset, one_hot, reshape)
    return darpa

