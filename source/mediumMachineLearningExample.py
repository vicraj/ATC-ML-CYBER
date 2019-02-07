import tensorflow as tf
import numpy as np

x = tf.placeholder(tf.float32, [None, 1])
W = tf.Variable(tf.zeros([1, 1]))
b = tf.Variable(tf.zeros([1]))
steps = 100;

#y = W.x + b

y = tf.matmul(x, W) + b
y_ = tf.placeholder(tf.float32, [None, 1])
cost = tf.reduce_sum(tf.pow((y_-y), 2))

for i in range(100):
    #Create fake data for actual data
    xs = np.array([[i]])
    ys = np.array([[2*i]])

train_step = tf.train.GradientDescentOptimizer(0.00001).minimize(cost)

init = tf.initialize_all_variables()

sess = tf.Session()
sess.run(init)

for i in range(steps):
    #create fake data for y = W.x + b where W = 2, b = 0
    xs = np.array([[i]])
    ys = np.array([[2*i]])

    #Train
    feed = {x: xs, y_: ys }
    sess.run(train_step, feed_dict=feed)

    print("After %d iteration:" %i)
    print("W: %f" % sess.run(W))
    print("b: %f" % sess.run(b))
    
