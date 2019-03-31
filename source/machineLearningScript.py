import tensorflow as tf
import source.dataManipulation

print("Tensorflow version " + tf.__version__)

tf.set_random_seed(0)

darpa = source.dataManipulation.read_data_sets(one_hot=True, reshape=False)

X = tf.placeholder(tf.float32, [-1, 41])

Y_ = tf.placeholder(tf.float32, [None, 6])

#five layers and the number of neurons (the last layer has 22 softmax neurons)
L = 200
M = 100
N = 60
O = 30

#Weights initialized with small random values between -0.2 and +0.2

W1 = tf.Variable(tf.truncated_normal([41, L], stddev=0.1))
B1 = tf.Variable(tf.zeros([L]))
W2 = tf.Variable(tf.truncated_normal([L, M], stddev=0.1))
B2 = tf.Variable(tf.zeros([M]))
W3 = tf.Variable(tf.truncated_normal([M, N], stddev=0.1))
B3 = tf.Variable(tf.zeros([N]))
W4 = tf.Variable(tf.truncated_normal([N, O], stddev=0.1))
B4 = tf.Variable(tf.zeros([O]))
W5 = tf.Variable(tf.truncated_normal([O, 6], stddev=0.1))
B5 = tf.Variable(tf.zeros([6]))

#The model
Y1 = tf.nn.sigmoid(tf.matmul(X, W1) + B1)
Y2 = tf.nn.sigmoid(tf.matmul(Y1, W2) + B2)
Y3 = tf.nn.sigmoid(tf.matmul(Y2, W3) + B3)
Y4 = tf.nn.sigmoid(tf.matmul(Y3, W4) + B4)
Ylogits = tf.matmul(Y4, W5) + B5
Y = tf.nn.softmax(Ylogits)

#cross-entropy loss function (= -sum(Y_i * log(Yi)) ), normalized for batches of 100 sessions
#Tensorflow provides the softmax_cross_entropy_with_logits function to avoid numerical stability
#problems with log(0) which is NaN
cross_entropy = tf.nn.softmax_cross_entropy_with_logits(logits = Ylogits, labels=Y_)
cross_entropy = tf.reduce_mean(cross_entropy) * 100

#accruacy of the trained model, between 0 (worst) and 1 (best)
correct_prediction = tf.equal(tf.argmax(Y, 1), tf.argmax(Y_, 1))
accuracy = tf.reduce_mean(tf.cast(correct_prediction, tf.float32))

#For later use to possibly visualize the concept
#allweights = tf.concat([tf.reshape(W1, [-1]), tf.reshape(W2, [-1]),  tf.reshape(W3, [-1]), tf.reshape(W4, [-1]),  tf.reshape(W5, [-1])], 0)
#allBiases = tf.concat([tf.reshape(B1, [-1]), tf.reshape(B2, [-1]),  tf.reshape(B3, [-1]), tf.reshape(B4, [-1]),  tf.reshape(B5, [-1])], 0)
#I = tensorflowvisu.tf_format_darpa_sessions(X, Y, Y_)
#It = tensorflowvisu.tf_format_darpa_sessions(X, Y, Y_, 1000, lines=25)

#training step, learning rate = 0.003
learning_rate = 0.003
train_step = tf.train.AdamOptimizer(learning_rate).minimize(cross_entropy)

#init
init = tf.global_variables_initializer()
sess = tf.Session()
sess.run(init)

#you can call this function in a loop to train the model, 100 sessions at a time
#def training_step(i, update_test_data, update_train_data):

    #training on batches of 100 sessions with 100 labels
#    batch_X, batch_Y = darpa.train.next_batch(100)

    #compute training values for visualization
#    if update_train_data:
#        a, c, im, w, b = sess.run([accuracy, cross_entropy, I, allweights, allbiases])
#        print(str(i) + ": accuracy:" + str(a) + " loss: " + str(c) + " (lr:" + str(learning_rate) + ")")
#        datavis.append_training_curves_data(i, a, c)
#        datavis.update_session1(im)
#        datavis.append_data_histograms(i, w, b)

    #compute test values for visualization
#    if update_test_data:
#        a, c, im = sess.run([accuracy, cross_entropy, It], {X: darpa.test.sessions, Y_: darpa.test.labels})
#        print(str(i) + ": ********* epoch " + str(i*100//darpa.train.sessions.shape[0] + 1) + " ********* test accuracy:" + str(a) + " test loss: " + str(c))
#        datavis.append_test_curves_data(i, a, c)
#        datavis.update_session2(im)

    #the back propagation training step
#    sess.run(train_step, {X: batch_X, Y_: batch_Y})

#datavis.animate(training_step, iterations=10000+1, train_data_update_freq=20, test_data_update_freq=100, more_tests_at_start=True)

#to save the animation as a movie, add save_movie=True as an argument to datavis.animate
#to disable the visualization use the following line instead of the datavis.animate line
#for i in range(10000+1): trainging_step(i, 1 % 100 == 0, i % 20 == 0)

#print("max test accuracy: " str(datavis.get_max_test_accuracy()))