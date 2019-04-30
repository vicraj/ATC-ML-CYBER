import tensorflow as tf
from tensorflow import contrib
import matplotlib.pyplot as plt

tf.enable_eager_execution()

#Change to correct file location
train_dataset_file = "/Users/blair/OneDrive/Desktop/Spring 2019/Cap Stone/IDS_MachineLearning/ATC-ML-CYBER/source/training3.txt"

#Change to correct file location
test_dataset_file = "/Users/blair/OneDrive/Desktop/Spring 2019/Cap Stone/IDS_MachineLearning/ATC-ML-CYBER/source/testing3.txt"

'''
Features: 
If you want to add more variables from datasets you will have to add it into a csv friendly format and add the name of the variable to the column array.
'''

column_names = ["Duration.", "Protocol_Type.", "Service.", "Flag.", "Src_Bytes.", "Dst_Bytes", "Land.", "Wrong_Fragment.", "Urgent.", "Hot.", "Num_Failed_Logins.", "Logged_In.", "Num_Compromised.", "Root_Shell.", "Su_Attempted.", "Num_Root.", "Num_File_Creations.", "Num_Shells.", "Num_Access_Files.", "Num_Outbound_Cmds.", "Is_Host_Login.", "Is_Guest_Login.", "Count.", "Srv_Count.", "Serror_Rate.", "Srv_Serror_Rate.", "Rerror_Rate.", "Srv_Rerror_Rate.", "Same_Srv_Rate.", "Diff_Srv_Rate.", "Srv_Diff_Host_Rate", "Dst_Host_Count.", "Dst_Host_Srv_Count.", "Dst_Host_Same_Srv_Rate.", "Dst_Host_Diff_Rate.", "Dst_Host_Same_Src_Port_Rate.", "Dst_Host_Srv_Diff_Host_Rate.", "Dst_Host_Serror_Rate.", "Dst_Host_Srv_Serror_Rate.", "Dst_Host_Rerror_Rate.", "Dst_Host_Srv_Rerror_Rate.", "attacks"]

feature_names = column_names[:-1]
label_name = column_names[-1]

'''
Attacks: Normal, Neptune, Smurf, Portsweep, Back, and Nmap
'''
attack_names = ["normal.", "neptune.", "smurf.", "portsweep.", "back.", "nmap."]

'''
Batch Size:
Number of sessions to train on.
'''
batch_size = 40


'''
Training dataset:
Make a new csv that Tensorflow can use for the model;
training_dataset_file = filepath to training data
batch_size: explained above
column_names = features
label_names = attack types
num_epoch = used for iterating
'''
train_dataset = tf.contrib.data.make_csv_dataset(
    train_dataset_file,
    batch_size,
    column_names = column_names,
    label_name = label_name,
    num_epochs = 1
)

features, labels = next(iter(train_dataset))

print(features)

def pack_features_vector(features, labels):
    """
    This packages the features and labels into a nice format to be pushed into the machine learning iterations
    :param features: Features in the column array ( Variables in the datasets used to distinguish attacks )
    :param labels: Labels in the label array above ( Attacks that you are trying to categorize )
    :return: A stack of Tensors that are compressed with tf.stack
    """
    features = tf.stack(list(features.values()), axis=1)
    return features, labels

train_dataset = train_dataset.map(pack_features_vector)

features, labels = next(iter(train_dataset))

print(features)

#Model
model = tf.keras.Sequential([
    tf.keras.layers.Dense(60, activation=tf.nn.relu, input_shape=(41,)),
    tf.keras.layers.Dense(60, activation=tf.nn.relu),
    tf.keras.layers.Dense(6)
])

predictions = model(features)

print("Prediction: {}".format(tf.argmax(predictions, axis=1)))
print("    Labels: {}".format(labels))

def loss(model, x, y):
    '''
    This is a method to generate the amount Tensor loss based on the model.
    :param model: Class model for the neural network
    :param x: Features to be used with the model in order to get the logits.
    :param y: Labels/Attacks to be put into the softmax function.
    :return: Amount of loss from the model based on the label and logits as logits. If returns NaN for reduction it will be similar shape as the labels.
    '''
    y_ = model(x)
    return tf.losses.sparse_softmax_cross_entropy(labels=y, logits=y_)

l = loss(model, features, labels)
print("Loss test:   {}".format(l))

def grad(model, inputs, targets):
    """
    Used to compute/produce multiple gradients at the same time.
    :param model: Model of the Tensor
    :param inputs: Features being passed in to get the logits.
    :param targets: Target for where to categorize each session data ( Attack types )
    :return: Same as loss function for first return, A list or nested structure of Tensors
    """
    with tf.GradientTape() as tape:
        loss_value = loss(model, inputs, targets)
    return loss_value, tape.gradient(loss_value, model.trainable_variables)

optimizer = tf.train.GradientDescentOptimizer(learning_rate=0.0001)

global_step = tf.Variable(0)

loss_value, grads = grad(model, features, labels)
print("Step: {}, Initial Loss: {}".format(global_step.numpy(),
                                          loss(model, features, labels).numpy()))

optimizer.apply_gradients(zip(grads, model.trainable_variables), global_step)
print("Step: {}          Loss: {}".format(global_step.numpy(),
                                          loss(model, features, labels).numpy()))

#I MAKE IT HERE!!!
#Training Loop
tfe = contrib.eager

#keep results for plotting
train_loss_results = []
train_accuracy_results = []

num_epochs = 500


for epoch in range(num_epochs):
    epoch_loss_avg = tfe.metrics.Mean()
    epoch_accuracy = tfe.metrics.Accuracy()
    #print("hello")
    i = 0
    #Currently I GET STUCK IN THIS FOR LOOP BELOW!!!! WHY?!?!?!
    #Loop in batches of 32
    for (x, y) in train_dataset:
        #optimize
        loss_value, grads = grad(model, x, y)
        optimizer.apply_gradients(zip(grads, model.trainable_variables),
                                  global_step)
        #track progress
        epoch_loss_avg(loss_value) #add current batch loss
        #compare predicted label to actual label
        epoch_accuracy(tf.argmax(model(x), axis=1, output_type=tf.int32), y)

    #end epoch
    train_loss_results.append(epoch_loss_avg.result())
    train_accuracy_results.append(epoch_accuracy.result())


    #to see it learning in the console every 10 iterations.
    if epoch % 10 == 0:
        print("Epoch {:03d}: Loss: {:.3f}, Accuracy: {:.3%}".format(epoch,
                                                                    epoch_loss_avg.result(),
                                                                    epoch_accuracy.result()))

#to see it via matplot. Graphs

fig, axes = plt.subplots(2, sharex=True, figsize=(12, 8))
fig.suptitle("IDS Detection Metrics")

axes[0].set_ylabel("Loss", fontsize=14)
axes[0].plot(train_loss_results)

axes[1].set_ylabel("Accuracy", fontsize=14)
axes[1].set_xlabel("Epochs", fontsize=14)
axes[1].plot(train_accuracy_results)


'''
Testing Set:
Used to test the algorithm against what the iterations categorize each session as in the test dataset.
'''
test_dataset = tf.contrib.data.make_csv_dataset(
    test_dataset_file,
    batch_size,
    column_names=column_names,
    label_name='attacks',
    num_epochs=1,
    shuffle=False)

test_dataset = test_dataset.map(pack_features_vector)

test_accuracy = tfe.metrics.Accuracy()

"""
Obtain logits from the model and put into argmax,
test_accuracy is getting the accuracy for what is being compared against.
"""
for (x, y) in test_dataset:
    logits = model(x)
    prediction = tf.argmax(logits, axis=1, output_type=tf.int32)
    test_accuracy(prediction, y)

print("Test set accuracy: {:.3%}".format(test_accuracy.result()))

tf.stack([y, prediction],axis=1)

