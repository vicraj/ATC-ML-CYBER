Guide in order to manipulate machine learning script.

First make sure that the location of the training and testing data sets are correct corresponding to your instance via your download location.

Alterations:

1.  If you are wanting to change values for the number of features or types of attacks make sure that the data sets you are using are in the same format as the ones we have.
    If not you will have issues for how the Tensor if being built.

2. If you are changing the values change them in the arrays corresponding to the feature/variable list and the different names for the attacks in each array.

3. Go to the model and change the number of output nodes to the number of attacks that you are trying to categorize.

4. In the model you will also have to change the number of features corresponding to the number of features that you have as well.

To Alter the Accuracy ( three options )

1. You can change the batch size for how many lines are stored in each Tensor

2. You can change the learning rate. Larger can cause it to learn to fast and bypass accuracy, and to slow can have similar effects to the accuracy being low

3. You can also change the number of Epochs during your training phase which runs the script through more iterations.
