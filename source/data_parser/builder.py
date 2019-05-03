"""
Builder is used to generate both the training and testing sets for
the tensorflow machine learning module. It uses the 'library of
attacks' generated by organizer.py.

This file must be run after organizer.py and in the same directory
as organizer.py at execution to work correctly.

This file went through several rounds of development.

See README for more details
"""

import csv
import random

# Data in from our selected attack files
normalData = open('data/normal.txt', 'r')
normalReader = csv.reader(normalData)

backData = open('data/dos/back.txt', 'r')
backReader = csv.reader(backData)

neptuneData = open('data/dos/neptune.txt', 'r')
neptuneReader = csv.reader(neptuneData)

smurfData = open('data/dos/smurf.txt', 'r')
smurfReader = csv.reader(smurfData)

portsweepData = open('data/probing/portsweep.txt', 'r')
portsweepReader = csv.reader(portsweepData)

nmapData = open('data/probing/nmap.txt', 'r')
nmapReader = csv.reader(nmapData)

# Data out to training file
trainingOut = open('training3.txt', 'w', newline='')
trainingWriter = csv.writer(trainingOut)

# Data out to testing file
testingOut = open('testing3.txt', 'w', newline='')
testingWriter = csv.writer(testingOut)


def getRecord():
    """
    The getRecord method is used to randomly select an entry from one of the
    attack files listed above. Random selection is weighted to give a 50%
    distribution to normal traffic, and 10% each to back, neptune, smurf,
    portsweep, and nmap

    Args:

    Returns:
        list: The list of attributes for each record.
    """
    randNum = random.randrange(10)
    # attempt to select correct data, if failed, select from normal
    if randNum == 9:
        try:
            record = next(backReader)
        except:
            record = next(normalReader)
    elif randNum == 8:
        try:
            record = next(neptuneReader)
        except:
            record = next(normalReader)
    elif randNum == 7:
        try:
            record = next(smurfReader)
        except:
            record = next(normalReader)
    elif randNum == 6:
        try:
            record = next(portsweepReader)
        except:
            record = next(normalReader)
    elif randNum == 5:
        try:
            record = next(nmapReader)
        except:
            record = next(normalReader)
    else:
        record = next(normalReader)
    return record


# creating files of size 10000
for x in range(10000):
    # get record
    lineTo = getRecord();

    # container
    temp = []

    # append every attribute but last
    for i in range(41):
        temp.append(float(lineTo[i]))

    # append last after further mapping
    if int(lineTo[41]) == 17:
        temp.append(5)
    elif int(lineTo[41]) == 13:
        temp.append(4)
    elif int(lineTo[41]) == 9:
        temp.append(3)
    elif int(lineTo[41]) == 5:
        temp.append(2)
    elif int(lineTo[41]) == 4:
        temp.append(1)
    else:
        temp.append(0)

    # write to training file
    trainingWriter.writerow(temp)

    # get record
    lineTo = getRecord();

    # container
    temp = []

    # append every attribute but last
    for i in range(41):
        temp.append(float(lineTo[i]))

    # append last after further mapping
    if int(lineTo[41]) == 17:
        temp.append(5)
    elif int(lineTo[41]) == 13:
        temp.append(4)
    elif int(lineTo[41]) == 9:
        temp.append(3)
    elif int(lineTo[41]) == 5:
        temp.append(2)
    elif int(lineTo[41]) == 4:
        temp.append(1)
    else:
        temp.append(0)

    # write to testing file
    testingWriter.writerow(temp)

# close all files
trainingOut.close()
testingOut.close()

normalData.close()
backData.close()
neptuneData.close()
smurfData.close()
portsweepData.close()
nmapData.close()