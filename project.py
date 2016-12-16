#!/usr/bin/env python

import os
import sys
import uuid
import numpy
import packet
from keras.models import Sequential
from keras.layers import Dense, Activation
from keras.utils.visualize_util import plot

def train(model):

    # Load the data set to train on
    dataset = numpy.loadtxt("train.csv", delimiter=",")

    # split into input and expected outputs
    inputs = dataset[:,0:7]
    expected = dataset[:,7]

    # Compile, fit and evaulate the model
    model.fit(inputs, expected, nb_epoch=500, batch_size=5, verbose=1, validation_split=0.05)
    scores = model.evaluate(inputs, expected)
    print("\n\nAccuracy: %.2f%%" % (scores[1] * 100))

def evaluate(model):
    """ Load the inputs from the csv file """

    tmpname = str(uuid.uuid4().hex)

    data = raw_input("pcap filename: ")
    if packet.analyze(data, False, tmpname):
        dataset = numpy.loadtxt(tmpname, delimiter=",")
        ins = dataset[:,0:7]
        output = dataset[:,7]

        """ Make the predictions and print the results! """
        predictions = model.predict(ins, batch_size = 5)
        rounded = [round(x) for x in predictions]

        print(rounded)

        outcome = float(rounded.count(1)) / len(rounded)

        os.remove(tmpname)

        print "Percentage of Possible Malicious Traffic: %d%%" % (outcome * 100.0) 
    else:
        print "Need at least 100 captured packets to analyze traffic"


def menu_print():
    print 30 * "-" , "MENU", 30 * "-"
    print "1. Train Neural Network"
    print "2. Evaluate Neural Network"
    print "3. Plot Neural Network"
    print "4. Exit"
    print 67 * "-"

if __name__ == "__main__":

    """ Set numpy's random seed """
    numpy.random.seed(80051)

    """ Create a menu to train, then test the data multiple times """
    model = Sequential()
    model.add(Dense(45, input_dim=7, init='uniform', activation='softmax'))
    model.add(Dense(12, init='uniform', activation='softmax'))
    model.add(Dense(4, init='uniform', activation='softmax'))
    model.add(Dense(1, init='uniform', activation='sigmoid'))
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    while True:
        menu_print()
        choice = input("Enter choice [1-4]: ")

        if 1 == choice:
            train(model)
        elif 2 == choice:
            evaluate(model)
        elif 3 == choice:
            plot(model, to_file='network.png')
        elif 4 == choice:
            sys.exit()
        else:
            raw_input("Invalid option, Press Enter to return to main menu")

