#!/usr/bin/python

from __future__ import division
from __future__ import print_function

import json
import sys
import argparse
import os

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", default="")
    args = parser.parse_args()

    if args.file == "":
        parser.print_usage()
        return

    with open(args.file) as corpus:
        urldata = json.load(corpus, encoding="latin1")

    measure(urldata)

def ismalicious(record):
    """classify a single url as either malicious or not malicious"""
    # Do something with the URL record data...
    #print record["domain_age_days"], record["malicious_url"]
    return True

def measure(urldata):
    """measure our false positive and false negative rate"""
    matrix = [[0, 0], [0, 0]]
    for record in urldata:
        prediction = ismalicious(record)
        actual = record['malicious_url'] == 1

        matrix[actual][prediction] += 1

    print("true positives:", matrix[1][1])
    print("true negatives:", matrix[0][0])
    print("false positives:", matrix[0][1])
    print("false negatives:", matrix[1][0])

    total = matrix[0][0] + matrix[0][1] + matrix[1][0] + matrix[1][1]
    print("accuracy: {:%}".format((matrix[1][1] + matrix[0][0]) / total))

if __name__ == "__main__":
    main()
