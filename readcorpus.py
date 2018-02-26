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
    score = 0
    # old domains are likely benign
    # newly-registered domains are likely malicious
    if int(record["domain_age_days"]) < 10:
        score += 1
    if int(record["domain_age_days"]) > 365:
        score -= 1

    # valid domains shouldn't have a tld in a subdomain
    # eg. eu.battle.net.blizzardentertainmentfreeofactivitiese.com
    if any(tld in record['domain_tokens'][:-1] for tld in ("com", "net", "org")):
        # .com.cn is valid
        if not record['host'].endswith(".com.cn"):
            score += 2

    # www is a good sign
    if "www" in record['domain_tokens'][:1]:
        score -= 1

    return score >= 1

def measure(urldata):
    """measure our false positive and false negative rate"""
    matrix = [[0, 0], [0, 0]]
    false_positives = []
    for record in urldata:
        prediction = bool(ismalicious(record))
        actual = bool(record['malicious_url'])

        if prediction == True and actual == False:
            false_positives.append(record)

        matrix[actual][prediction] += 1

    for record in false_positives[:20]:
        print("false positive:", record['url'])

    print("true positives:", matrix[1][1])
    print("true negatives:", matrix[0][0])
    print("false positives:", matrix[0][1])
    print("false negatives:", matrix[1][0])

    total = matrix[0][0] + matrix[0][1] + matrix[1][0] + matrix[1][1]
    print("accuracy: {:%}".format((matrix[1][1] + matrix[0][0]) / total))


if __name__ == "__main__":
    main()
