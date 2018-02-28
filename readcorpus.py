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
    score, reason = classify(record)
    return score >= 1

TLD_WHITELIST = {"com", "net", "org", "edu"}
TLD_BLACKLIST = {"ru", "vu"}

def classify(record):
    """classify a single url and return its score"""
    score = 0 # high is bad, low is good
    reason = []

    # old domains are likely benign
    # newly-registered domains are likely malicious
    if int(record["domain_age_days"]) < 10:
        score += 1
        reason.append("age")
    elif int(record["domain_age_days"]) > 365:
        score -= 1
        reason.append("age")

    # valid domains shouldn't have a tld in a subdomain
    # eg. eu.battle.net.blizzardentertainmentfreeofactivitiese.com
    if any(tld in record['domain_tokens'][:-1] for tld in ("com", "net", "org")):
        # .com.cn is valid
        if not record['host'].endswith((".com.cn", ".com.tw", ".com.hk")):
            score += 5
            reason.append("tld in subdomain")

    # www is a good sign
    if "www" in record['domain_tokens'][:1]:
        score -= 1
        reason.append("has www")

    # check if any path component looks like a domain name
    # eg. http://www.hxc.sdnu.edu.cn/www.paypal.co.uk/webscr.html

    if record.get('mxhosts') and record['mxhosts'][0].get('ips'):
        score -= 1
        reason.append("has mx record")

        try:
            mxgeo = record['mxhosts'][0]['ips'][0]['geo']
            ageo = record['ips'][0]['geo']
        except (IndexError, KeyError, TypeError):
            pass
        else:
            if mxgeo != ageo and mxgeo is not None and ageo is not None:
                #print(mxgeo, ageo)
                score += 2
                reason.append("MX record geo does not match A record geo")


    # high alex rank is good
    if record.get('alexa_rank') is not None:
        alexa_rank = int(record['alexa_rank'])
        if alexa_rank > 20000:
            score += 1
            reason.append('low alexa rank')
        elif alexa_rank < 100:
            score -= 1
            reason.append("high alexa rank")

    if record['tld'] in TLD_WHITELIST:
        score -= 1
        reason.append("well-known tld")
    if record['tld'] in TLD_BLACKLIST:
        score += 1
        reason.append("blacklisted tld")

    # I'm not saying all php is malicious but...
    # all php is malicious
    if '.php' in record['path']:
        score += 1
        reason.append("php")

    return score, reason

def measure(urldata):
    """measure our false positive and false negative rate"""
    matrix = [[0, 0], [0, 0]]
    false_positives = []
    false_negatives = []
    for record in urldata:
        prediction = bool(ismalicious(record))
        actual = bool(record['malicious_url'])

        if prediction == False and actual == True:
            false_negatives.append(record)
        if prediction == True and actual == False:
            false_positives.append(record)

        matrix[actual][prediction] += 1

    for record in false_negatives[:20]:
        score, reason = classify(record)
        print("false negative ({}): {}".format(score, record['url']))

    print()
    for record in false_positives[:20]:
        score, reason = classify(record)
        print("false positive ({}): {}".format(score, record['url']))
        print("\t" + ", ".join(reason))

    print("true positives:", matrix[1][1])
    print("true negatives:", matrix[0][0])
    print("false negatives:", matrix[1][0])
    print("false positives:", matrix[0][1])

    total = matrix[0][0] + matrix[0][1] + matrix[1][0] + matrix[1][1]
    print("accuracy: {:%}".format((matrix[1][1] + matrix[0][0]) / total))


if __name__ == "__main__":
    main()
