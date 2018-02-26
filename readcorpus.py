#!/usr/bin/python

import json
import sys
import argparse
import os

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file")
    args = parser.parse_args()

    if args.file == "":
        parser.print_usage()
        return

    with open(args.file) as corpus:
        urldata = json.load(corpus, encoding="latin1")

    for record in urldata:

        # Do something with the URL record data...
        print record["domain_age_days"]

if __name__ == "__main__":
    main()
