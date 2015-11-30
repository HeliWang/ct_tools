#!/usr/bin/python

import base64

from gaol_conf import *
from gaol_lib import *

def test_get_entry(url, idx):
    print "Testing to fetch an entry..."
    entry = get_entries(url,idx,idx)["entries"][0]
    print "Received: " + extract_original_entry(entry)[0]

def test_submission(url, data):
    print "\nTesting to submitt a sample text..."
    blob = make_blob(data)
    res = add_blob(url,blob)
    print res

def test_consistency_proof(url, idx1, idx2):
    print "\nTesing a consistency proof"
    res = get_consistency_proof(url, idx1, idx2)
    print res

if __name__ == '__main__':
    url = CTLOGS[0]["url"]
    test_get_entry(url,2)
    # test_submission(url, "In a time of universal deceit - telling the truth is a revolutionary act.  -- George Orwell")
    test_consistency_proof(url, 2, 3)