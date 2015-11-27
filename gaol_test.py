#!/usr/bin/python

import base64

from gaol_conf import *
from gaol_lib import *

def test_get_entry(url, idx):
    print "Testing to fetch an entry..."
    entry = get_entries(url,idx,idx)["entries"][0]
    print "Received: " + extract_original_entry(entry)[0]

if __name__ == '__main__':
    url = CTLOGS[0]["url"]
    test_get_entry(url,1)
