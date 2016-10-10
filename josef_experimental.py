#!/usr/bin/python
# -*- coding: utf-8 -*-     

import sys
import os
from josef_lib import *
# from josef_lib2 import *
# import leveldb
# import argparse
import json
import time
# from josef_leveldb import *
from datetime import datetime as dt
# from josef_monitor import verify_inclusion_by_hash
from monitor_conf import *

def is_new_timestamp(ts):
    MAX_TIMEDIFF = 300 # 5 min, allows for some clock skew
    ts_time = datetime.datetime.fromtimestamp(ts / 1000, UTC()).strftime('%Y-%m-%d %H:%M:%S')
    start_time = datetime.datetime.utcnow().strftime('2015-10-19 00:00:00')
    # delta_time = datetime.datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') - datetime.datetime.strptime(ts_time, '%Y-%m-%d %H:%M:%S')
    # print delta_time.seconds
    if ts_time < start_time:
        return False
    else:
        return True

def check_inclusion_by_submission(first, last, source, dests):
    # print entries
    for s_log in source:
        try:
            entries = []
            while len(entries) <= last - first:

                print "Getting " + str(first + len(entries)) + " to " + str(last)
                entries += get_entries(s_log["url"], first + len(entries), last)["entries"]
                # print "Fetched entries up to " + str(len(first + len(entries)))
        except:
            print "Failed to get entries from " + s_log["name"]

        for i in range(len(entries)):
            item = entries[i]
            inclusions = []
            for d_log in dests:
                try:
                    entry = extract_original_entry(item)
                    if entry[2]:
                        precert = True
                    else:
                        precert = False
                    submission = []

                    for e in entry[0]:
                        submission.append(base64.b64encode(e))

                    if entry[2]:
                        res = add_prechain(d_log["url"], {"chain" : submission})
                    else:
                        res = add_chain(d_log["url"], {"chain" : submission})
                    # print_reply(res, entry)
                    print res

                    if not is_new_timestamp(res["timestamp"]):
                        inclusions.append(d_log["name"])

                except KeyboardInterrupt:
                    sys.exit()
                except Exception ,e:
                    print Exception, e
                    pass
            s = s_log["name"] + "[" + str(first + i) + "] found in " + str(len(inclusions)) + " logs: " + str(inclusions)
            print s
            # log(logfile, s)
            time.sleep(1)


def update_roots(log):
    roots_hash = None

    roots = get_all_roots(log["url"])
    new_roots_hash = str(hash(str(roots)))

    if new_roots_hash != roots_hash:
        cert_dir = OUTPUT_DIR + log["name"] + "-roots"
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        hash_list = []
        for cert in roots:
            h = str(hash(str(cert)))
            hash_list.append(h)

        loaded_list = os.listdir(cert_dir)

        added, removed = compare_lists(hash_list[:-1], loaded_list)

        # TODO log changes
        if len(added) != 0:
            print str(len(added)) + " new roots found!"
        if len(removed) != 0:
            print str(len(removed)) + " roots removed!"

        for item in removed:
            data = open(cert_dir + "/" + item).read()

            root_cert = base64.decodestring(data)
            subject = get_cert_info(root_cert)["subject"]
            issuer = get_cert_info(root_cert)["issuer"]
            if subject == issuer:
                print "Removed Root: " + item + ", " + subject
            else: 
                print "WTF? Not a root..."


        for item in added:
            root_cert = base64.decodestring(roots[hash_list.index(item)])
            subject = get_cert_info(root_cert)["subject"]
            issuer = get_cert_info(root_cert)["issuer"]
            if subject == issuer:
                print "New Root: " + item + ", " + subject
            else: 
                print "WTF? Not a root..."

            fn = cert_dir + "/" + item
            tempname = fn + ".new"
            data = roots[hash_list.index(item)]
            open(tempname, 'w').write(data)
            mv_file(tempname, fn)

def parse_entry(e, idx, log):
    # print the following fields, separated by sep
    sep = ";"

    s = log["name"]
    s += sep + str(idx) # index
    s += sep + e["serial"] # cert serial number
    s += sep + e["subject"] # Subject
    if "SAN" in e:
        s += sep + e["SAN"] # SAN
    else:
        s += sep
    s += sep + e["issuer"] # issuer
    s += sep + e["chain_length"] # path length
    s += sep + e["sig_algorithm"] # Signature algothithm
    s += sep + e["pubkey_algorithm"] # pubkey algorithm

    try:
        s += sep + e["keylength"]
    except:
        s += sep 
        print "\nERROR: COUND NOT FIND KEYLENGTH!"
        print str(e)

    s += sep + e["not_before"] # valid from
    s += sep + e["not_after"] # valid to
    s += sep + e["validation"] # EV?
    s += sep + e["in_mozilla"] # chains to mozilla root?

    return s

# def check_api2(url):
#     print "\nTesting " + url
#     try:
#         print get_sth_v2(url)
#     except:
#         print "GET STH Failed..."



if __name__ == '__main__':

    # prompt_confirm("you are about to remove file")

    # Find let's encrypt certs
    if False:
        CHUNK = 1000
        log = CTLOGS[1]
        sth = get_sth(log["url"])
        size = int(sth["tree_size"])
        for i in range(0,100):
            start = size - (i + 1) * CHUNK
            end = size - i * CHUNK
            print "Getting " + str(start) + " to " + str(end)
            entries = get_entries(log["url"],start ,end - 1)["entries"]

            for entry in entries:
                res = check_domain(entry)
                issuer = res["issuer"]
                if "Encrypt" in issuer:
                    print res


    # Experimental
    if False:
        log = CTLOGS[1]
        entries = get_entries(log["url"],187851 ,187851)["entries"]
        entry = entries[0]
        print check_domain_all(entry)
        # res = check_domain_extended(entry)
        # print parse_entry(res,0,log)

    # Data gathering for Niklas
    if True:
        logs = [CTLOGS[9]] #,CTLOGS[4],CTLOGS[7],CTLOGS[8],CTLOGS[9]]
        for log in logs:
            filename = log["name"] + "_content.txt"
            if os.path.exists(filename):
                if prompt_confirm("You are about to overwrite " + filename):
                    os.remove(filename)
                else:
                    continue

            sth = get_sth(log["url"])
            start = 0
            idx = 0
            end = int(sth["tree_size"]) - 1

            while start + idx < end:
                entries = get_entries(log["url"],start + idx ,end)["entries"]
                print time_str() + " " + log["name"] + ": Got " + str(start + idx) + " to " + str(start + idx + len(entries) - 1)
                
                with open(filename, 'a') as f:
                    for i in range(len(entries)):
                        entry = entries[i]
                        res = check_domain_extended(entry)
                        string = parse_entry(res, i + start + idx, log)
                        f.write(string + "\n")            

                idx += len(entries)












