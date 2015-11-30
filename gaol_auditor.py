#!/usr/bin/python
# -*- coding: utf-8 -*-  


import time
import datetime
import base64
import argparse
import errno

import json

from gaol_lib import *
from lib import *
import os.path


parser = argparse.ArgumentParser(description="")
parser.add_argument('--config', default="gaol_conf.py")
args = parser.parse_args()

# Import from config file
if os.path.isfile(args.config):
    modules = map(__import__, [args.config[:-2]])
    CONFIG = modules[0]
    ERROR_STR = CONFIG.ERROR_STR
else:
    print "Config file not found!"
    ERROR_STR = "(local)ERROR: "
    sys.exit()



class ctlog:
    def __init__(self, name, url, key, log_id=None, build=True):
        self.name = name
        self.url = url
        self.key = key
        self.log_id = log_id
        self.logfile = CONFIG.OUTPUT_DIR + name + ".log"
        self.savefile = CONFIG.OUTPUT_DIR + name + "-state-info.json"
        self.subtree = [[]]
        # self.fe_ips = {}
        self.sth = None
        self.entries = 0
        self.root_hash = None
        self.build = build

        self.saved_sth = None
        self.saved_entries = None
        self.saved_subtree = None

        self.log("Starting monitor")



    def to_dict(self):
        d = {}
        d["sth"] = self.sth
        return d

    def save(self):
        self.log("Saving state to file")
        open(self.savefile, 'w').write(json.dumps(self.to_dict()))

    def load(self):
        self.log("Loading state from file")
        try:
            f = open(self.savefile)
            s = f.read()
            d = json.loads(s)
            self.sth = d["sth"]

        except IOError, e:
            if e.errno == errno.ENOENT:
                return None
            raise e


    def log(self, string):
        s = time_str() + " " + string
        with open(self.logfile, 'a') as f:
            f.write(s + "\n")
            f.close()

    def update_sth(self):
        try:
            new_sth = get_sth(self.url)
        except Exception, e:
            self.log(ERROR_STR + "Failed to fetch STH. " +str(e))
            return

        try:
            check_sth_signature(self.url, new_sth, base64.b64decode(self.key))
        except:
            self.log(ERROR_STR + "Could not verify STH signature " + str(new_sth))

        if self.sth:
            sth_time = time_str(new_sth["timestamp"])
            if new_sth["timestamp"] != self.sth["timestamp"]:
                self.log("STH updated. Size: " + str(new_sth["tree_size"]) + ", Time: " + sth_time)
                self.sth = new_sth
        else:
            self.log("Setting initial STH: " + str(new_sth))
            self.sth = new_sth

    
    def verify_progress(self, old):
        new = self.sth
        try:
            if new["tree_size"] == old["tree_size"]:
                if old["sha256_root_hash"] != new["sha256_root_hash"]:
                    self.log(ERROR_STR + "New root hash for same tree size! Old:" + str(old) + " New:" + str(new))
            elif new["tree_size"] < old["tree_size"]:
                self.log(ERROR_STR + "New tree is smaller than old tree! Old:" + str(old) + " New:" + str(new))

            if new["timestamp"] < old["timestamp"]:
                self.log(ERROR_STR + "Regression in timestamps! Old:" + str(old) + " New:" + str(new))
            else:
                age = time.time() - new["timestamp"]/1000
                sth_time = time_str(new["timestamp"])
                roothash = new['sha256_root_hash']
                if age > 24 * 3600:
                    s = ERROR_STR + "STH is older than 24h: %s UTC" % (sth_time)
                    self.log(s + str(new))
                    print s
                elif age > 12 * 3600:
                    s = "WARNING: STH is older than 12h: %s UTC" % (sth_time)
                    self.log(s)
                elif age > 6 * 3600:
                    s = "WARNING: STH is older than 6h: %s UTC" % (sth_time)
                    self.log(s)
        except Exception, e:
            self.log(ERROR_STR + "Failed to verify progress! Old:" + str(old) + " New:" + str(new) + " Exception: " + str(e))

    def verify_consistency(self, old):
        new = self.sth
        try:
            if old["tree_size"]!= new["tree_size"]:
                consistency_proof = get_consistency_proof(self.url, old["tree_size"], new["tree_size"])
                decoded_consistency_proof = []
                for item in consistency_proof:
                    decoded_consistency_proof.append(base64.b64decode(item))
                res = verify_consistency_proof(decoded_consistency_proof, old["tree_size"], new["tree_size"], old["sha256_root_hash"])
                
                if old["sha256_root_hash"] != str(base64.b64encode(res[0])):
                    self.log(ERROR_STR + "Verification of consistency for old hash failed! Old:" \
                        + str(old) + " New:" + str(new) + " Calculated:" + str(base64.b64encode(res[0])\
                        + " Proof:" + str(consistency_proof))
                elif new["sha256_root_hash"] != str(base64.b64encode(res[1])):
                    self.log(ERROR_STR + "Verification of consistency for new hash failed! Old:" \
                        + str(old) + " New:" + str(new) + " Proof:" + str(consistency_proof))

        except Exception, e:
            self.log(ERROR_STR + "Could not verify consistency! " + " Old:" + str(old) + " New:" + str(new) + " Error:"  + str(e))



def main(args):
    # Create logs
    logs = []
    try:
        # Create log objects
        for item in CONFIG.CTLOGS:
            logs.append(ctlog(item["name"], item["url"], item["key"], item["id"], item["build"]))
        print time_str() + " Setting up monitor for " + str(len(logs)) + " logs..."

        # Set up state 
        for log in logs:
            if os.path.isfile(log.savefile):
                log.load()


        # Main loop: Auditor
        print time_str() + " Running... (see logfiles for output)"
        while True:
            for log in logs:
                old_sth = log.sth

                log.update_sth()
                if old_sth and old_sth["timestamp"] != log.sth["timestamp"]:
                    log.verify_progress(old_sth)        
                    log.verify_consistency(old_sth)      # Does rollback on critical fail
                    pass
            time.sleep(CONFIG.INTERVAL)

    # Normal exit of the program
    except KeyboardInterrupt:
        print time_str() + ' Received interrupt from user. Saving and exiting....'
        for log in logs:
            log.save()

    # Something went horribly wrong!
    except Exception, err:
        print Exception, err
        for log in logs:
            log.save()



if __name__ == '__main__':
    if CONFIG.OUTPUT_DIR and not os.path.exists(CONFIG.OUTPUT_DIR):
        os.makedirs(CONFIG.OUTPUT_DIR)

    main(args)






